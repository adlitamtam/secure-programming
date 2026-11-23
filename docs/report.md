# PassVault: A Local CLI Password Manager in Java

**Course:** ICS0022 Secure Programming – Tallinn University of Technology (TalTech)  
**Author:** Matilda Thurso (266057IV)

---

## 1. Introduction

Reusing passwords across multiple online services remains one of the most common security risks for everyday users.
While password managers solve this problem by allowing unique, complex passwords for every account, storing all
credentials in one place also turns the vault itself into a high-value target. If the storage file is leaked, modified,
or improperly handled in memory, an attacker could compromise every stored account at once.

The goal of this project, **PassVault**, is to design and implement a local command-line password manager in Java that
protects user credentials both at rest and during runtime. Instead of relying on cloud synchronization, PassVault stores
data locally in an embedded SQLite database (`vault.db`) and follows a zero-knowledge design: neither the user's master
password nor the derived vault encryption key is ever written to disk.

### Security Objectives and Threat Model

The design of PassVault focuses on four core security requirements:

1. **Confidentiality at Rest and in Memory:** Stored passwords must remain unreadable without the user's master
   password, and sensitive values in RAM must be cleared as soon as they are no longer needed.
2. **Integrity and Authenticity:** Unauthorized edits to stored ciphertexts or application logs must be detected
   reliably.
3. **Multi-User Isolation:** Multiple users can register on the same local database, and every vault operation must
   strictly enforce per-user ownership.
4. **Resilience Against Common Attacks:** The application must defend against brute-force login attempts, SQL injection,
   log injection, malformed inputs, and shoulder-surfing.

In this threat model, we assume an attacker may gain read or write access to the local `vault.db` and `../passvault.log`
files, attempt automated password guessing through the CLI, or supply malicious input strings. Full compromise of the
underlying operating system kernel or active root-level malware monitoring keystrokes in real time is considered outside
the scope of a user-space Java application.

---

## 2. Implementation

### 2.1 System Architecture

PassVault is built with Java 21 and Maven, organized into a layered package structure under `ee.taltech.passvault` so
that user interface logic, authentication, cryptography, and database access remain clearly separated:

```text
+-------------------------------------------------------------------+
| UI Layer (ee.taltech.passvault.ui)                                |
|  - CommandLineInterface: interactive menu, command dispatch,      |
|    masked password input (char[]), JVM shutdown hook              |
|  - ClipboardService: copies decrypted secrets, 30s auto-wipe      |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
| Authentication & Session Layer (ee.taltech.passvault.auth)        |
|  - AuthenticationService: registration, login, lockout checks     |
|  - UserSession: holds userId, username, and in-memory K_enc       |
+----------------+----------------------------------+---------------+
                 |                                  |
                 v                                  v
+---------------------------------+ +-------------------------------+
| Crypto & Security               | | Storage Layer                 |
| (.crypto & .security)           | | (.storage)                    |
|  - KeyDerivationService         | |  - DatabaseManager (SQLite)   |
|  - VaultCipher (AES-256-GCM)    | |  - UserDao (users & lockout)  |
|  - MemoryWiper                  | |  - VaultItemDao (credentials) |
|  - InputValidator               | +-------------------------------+
|  - LogSanitizer &               |
|    TamperEvidentFileAppender    |
+---------------------------------+
```

When a user unlocks their vault, `AuthenticationService` creates a `UserSession` object holding the derived encryption
key (`K_enc`) in RAM. All subsequent vault commands (`list`, `add`, `get`, `delete`) pass this active session to the
service and DAO layers, ensuring that cryptographic operations and database queries are always bound to the
authenticated user.

### 2.2 Cryptographic Design and Key Hierarchy

All cryptographic primitives are provided by the Bouncy Castle library (`bcprov-jdk18on`) and the standard Java
Cryptography Architecture (JCA):

* **Key Derivation (Argon2id):** During registration, `SecureRandomUtils` generates a fresh 16-byte random salt using
  `java.security.SecureRandom`. Rather than using fast general-purpose hashes like SHA-256, PassVault uses **Argon2id**
  (configured with 64 MiB memory cost, 3 iterations, and parallelism 1) to slow down offline GPU/ASIC brute-force
  attacks.
* **Domain Separation:** To avoid using the same derived key for both authentication and encryption, PassVault derives
  two independent 256-bit keys from the master password. The first key is derived using the original salt and stored as
  a hex-encoded authentication hash in the `users` table. For the vault encryption key (`K_enc`), a single bit of the
  salt is flipped (`encSalt[0] ^= 0x01`) before running Argon2id a second time. As a result, even if an attacker
  extracts the stored authentication hash from `vault.db`, they cannot use it to decrypt vault entries.
* **Constant-Time Verification:** During login, the newly computed authentication hash is compared against the stored
  hash using `MessageDigest.isEqual(...)` to prevent timing side-channel leaks.
* **Authenticated Encryption (AES-256-GCM):** Whenever a user adds a credential (`add <service>`), `VaultCipher`
  generates a fresh 12-byte random nonce and encrypts the password using **AES-256-GCM** with a 128-bit authentication
  tag. GCM provides both confidentiality and integrity: if even a single byte of the ciphertext or nonce is modified in
  SQLite, decryption fails immediately with a `SecurityException` (`Tag mismatch`).

### 2.3 Memory Hygiene and Clipboard Security

In Java, `String` objects are immutable and remain on the heap until garbage collection, making them risky for passwords
and keys. Throughout PassVault, master passwords, entry passwords, and derived keys are handled exclusively as `char[]`
and `byte[]` arrays:

* **Masked Console Input:** `CommandLineInterface` reads passwords via `System.console().readPassword()` (falling back
  safely only when no console is attached, such as inside IDE runners).
* **Deterministic Zero-Wiping:** `MemoryWiper` overwrites sensitive `char[]` and `byte[]` arrays with `\0` / `0x00`
  inside `finally` blocks immediately after hashing, encryption, or decryption completes. When the user runs `lock` or
  exits the program, `UserSession.invalidate()` wipes `K_enc` from memory. Additionally, a JVM shutdown hook
  (`Runtime.getRuntime().addShutdownHook`) ensures active session keys are cleared even if the process is interrupted
  via `Ctrl+C`.
* **Shoulder-Surfing Protection:** Decrypted passwords are never printed to `stdout`. Instead, `ClipboardService` places
  the decrypted password into the system clipboard and spawns a background timer thread that clears the clipboard after
  30 seconds. Before accessing AWT clipboard APIs, the service checks `GraphicsEnvironment.isHeadless()` so that running
  in a server or Docker container degrades gracefully without crashing.

### 2.4 Database Layer, Access Control, and Brute-Force Protection

PassVault uses an embedded SQLite database (`vault.db`) managed by `DatabaseManager`:

* **SQL Injection Prevention:** Every query involving user-supplied data in `UserDao` and `VaultItemDao` uses
  parameterized `PreparedStatement` objects with `?` placeholders. Static `Statement` calls are strictly limited to
  schema setup (`PRAGMA` and `CREATE TABLE IF NOT EXISTS`).
* **Per-User Access Control:** Every row in `vault_items` is linked to a user via a `user_id` foreign key
  (`ON DELETE CASCADE`). All read, list, and delete queries in `VaultItemDao` include `WHERE user_id = ?`, ensuring that
  one registered user can never view, decrypt, or delete another user's entries even if both users store credentials for
  the same service name.
* **Runtime Self-Healing:** `DatabaseManager.getConnection()` enables foreign keys and WAL mode and verifies that the
  required tables exist. If `vault.db` is accidentally deleted while the application is running, the schema is recreated
  automatically on the next database operation instead of crashing the CLI.
* **Persistent Brute-Force Lockout:** To prevent automated password guessing, `UserDao` tracks failed login attempts and
  a `locked_until` Unix timestamp in a dedicated `lockout` table. After 5 consecutive failed attempts, authentication is
  blocked for 60 seconds. Because the state is persisted in SQLite and checked *before* Argon2id runs, restarting the
  application does not reset the timer, and locked-out requests cannot consume CPU/RAM via repeated Argon2id
  derivations.

### 2.5 Input Validation, Error Handling, and Tamper-Evident Logging

* **Input Validation:** Before any input reaches the authentication or storage layer, `InputValidator` enforces length
  bounds and character whitelists (e.g., alphanumeric characters, underscores, dots, and hyphens for usernames and
  service names) as well as minimum length and complexity rules for master passwords.
* **Secure Error Handling:** Internal exceptions (such as `SQLException` or GCM tag mismatches) are caught cleanly,
  logged with technical details for auditing, and translated into concise, non-revealing messages for the CLI user so
  stack traces or database paths are never exposed.
* **Audit Logging with User Context and Hash Chaining:** Logging is configured via SLF4J and Logback (`../passvault.log`
  with size-based rotation). `LogSanitizer` strips newline and control characters (`\r`, `\n`) from user-controlled
  values to prevent log injection. Using SLF4J's Mapped Diagnostic Context (`MDC`), every log line automatically records
  the active username (`[user=alice]` or `[user=anonymous]`). Finally, a custom `TamperEvidentFileAppender` appends a
  SHA-256 hash signature (`[sig=...]`) to each log entry, chaining every line to the previous line's hash. On startup,
  `Main` verifies the entire hash chain and prints a security warning if any historical log entry was edited or removed.

### 2.6 Testing and Containerized Execution

To verify that the security controls work as intended, PassVault includes an automated JUnit Jupiter (`6.1.3`) test 
suite covering both normal workflows and negative security edge cases. The tests verify Argon2id key derivation 
consistency, domain separation between authentication and encryption keys, AES-256-GCM encryption/decryption 
round-trips, rejection of tampered ciphertexts, input validation boundary cases, deterministic array zero-wiping in 
`MemoryWiper`, and persistent 5-attempt lockout behavior across DAO restarts.

In addition to unit testing, the codebase was evaluated using static analysis and dependency vulnerability checks 
(IntelliJ IDEA Code Inspection and Qodana):
- **Static Code & Taint Analysis:** Inspection rules were run across all packages to verify resource cleanup, 
  return-value checking (e.g., file permission checks), and taint propagation from untrusted CLI inputs through 
  `InputValidator` and `LogSanitizer` before reaching SQL (`PreparedStatement`) or file-logging sinks, leaving zero 
  unresolved security warnings.
- **Dependency Vulnerability Management:** All third-party Maven dependencies were scanned for known CVEs and updated 
to patched releases (`bcprov-jdk18on` `1.87`, `sqlite-jdbc` `3.54.1.0`, `slf4j-api` `2.0.20`, and `logback-classic` `1.6.7`).
- **Timing Side-Channel Mitigation:** During review of the authentication flow, a potential timing discrepancy was 
  identified when logging in with a non-existent username versus an existing account with a wrong password. This was closed by executing a dummy Argon2id key derivation on unknown usernames so failed login attempts exhibit uniform response timing and identical error messages.

To ensure reproducible execution across different operating systems without manual JDK or Maven setup, the repository also includes a multi-stage `../Dockerfile` that builds the JAR with Maven and runs it inside an `eclipse-temurin:21-jre` container under a dedicated non-root `passvault` user with a persistent `/app/data` volume.

---

## 3. Security Analysis

The table below summarizes the primary threats considered during development, how PassVault mitigates them, and what
residual limitations remain:

| Threat / Attack Vector                                            | Implemented Mitigation                                                                                                                                                                                                            | Residual Risk / Limitation                                                                                                                                                                |
|:------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Offline database theft** (`vault.db` copied by an attacker)     | Master password is never stored; Argon2id (64 MiB, 3 iterations) slows down offline brute-force attacks; domain separation isolates the auth hash from `K_enc`; entries are encrypted with AES-256-GCM and unique 12-byte nonces. | Security still depends on the entropy of the user's master password; weak passwords remain vulnerable to dictionary attacks.                                                              |
| **Database tampering** (modifying ciphertext or nonces in SQLite) | AES-256-GCM verifies a 128-bit authentication tag before returning plaintext and aborts on any modification.                                                                                                                      | Metadata columns (`service`, `account_username`) are stored in plaintext so users can list their entries without decrypting every row.                                                    |
| **Online brute-force guessing**                                   | Persistent `lockout` counter in SQLite blocks login for 60 seconds after 5 failed attempts, surviving process restarts and blocking Argon2id execution while locked.                                                              | A local user with direct write access to `vault.db` could manually reset the `lockout` table using an external SQLite client.                                                             |
| **Memory dump / cold-boot inspection**                            | Secrets are stored in `char[]`/`byte[]` instead of `String` and overwritten with zeroes in `finally` blocks, on `lock`, and via a JVM shutdown hook.                                                                              | The JVM garbage collector may copy objects during heap compaction before zeroing occurs, and OS swap space is not locked (`mlock`).                                                       |
| **SQL injection & malformed input**                               | Strict whitelist validation (`InputValidator`) combined with parameterized `PreparedStatement` queries across all DAOs.                                                                                                           | None for SQL execution; overly restrictive whitelists could reject unusual service names if not tuned carefully.                                                                          |
| **Log injection & log tampering**                                 | `LogSanitizer` removes line breaks; `MDC` attributes every action to a user; `TamperEvidentFileAppender` chains lines with SHA-256 hashes and checks integrity on startup.                                                        | Because the app runs under a standard user account, an attacker on the same OS user can still edit `../passvault.log`—the hash chain detects tampering rather than physically preventing it. |
| **Shoulder-surfing**                                              | Passwords are never echoed during input or printed on `get`; copied to clipboard and cleared automatically after 30 seconds.                                                                                                      | Any other desktop application running under the same user session can read the clipboard during the 30-second window.                                                                     |

---

## 4. Conclusion

Building PassVault demonstrated that implementing a secure password manager involves far more than simply calling an
encryption API. While Argon2id and AES-256-GCM protect credentials on disk, real-world security depends just as much on
surrounding engineering choices: handling secrets in mutable arrays instead of `String` objects, persisting brute-force
lockouts so restarts cannot bypass them, enforcing user-scoped SQL queries, and ensuring logs cannot be silently
altered.

By Checkpoint 3, all core functional and security requirements—including authenticated encryption, memory wiping, strict
input validation, per-user isolation, tamper-evident logging, unit testing, and Docker packaging—are implemented and
verified. For future iterations beyond this course, useful extensions would include a built-in cryptographically secure
password generator, encrypted vault export/import for backups, and optional AAD (Additional Authenticated Data) binding
in AES-GCM to cryptographically tie each ciphertext to its service name and user ID.