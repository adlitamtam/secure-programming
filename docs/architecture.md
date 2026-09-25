# Threat Model and System Architecture

## 1. Technical Decisions and Cryptographic Scheme
* **Language:** Java 17+ 
* **Libraries:**
    * `org.bouncycastle:bcprov-jdk18on` – Cryptographic provider for Argon2id and AES-256-GCM primitives.
    * `org.xerial:sqlite-jdbc` – Embedded local relational database.
    * `ch.qos.logback:logback-classic` – Structured logging without secret exposure.
* **Cryptographic Scheme:**
    * **Key Derivation:** Argon2id derives an authentication key (K_auth) and an encryption key (K_enc).
    * **Vault Encryption:** AES-256-GCM providing confidentiality and tamper-evident authentication tags.
* **Vault Storage Format:** Local embedded SQLite database (`vault.db`) storing salts, hashes, initialization vectors (nonces), and ciphertext blobs.

---

## 2. Threat Model

### Trust Boundaries and Key Locations
* **Volatile Memory (RAM / Client):** Master password (`char[]`) and K_enc are kept temporarily in memory and overwritten immediately after use.
* **Storage at Rest (Disk / Database):** Untrusted boundary. Holds only ciphertexts, salts, and nonces. No plaintext secrets or keys ever touch the disk.
* **User Interface (Console):** Boundary where user commands and credentials enter the system.

### Threats and Mitigations (Covering Key Areas)

| Area | Threat | Mitigation |
| :--- | :--- | :--- |
| **Master Password** | Offline brute-force dictionary attacks if the database is leaked. | Memory-hard key derivation via **Argon2id** with calibrated cost factors and per-user random salts. |
| **Vault at Rest** | Unauthorized record manipulation or database theft. | Authenticated encryption (**AES-256-GCM**); parameterized SQL queries (**PreparedStatement**) enforcing per-user access control (`WHERE user_id = ?`). |
| **Vault in Memory** | Heap dumps or memory scanning by hostile local processes. | Avoid immutable `String` objects; sensitive data is handled in `char[]`/`byte[]` and wiped immediately (`Arrays.fill(..., 0)`) via `MemoryWiper`. Automatic session timeout on inactivity. |
| **Interface / CLI** | Shoulder-surfing or terminal history exposure; clipboard sniffing. | Masked console input (`System.console().readPassword()`); retrieved passwords are sent directly to the OS clipboard and auto-cleared after 30 seconds. Passwords are never printed to stdout. |

---

## 3. Architecture and Data Flows

![PassVault Architecture](docs/architecture.png)

### Flow 1: Authentication and Login
1. **User → Presentation Layer:** Inputs `username` and `masterPassword` (masked `char[]`).
2. **Presentation Layer → User Management Module:** Passes input through `InputValidator` to `AuthenticationService`.
3. **AuthenticationService → Storage Layer (UserDao):** Queries user record (`salt`, `auth_hash`) via parameterized SQL.
4. **UserDao → Database (vault.db):** Retrieves record from SQLite.
5. **AuthenticationService → Cryptographic Module (KeyDerivationEngine):** Executes Argon2id with `salt` to derive `K_auth` and `K_enc`.
6. **Cryptographic Module → User Management Module:**
    * Verifies `K_auth` against `auth_hash`.
    * Stores `K_enc` temporarily in `UserSessionState`.
    * Calls `MemoryWiper` to zeroize `char[]` and hash buffers immediately.

### Flow 2: Store Credential (Add Entry)
1. **User → Presentation Layer:** Enters `service`, `username`, and `password` (`char[]`).
2. **Presentation Layer → User Management Module:** `InputValidator` validates lengths and character sets.
3. **User Management Module → Cryptographic Module:** Requests encryption using active `K_enc` from `UserSessionState`.
4. **Cryptographic Module:**
    * `SecureRandomGenerator` outputs a unique 12-byte IV/nonce.
    * `EncryptionService` executes AES-256-GCM on plaintext password → produces ciphertext and auth tag.
    * `MemoryWiper` clears the plaintext buffer.
5. **User Management Module → Storage Layer (VaultItemDao):** Passes metadata, ciphertext, and nonce.
6. **VaultItemDao → Database (vault.db):** Inserts record using `PreparedStatement` bound to current `user_id`.

### Flow 3: Retrieve Credential (Clipboard / No Cleartext)
1. **User → Presentation Layer:** Issues command `get <service>`.
2. **Presentation Layer → User Management Module:** Forwards request with active session `user_id`.
3. **User Management Module → Storage Layer (VaultItemDao):** Enforces ownership check (`WHERE user_id = ? AND service = ?`).
4. **Storage Layer → Cryptographic Module (EncryptionService):** Passes ciphertext and nonce with active `K_enc`.
5. **Cryptographic Module:** Authenticates GCM tag, decrypts password into a temporary buffer, and wipes internal states.
6. **Cryptographic Module → Presentation Layer (ClipboardHelper):** Copies decrypted password directly into system clipboard.
7. **Presentation Layer (ClipboardHelper):** Initiates a 30-second timer to wipe the clipboard; no plaintext is ever printed to terminal output.