# PassVault – Secure CLI Password Manager

**Course:** ICS0022 Secure Programming (Tallinn University of Technology)  
**Student:** Matilda Thurso (266057IV) – matilt@taltech.ee

A command-line password manager written in Java for the ICS0022 semester project. The goal of this project is to store credentials locally while protecting sensitive data both at rest and in memory using modern cryptography and defensive coding practices.

---

## 1. How It Works

PassVault runs locally and stores its data in an embedded SQLite database (`vault.db`). It follows a zero-knowledge approach: neither your master password nor the vault encryption key is ever written to disk.

### Cryptography & Data Flow
1. **Registration & Key Derivation:**
    - When creating an account, a random 16-byte salt is generated via `SecureRandom`.
    - Using **Argon2id** (Bouncy Castle, 64 MB memory, 3 iterations), two separate keys are derived from the master password using domain separation (modifying the salt byte for the second key):
        - An authentication hash stored in SQLite to verify logins (checked using constant-time comparison).
        - A 256-bit vault encryption key (`K_enc`) kept only in RAM while your session is unlocked.
2. **Storing Credentials:**
    - Each entry gets a fresh 12-byte random nonce.
    - Passwords are encrypted with **AES-256-GCM**, which also generates an authentication tag so any tampering with the database file is detected during decryption.
    - Only the service name, account username, nonce, and encrypted ciphertext are saved in SQLite.
3. **Retrieving Passwords:**
    - Entries are decrypted on demand in memory using `K_enc`.
    - To avoid shoulder-surfing, passwords are never printed to the terminal. Instead, they are copied directly to the system clipboard and automatically wiped after 30 seconds (with a safe fallback if running in a headless environment without a GUI).

### Additional Security Measures
- **Memory Hygiene:** Passwords and derived keys are handled as `char[]` and `byte[]` arrays rather than immutable `String` objects and are overwritten with zeroes (`\0`) in `finally` blocks right after use. A JVM shutdown hook also wipes active session keys if the program is terminated abruptly with `Ctrl+C`.
- **Persistent Brute-Force Protection:** After 5 failed login attempts, login is locked for 60 seconds. Because the attempt counter and lockout timestamp are stored in SQLite, restarting the application does not reset the lockout.
- **Database Safety:** All database queries use `PreparedStatement` to prevent SQL injection, and the connection automatically recreates missing tables if `vault.db` is deleted while the app is running.
- **Input & Log Protection:** User inputs are checked against strict character whitelists and length limits. Logs (`passvault.log`) use size-based rotation, sanitize newline characters to prevent log injection, include the active username via SLF4J MDC, and chain log lines with SHA-256 hashes so external edits to the log file trigger a warning on startup.

---

## 2. Requirements & Dependencies

- **Java:** JDK 21 or newer
- **Build Tool:** Apache Maven 3.8+
- **Libraries (managed in `pom.xml`):**
    - `org.bouncycastle:bcprov-jdk18on` (Argon2id key derivation)
    - `org.xerial:sqlite-jdbc` (embedded SQLite database)
    - `org.slf4j:slf4j-api` & `ch.qos.logback:logback-classic` (logging)
    - `org.junit.jupiter:junit-jupiter` (unit testing)

---

## 3. Build and Run

### Clone and Build
```bash
git clone [https://github.com/adlitamtam/secure-programming.git](https://github.com/adlitamtam/secure-programming.git)
cd pw-manager
mvn clean package
```
This compiles the project, runs the unit tests, and creates the runnable JAR file in target/passvault.jar.

### Start the Application
Run the JAR from the project root directory (so SQLite uses the local vault.db file):
```bash
java -jar target/passvault.jar
```

---

## 4. Usage and Commands

After starting the program, you can register a new user or log into an existing vault:
```Plaintext
=== PassVault CLI ===
1. Login
2. Register
3. Exit
> Choice: 1
Username: alice
Master Password: 
SUCCESS: Vault unlocked for user 'alice'.

[alice@vault] Enter command ('help' for options):
> list
> add github.com
> get github.com
> delete github.com
> lock
```

### Available Vault Commands

`list` – Show all stored services and account usernames for your user.

`add <service>` – Encrypt and save a new credential entry.

`get <service>` – Decrypt the password for a service and copy it to the clipboard for 30 seconds.

`delete <service>` – Remove an entry from your vault.

`lock` – Wipe the session key from memory and return to the main menu.

`help` – Display available commands.
