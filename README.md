# Secure Password Manager

**Course:** ICS0022 Secure Programming (Tallinn University of Technology)

**Student:** Matilda Thurso (266057IV) - matilt@taltech.ee

A command-line password manager written in Java, built for the ICS0022 semester project. The goal is to provide a local credential store that protects passwords at rest and in memory using standard cryptographic algorithms and secure coding practices.

---

## 1. How It Works

The application operates locally using an embedded SQLite database. It follows a zero-knowledge approach: your master password is never written to disk, nor is the raw encryption key.

### Data Flow & Cryptography
1. **Master Password & Derivation:**
   * When creating an account, a random 16-byte salt is generated.
   * I use **Argon2id** (via Bouncy Castle) to derive two keys from your master password:
      * An authentication hash to verify your identity on login.
      * A 256-bit encryption key (`K_enc`) kept in memory while the vault session is open.
2. **Adding an Entry:**
   * The user enters the service name, username, and password.
   * A fresh 12-byte initialization vector is generated using `SecureRandom`.
   * The password is encrypted using **AES-256-GCM** (which also calculates an authentication tag to prevent tampering).
   * Only the ciphertext, IV, service name, and username are stored in the SQLite database.
3. **Retrieving / Copying:**
   * Entries are fetched by service name.
   * The password is decrypted in memory using `K_enc` and the stored IV.
   * To prevent shoulder-surfing, passwords are never printed to `stdout` in cleartext. Instead, the program copies the password directly to the system clipboard and clears it after 30 seconds.
4. **Memory Cleanup:**
   * Sensitive inputs are read as `char[]` via `System.console().readPassword()`.
   * As soon as cryptographic operations are done, all arrays holding keys or plaintext passwords are wiped with zeroes (`Arrays.fill(..., '\0')`).

---

## 2. Requirements & Dependencies

* JDK 21 or newer
* Apache Maven 3.8+
* Dependencies (handled via Maven `pom.xml`):
   * `org.bouncycastle:bcprov-jdk18on` (for Argon2id and crypto primitives)
   * `org.xerial:sqlite-jdbc` (local database)
   * `org.slf4j:slf4j-api` & `ch.qos.logback:logback-classic` (structured logging)

---

## 3. How to Build and Run

### Clone and Compile
```bash
git clone https://github.com/adlitamtam/secure-programming.git
cd secure-password-manager
mvn clean package
```

This compiles the code, executes unit tests, and produces an executable JAR file in target.

### Running the App
Run the compiled JAR:
```bash
java -jar target/secure-password-manager-1.0.0-SNAPSHOT.jar
````

---

## 4. Usage & Commands

Running `java -jar target/passvault-1.0.jar` launches an interactive prompt:
```
=== PassVault CLI ===
1. Login
2. Register
3. Exit
> 1
Username: alice
Master Password: [hidden]
Vault unlocked for user 'alice'.

[alice@vault] > list
[alice@vault] > add github.com
[alice@vault] > get github.com
[alice@vault] > delete github.com
[alice@vault] > lock
```