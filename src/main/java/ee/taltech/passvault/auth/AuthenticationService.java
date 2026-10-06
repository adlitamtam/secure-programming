package ee.taltech.passvault.auth;

import ee.taltech.passvault.crypto.KeyDerivationService;
import ee.taltech.passvault.crypto.MemoryWiper;
import ee.taltech.passvault.crypto.SecureRandomUtils;
import ee.taltech.passvault.storage.UserDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HexFormat;
import java.util.Optional;

/**
 * Handles user registration, master password verification, and session key derivation.
 */
public class AuthenticationService {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

    private final UserDao userDao;
    private final KeyDerivationService keyDerivationService;

    public AuthenticationService() {
        this.userDao = new UserDao();
        this.keyDerivationService = new KeyDerivationService();
    }

    /**
     * Registers a new user in the database.
     * Generates a unique 16-byte salt and derives the authentication hash using Argon2id.
     *
     * @param username Desired username.
     * @param masterPassword User's master password (char[]).
     * @return true if registration succeeded, false if username exists.
     */
    public boolean registerUser(String username, char[] masterPassword) {
        if (username == null || username.isBlank() || masterPassword == null || masterPassword.length == 0) {
            throw new IllegalArgumentException("Username and master password cannot be empty.");
        }

        // 1. Generate a cryptographically secure random 16-byte salt
        byte[] salt = SecureRandomUtils.generateSalt();
        byte[] derivedAuthKey = null;

        try {
            // 2. Derive authentication key bytes via Argon2id
            derivedAuthKey = keyDerivationService.deriveKey(masterPassword, salt);
            String authHashHex = HexFormat.of().formatHex(derivedAuthKey);

            // 3. Store user in SQLite database
            return userDao.createUser(username, salt, authHashHex);

        } finally {
            // Memory wiping
            MemoryWiper.wipe(derivedAuthKey);
        }
    }

    /**
     * Authenticates a user against stored master password hash.
     * If successful, returns the derived encryption key (K_enc) for vault decryption.
     *
     * @param username Username attempting login.
     * @param masterPassword Provided master password.
     * @return Optional containing UserSession if authentication succeeds, empty otherwise.
     */
    public Optional<UserSession> authenticate(String username, char[] masterPassword) {
        if (username == null || username.isBlank() || masterPassword == null || masterPassword.length == 0) {
            return Optional.empty();
        }

        // 1. Fetch stored user record from database
        Optional<User> userOpt = userDao.getUserByUsername(username);
        if (userOpt.isEmpty()) {
            logger.warn("Authentication failed: User '{}' not found.", username);
            return Optional.empty();
        }

        User user = userOpt.get();
        byte[] derivedAuthKey = null;
        byte[] encryptionKey = null;

        try {
            // 2. Re-derive authentication key from provided master password and user's stored salt
            derivedAuthKey = keyDerivationService.deriveKey(masterPassword, user.getSalt());
            String computedHashHex = HexFormat.of().formatHex(derivedAuthKey);

            // 3. Verify against stored auth_hash (Constant-time string comparison)
            if (!constantTimeEquals(computedHashHex, user.getAuthHash())) {
                logger.warn("Authentication failed: Invalid master password for user '{}'.", username);
                return Optional.empty();
            }

            // 4. Derive distinct 256-bit encryption key (K_enc) using salt with domain separation modifier
            byte[] encSalt = user.getSalt().clone();
            encSalt[0] ^= 0x01; // Simple domain separation byte
            encryptionKey = keyDerivationService.deriveKey(masterPassword, encSalt);

            logger.info("Authentication successful for user '{}'. Session created.", username);
            return Optional.of(new UserSession(user.getId(), user.getUsername(), encryptionKey));

        } finally {
            MemoryWiper.wipe(derivedAuthKey);
        }
    }

    /**
     * Constant-time string comparison to mitigate timing attacks.
     */
    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }
        byte[] aBytes = a.getBytes();
        byte[] bBytes = b.getBytes();
        if (aBytes.length != bBytes.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < aBytes.length; i++) {
            result |= aBytes[i] ^ bBytes[i];
        }
        return result == 0;
    }
}
