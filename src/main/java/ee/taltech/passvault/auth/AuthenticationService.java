package ee.taltech.passvault.auth;

import ee.taltech.passvault.crypto.KeyDerivationService;
import ee.taltech.passvault.crypto.MemoryWiper;
import ee.taltech.passvault.crypto.SecureRandomUtils;
import ee.taltech.passvault.security.LogSanitizer;
import ee.taltech.passvault.storage.UserDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

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
     * @param username       Desired username.
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
     * @param username       Username attempting login.
     * @param masterPassword Provided master password.
     * @return Optional containing UserSession if authentication succeeds, empty otherwise.
     */
    public Optional<UserSession> authenticate(String username, char[] masterPassword) {
        long lockedSeconds = userDao.getRemainingLockoutSeconds();
        if (lockedSeconds > 0) {
            throw new IllegalStateException("Too many failed attempts. Try again in " + lockedSeconds + " seconds.");
        }

        if (username == null || username.isBlank() || masterPassword == null || masterPassword.length == 0) {
            return Optional.empty();
        }

        String safeUsername = LogSanitizer.sanitize(username);
        Optional<User> userOpt = userDao.getUserByUsername(username);
        if (userOpt.isEmpty()) {
            // Dummy Argon2id run to prevent username enumeration via response timing
            byte[] dummySalt = new byte[16];
            byte[] dummyKey = keyDerivationService.deriveKey(masterPassword, dummySalt);
            MemoryWiper.wipe(dummyKey);

            logger.warn("Authentication failed: User '{}' not found.", safeUsername);
            userDao.recordFailedAttempt();
            checkIfNowLocked();
            return Optional.empty();
        }

        User user = userOpt.get();
        byte[] derivedAuthKey = null;
        byte[] encSalt = null;

        try {
            derivedAuthKey = keyDerivationService.deriveKey(masterPassword, user.getSalt());
            String computedHashHex = HexFormat.of().formatHex(derivedAuthKey).toLowerCase();
            String storedHashHex = user.getAuthHash().toLowerCase();

            boolean hashesMatch = MessageDigest.isEqual(
                    computedHashHex.getBytes(StandardCharsets.UTF_8),
                    storedHashHex.getBytes(StandardCharsets.UTF_8)
            );

            if (!hashesMatch) {
                logger.warn("Authentication failed: Invalid master password for user '{}'.", safeUsername);
                userDao.recordFailedAttempt();
                checkIfNowLocked();
                return Optional.empty();
            }

            userDao.resetLockout();

            encSalt = user.getSalt().clone();
            encSalt[0] ^= 0x01; // Domain Separation Byte
            byte[] encryptionKey = keyDerivationService.deriveKey(masterPassword, encSalt);

            logger.info("Authentication successful for user '{}'. Session created.", safeUsername);
            return Optional.of(new UserSession(user.getId(), user.getUsername(), encryptionKey));

        } finally {
            MemoryWiper.wipe(derivedAuthKey);
            MemoryWiper.wipe(encSalt);
        }
    }

    private void checkIfNowLocked() {
        long lockedSeconds = userDao.getRemainingLockoutSeconds();
        if (lockedSeconds > 0) {
            throw new IllegalStateException("Too many failed attempts. Locked for " + lockedSeconds + " seconds.");
        }
    }
}
