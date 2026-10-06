package ee.taltech.passvault.crypto;

import java.security.SecureRandom;

/**
 * Utility for generating cryptographically secure random bytes for salts and nonces.
 */
public class SecureRandomUtils {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static final int SALT_LENGTH_BYTES = 16;
    public static final int GCM_NONCE_LENGTH_BYTES = 12;

    private SecureRandomUtils() {
        // Utility class
    }

    /**
     * Generates a cryptographically secure random 16-byte salt for Argon2id key derivation.
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    /**
     * Generates a cryptographically secure random 12-byte IV/nonce for AES-GCM.
     */
    public static byte[] generateNonce() {
        byte[] nonce = new byte[GCM_NONCE_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(nonce);
        return nonce;
    }
}