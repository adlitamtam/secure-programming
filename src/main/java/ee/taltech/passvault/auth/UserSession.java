package ee.taltech.passvault.auth;

import ee.taltech.passvault.crypto.MemoryWiper;

/**
 * Represents an active, authenticated user session holding the transient encryption key (K_enc).
 */
public class UserSession {

    private final int userId;
    private final String username;
    private final byte[] encryptionKey;

    public UserSession(int userId, String username, byte[] encryptionKey) {
        this.userId = userId;
        this.username = username;
        this.encryptionKey = encryptionKey;
    }

    public int getUserId() {
        return userId;
    }

    public String getUsername() {
        return username;
    }

    public byte[] getEncryptionKey() {
        return encryptionKey;
    }

    /**
     * Immediately zero-out the active session key from memory upon logout or lock.
     */
    public void invalidate() {
        MemoryWiper.wipe(encryptionKey);
    }
}
