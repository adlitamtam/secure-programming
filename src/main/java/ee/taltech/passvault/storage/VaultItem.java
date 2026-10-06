package ee.taltech.passvault.storage;

/**
 * Model representing an encrypted vault record retrieved from the database.
 */
public class VaultItem {

    private final int id;
    private final int userId;
    private final String service;
    private final String accountUsername;
    private final byte[] ciphertext;
    private final byte[] nonce;

    public VaultItem(int id, int userId, String service, String accountUsername, byte[] ciphertext, byte[] nonce) {
        this.id = id;
        this.userId = userId;
        this.service = service;
        this.accountUsername = accountUsername;
        this.ciphertext = ciphertext;
        this.nonce = nonce;
    }

    public int getId() {
        return id;
    }

    public int getUserId() {
        return userId;
    }

    public String getService() {
        return service;
    }

    public String getAccountUsername() {
        return accountUsername;
    }

    public byte[] getCiphertext() {
        return ciphertext;
    }

    public byte[] getNonce() {
        return nonce;
    }
}
