package ee.taltech.passvault.auth;

/**
 * Model representing a registered user account stored in the database.
 */
public class User {

    private final int id;
    private final String username;
    private final byte[] salt;
    private final String authHash;

    public User(int id, String username, byte[] salt, String authHash) {
        this.id = id;
        this.username = username;
        this.salt = salt;
        this.authHash = authHash;
    }

    public int getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public byte[] getSalt() {
        return salt;
    }

    public String getAuthHash() {
        return authHash;
    }
}