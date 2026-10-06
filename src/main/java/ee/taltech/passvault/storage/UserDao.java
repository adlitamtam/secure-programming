package ee.taltech.passvault.storage;

import ee.taltech.passvault.auth.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

/**
 * Data Access Object for user management in SQLite.
 * Uses strict parameterized PreparedStatements to prevent SQL injection.
 */
public class UserDao {

    private static final Logger logger = LoggerFactory.getLogger(UserDao.class);
    private final DatabaseManager dbManager;

    public UserDao() {
        this.dbManager = DatabaseManager.getInstance();
    }

    /**
     * Inserts a new user record into the database.
     *
     * @param username Unique username.
     * @param salt Cryptographic random salt for key derivation.
     * @param authHash Derived authentication hash (Argon2id).
     * @return true if user was successfully created, false if username already exists.
     */
    public boolean createUser(String username, byte[] salt, String authHash) {
        String sql = "INSERT INTO users (username, salt, auth_hash) VALUES (?, ?, ?)";

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, username.toLowerCase().trim());
            pstmt.setBytes(2, salt);
            pstmt.setString(3, authHash);

            int affectedRows = pstmt.executeUpdate();
            logger.info("User '{}' registered successfully.", username);
            return affectedRows > 0;

        } catch (SQLException e) {
            if (e.getErrorCode() == 19 || e.getMessage().contains("UNIQUE constraint failed")) {
                logger.warn("Registration attempt failed: Username '{}' already exists.", username);
                return false;
            }
            logger.error("Database error while creating user '{}': {}", username, e.getMessage());
            throw new RuntimeException("Failed to register user due to a database error.", e);
        }
    }

    /**
     * Retrieves a user by username.
     *
     * @param username Username to query.
     * @return Optional containing the User model if found.
     */
    public Optional<User> getUserByUsername(String username) {
        String sql = "SELECT id, username, salt, auth_hash FROM users WHERE username = ?";

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, username.toLowerCase().trim());

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    User user = new User(
                            rs.getInt("id"),
                            rs.getString("username"),
                            rs.getBytes("salt"),
                            rs.getString("auth_hash")
                    );
                    return Optional.of(user);
                }
            }
        } catch (SQLException e) {
            logger.error("Database error while fetching user '{}': {}", username, e.getMessage());
        }
        return Optional.empty();
    }
}
