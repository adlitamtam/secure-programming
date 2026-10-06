package ee.taltech.passvault.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Data Access Object for managing encrypted vault credentials.
 * Enforces per-user access control on every database query.
 */
public class VaultItemDao {

    private static final Logger logger = LoggerFactory.getLogger(VaultItemDao.class);
    private final DatabaseManager dbManager;

    public VaultItemDao() {
        this.dbManager = DatabaseManager.getInstance();
    }

    /**
     * Stores a new encrypted credential in the database.
     *
     * @param userId ID of the authenticated user.
     * @param service Name/Domain of the target service (e.g., github.com).
     * @param accountUsername Account username or email.
     * @param ciphertext AES-256-GCM encrypted password bytes.
     * @param nonce 12-byte initialization vector used during encryption.
     * @return true if stored successfully.
     */
    public boolean addVaultItem(int userId, String service, String accountUsername, byte[] ciphertext, byte[] nonce) {
        String sql = "INSERT INTO vault_items (user_id, service, account_username, ciphertext, nonce) VALUES (?, ?, ?, ?, ?)";

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, userId);
            pstmt.setString(2, service.trim());
            pstmt.setString(3, accountUsername.trim());
            pstmt.setBytes(4, ciphertext);
            pstmt.setBytes(5, nonce);

            int affectedRows = pstmt.executeUpdate();
            logger.info("Vault item added for service '{}' under userId {}", service, userId);
            return affectedRows > 0;

        } catch (SQLException e) {
            logger.error("Database error adding item for service '{}' (userId {}): {}", service, userId, e.getMessage());
            return false;
        }
    }

    /**
     * Lists all service names stored for a specific user (does not fetch ciphertext).
     *
     * @param userId ID of the authenticated user.
     * @return List of stored service names.
     */
    public List<String> getServicesForUser(int userId) {
        String sql = "SELECT service FROM vault_items WHERE user_id = ? ORDER BY service ASC";
        List<String> services = new ArrayList<>();

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, userId);

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    services.add(rs.getString("service"));
                }
            }
        } catch (SQLException e) {
            logger.error("Database error retrieving services for userId {}: {}", userId, e.getMessage());
        }
        return services;
    }

    /**
     * Fetches a specific vault item for a user by service name.
     * Enforces per-user isolation: user_id = ?
     *
     * @param userId ID of the authenticated user.
     * @param service Service name to query.
     * @return Optional containing the VaultItem if found and owned by user.
     */
    public Optional<VaultItem> getVaultItemByService(int userId, String service) {
        String sql = "SELECT id, user_id, service, account_username, ciphertext, nonce FROM vault_items WHERE user_id = ? AND LOWER(service) = LOWER(?)";

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, userId);
            pstmt.setString(2, service.trim());

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    VaultItem item = new VaultItem(
                            rs.getInt("id"),
                            rs.getInt("user_id"),
                            rs.getString("service"),
                            rs.getString("account_username"),
                            rs.getBytes("ciphertext"),
                            rs.getBytes("nonce")
                    );
                    return Optional.of(item);
                }
            }
        } catch (SQLException e) {
            logger.error("Database error fetching item for service '{}' (userId {}): {}", service, userId, e.getMessage());
        }
        return Optional.empty();
    }

    /**
     * Deletes a credential entry owned by the user.
     *
     * @param userId ID of the authenticated user.
     * @param service Service name to remove.
     * @return true if an entry was deleted.
     */
    public boolean deleteVaultItem(int userId, String service) {
        String sql = "DELETE FROM vault_items WHERE user_id = ? AND LOWER(service) = LOWER(?)";

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, userId);
            pstmt.setString(2, service.trim());

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows > 0) {
                logger.info("Vault item for service '{}' deleted by userId {}", service, userId);
                return true;
            }
        } catch (SQLException e) {
            logger.error("Database error deleting item for service '{}' (userId {}): {}", service, userId, e.getMessage());
        }
        return false;
    }
}
