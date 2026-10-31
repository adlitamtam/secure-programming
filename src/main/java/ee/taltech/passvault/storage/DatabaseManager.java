package ee.taltech.passvault.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Manages SQLite database connection and schema initialization.
 */
public class DatabaseManager {

    private static final Logger logger = LoggerFactory.getLogger(DatabaseManager.class);
    private static final String DB_FILE = "vault.db";
    private static final String DB_URL = "jdbc:sqlite:" + DB_FILE + "?busy_timeout=5000";
    private static DatabaseManager instance;

    private DatabaseManager() {
    }

    public static synchronized DatabaseManager getInstance() {
        if (instance == null) {
            instance = new DatabaseManager();
        }
        return instance;
    }

    /**
     * Obtains a fresh database connection.
     */
    public Connection getConnection() throws SQLException {
        Connection conn = DriverManager.getConnection(DB_URL);
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("PRAGMA foreign_keys = ON;");
            stmt.execute("PRAGMA journal_mode = WAL;");
        }
        return conn;
    }

    /**
     * Pre-flight health check to verify write permissions and create tables if needed.
     *
     * @return true if database is fully operational, false if severe I/O errors occur.
     */
    public boolean initializeAndValidate() {
        File dbFile = new File(DB_FILE);
        File parentDir = dbFile.getAbsoluteFile().getParentFile();

        if (parentDir != null && !parentDir.canWrite()) {
            logger.error("Database directory is not writable: {}", parentDir.getAbsolutePath());
            System.err.println("Critical Error: Cannot write to database directory. Check file permissions.");
            return false;
        }

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {

            String createUsersTable = """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    salt BLOB NOT NULL,
                    auth_hash TEXT NOT NULL
                );
            """;

            String createVaultItemsTable = """
                CREATE TABLE IF NOT EXISTS vault_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    service TEXT NOT NULL,
                    account_username TEXT NOT NULL,
                    ciphertext BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """;

            stmt.execute(createUsersTable);
            stmt.execute(createVaultItemsTable);

            logger.info("Database schema initialized and validated successfully.");
            return true;

        } catch (SQLException e) {
            logger.error("Failed to initialize database: {}", e.getMessage());
            System.err.println("Critical Error: Could not connect to or setup database. " + e.getMessage());
            return false;
        }
    }

    /**
     * Checks if the database file still exists and contains the required schema.
     * Used during runtime to detect accidental DB file deletion.
     */
    public boolean isDatabaseAlive() {
        File dbFile = new File(DB_FILE);
        if (!dbFile.exists()) {
            logger.warn("Database file '{}' was deleted at runtime!", DB_FILE);
            return false;
        }

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.executeQuery("SELECT 1 FROM users LIMIT 1");
            return true;
        } catch (SQLException e) {
            logger.warn("Database health check failed: {}", e.getMessage());
            return false;
        }
    }
}
