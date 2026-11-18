package ee.taltech.passvault.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
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

    private DatabaseManager() {}

    public static synchronized DatabaseManager getInstance() {
        if (instance == null) {
            instance = new DatabaseManager();
        }
        return instance;
    }

    /**
     * Opens a connection and guarantees that the schema exists (self-healing if DB was deleted at runtime).
     */
    public Connection getConnection() throws SQLException {
        Connection conn = DriverManager.getConnection(DB_URL);
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("PRAGMA foreign_keys = ON;");
            stmt.execute("PRAGMA journal_mode = WAL;");
            ensureTablesExist(stmt);
        }
        return conn;
    }

    /**
     * Startup check to verify write access and initialize the database.
     */
    public boolean initializeAndValidate() {
        File parentDir = new File(DB_FILE).getAbsoluteFile().getParentFile();
        if (parentDir != null && !parentDir.canWrite()) {
            logger.error("Database directory is not writable: {}", parentDir.getAbsolutePath());
            System.err.println("Critical Error: Cannot write to database directory.");
            return false;
        }

        try (Connection conn = getConnection()) {
            logger.info("Database initialized successfully.");
            return true;
        } catch (SQLException e) {
            logger.error("Failed to initialize database: {}", e.getMessage());
            System.err.println("Critical Error: " + e.getMessage());
            return false;
        }
    }

    private void ensureTablesExist(Statement stmt) throws SQLException {
        stmt.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL,
                auth_hash TEXT NOT NULL
            );
        """);

        stmt.execute("""
            CREATE TABLE IF NOT EXISTS vault_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                service TEXT NOT NULL,
                account_username TEXT NOT NULL,
                ciphertext BLOB NOT NULL,
                nonce BLOB NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """);

        stmt.execute("""
            CREATE TABLE IF NOT EXISTS lockout (
                id INTEGER PRIMARY KEY,
                attempts INTEGER NOT NULL DEFAULT 0,
                locked_until INTEGER NOT NULL DEFAULT 0
            );
        """);

        stmt.execute("INSERT OR IGNORE INTO lockout (id, attempts, locked_until) VALUES (1, 0, 0);");
    }
}
