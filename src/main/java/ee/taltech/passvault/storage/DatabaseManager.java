package ee.taltech.passvault.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.IOException;
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
    private static final String DB_URL = "jdbc:sqlite:vault.db";
    private static DatabaseManager instance;
    private Connection connection;

    private DatabaseManager() {
        try {
            this.connection = DriverManager.getConnection(DB_URL);
            enablePragmas();
            initializeSchema();
            logger.info("Database connection established and schema initialized successfully.");
        } catch (SQLException e) {
            logger.error("Failed to initialize database: {}", e.getMessage());
            throw new RuntimeException("Database initialization failed", e);
        }
    }

    /**
     * Singleton instance getter.
     */
    public static synchronized DatabaseManager getInstance() {
        if (instance == null) {
            instance = new DatabaseManager();
        }
        return instance;
    }

    /**
     * Returns the active database connection.
     */
    public Connection getConnection() {
        try {
            if (connection == null || connection.isClosed()) {
                connection = DriverManager.getConnection(DB_URL);
                enablePragmas();
            }
        } catch (SQLException e) {
            logger.error("Error checking/reopening connection: {}", e.getMessage());
        }
        return connection;
    }

    /**
     * Enforces SQLite PRAGMAs (Foreign Key Constraints & WAL mode).
     */
    private void enablePragmas() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("PRAGMA foreign_keys = ON;");
            stmt.execute("PRAGMA journal_mode = WAL;");
        }
    }

    /**
     * Reads schema.sql from resources and executes table creation.
     */
    private void initializeSchema() throws SQLException {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream("schema.sql");
        if (inputStream == null) {
            logger.error("schema.sql resource file not found!");
            throw new IllegalStateException("schema.sql file not found in resources");
        }

        StringBuilder sqlBuilder = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // Ignore comments and empty lines
                if (!line.trim().startsWith("--") && !line.trim().isEmpty()) {
                    sqlBuilder.append(line).append("\n");
                }
            }
        } catch (IOException e) {
            logger.error("Failed to read schema.sql: {}", e.getMessage());
            throw new RuntimeException("Could not read schema.sql", e);
        }

        // Split multiple SQL statements separated by semicolon
        String[] statements = sqlBuilder.toString().split(";");
        try (Statement stmt = connection.createStatement()) {
            for (String sql : statements) {
                if (!sql.trim().isEmpty()) {
                    stmt.execute(sql.trim());
                }
            }
        }
    }

    /**
     * Closes the database connection cleanly on shutdown.
     */
    public void closeConnection() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
                logger.info("Database connection closed.");
            }
        } catch (SQLException e) {
            logger.error("Error closing database connection: {}", e.getMessage());
        }
    }
}
