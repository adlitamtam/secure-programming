package ee.taltech.passvault.storage;

import org.junit.jupiter.api.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class DatabaseManagerTest {

    private static final Path DB_PATH = Path.of("vault.db");
    private static final Path BACKUP_PATH = Path.of("vault.db.testbackup");

    @BeforeAll
    static void backupExistingDatabase() throws IOException {
        if (Files.exists(DB_PATH)) {
            Files.copy(DB_PATH, BACKUP_PATH, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    @BeforeEach
    void cleanDatabaseFiles() throws IOException {
        deleteDbFiles();
    }

    @AfterAll
    static void restoreExistingDatabase() throws IOException {
        deleteDbFiles();
        if (Files.exists(BACKUP_PATH)) {
            Files.move(BACKUP_PATH, DB_PATH, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void deleteDbFiles() throws IOException {
        Files.deleteIfExists(DB_PATH);
        Files.deleteIfExists(Path.of("vault.db-wal"));
        Files.deleteIfExists(Path.of("vault.db-shm"));
    }

    @Test
    @DisplayName("initializeAndValidate creates users, vault_items, and lockout tables")
    void testInitializeAndSchemaCreation() throws Exception {
        DatabaseManager dbManager = DatabaseManager.getInstance();

        assertTrue(dbManager.initializeAndValidate(), "Database initialization should succeed");
        assertTrue(Files.exists(DB_PATH), "vault.db file should be created");

        Set<String> tables = new HashSet<>();
        try (Connection conn = dbManager.getConnection();
             ResultSet rs = conn.getMetaData().getTables(null, null, "%", new String[]{"TABLE"})) {
            while (rs.next()) {
                tables.add(rs.getString("TABLE_NAME").toLowerCase());
            }
        }

        assertTrue(tables.contains("users"), "Table 'users' must exist");
        assertTrue(tables.contains("vault_items"), "Table 'vault_items' must exist");
        assertTrue(tables.contains("lockout"), "Table 'lockout' must exist");

        // Verify default lockout row (id = 1) is initialized
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement("SELECT attempts, locked_until FROM lockout WHERE id = 1");
             ResultSet rs = ps.executeQuery()) {
            assertTrue(rs.next(), "Default lockout row must exist");
            assertEquals(0, rs.getInt("attempts"));
            assertEquals(0L, rs.getLong("locked_until"));
        }
    }

    @Test
    @DisplayName("getConnection recreates schema automatically if vault.db is deleted at runtime")
    void testSelfHealingOnDeletedDatabase() throws Exception {
        DatabaseManager dbManager = DatabaseManager.getInstance();
        assertTrue(dbManager.initializeAndValidate());
        assertTrue(Files.exists(DB_PATH));

        // Simulate accidental deletion while application is running
        deleteDbFiles();
        assertFalse(Files.exists(DB_PATH));

        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) FROM users");
             ResultSet rs = ps.executeQuery()) {
            assertTrue(Files.exists(DB_PATH), "Database must be recreated automatically");
            assertTrue(rs.next());
            assertEquals(0, rs.getInt(1));
        }
    }
}
