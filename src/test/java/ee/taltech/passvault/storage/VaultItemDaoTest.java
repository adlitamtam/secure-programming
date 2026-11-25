package ee.taltech.passvault.storage;

import org.junit.jupiter.api.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class VaultItemDaoTest {

    private static final Path DB_PATH = Path.of("vault.db");
    private static final Path BACKUP_PATH = Path.of("vault.db.testbackup");

    private VaultItemDao vaultItemDao;
    private int aliceId;
    private int bobId;

    @BeforeAll
    static void backupExistingDatabase() throws IOException {
        if (Files.exists(DB_PATH)) {
            Files.copy(DB_PATH, BACKUP_PATH, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        deleteDbFiles();
        DatabaseManager dbManager = DatabaseManager.getInstance();
        assertTrue(dbManager.initializeAndValidate());

        aliceId = insertTestUser(dbManager, "alice");
        bobId = insertTestUser(dbManager, "bob");
        vaultItemDao = new VaultItemDao();
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

    private int insertTestUser(DatabaseManager dbManager, String username) throws Exception {
        String sql = "INSERT INTO users (username, salt, auth_hash) VALUES (?, ?, ?)";
        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, username);
            pstmt.setBytes(2, new byte[16]);
            pstmt.setString(3, "dummy_hash_" + username);
            pstmt.executeUpdate();

            try (ResultSet keys = pstmt.getGeneratedKeys()) {
                assertTrue(keys.next());
                return keys.getInt(1);
            }
        }
    }

    @Test
    @DisplayName("Stores, lists, fetches (case-insensitive), and deletes vault items for owner")
    void testCrudOperationsForOwner() {
        byte[] ciphertext = new byte[]{10, 20, 30, 40};
        byte[] nonce = new byte[12];

        assertTrue(vaultItemDao.addVaultItem(aliceId, "github.com", "alice_gh", ciphertext, nonce));

        List<String> services = vaultItemDao.getServicesForUser(aliceId);
        assertEquals(List.of("github.com"), services);

        Optional<VaultItem> fetched = vaultItemDao.getVaultItemByService(aliceId, "GITHUB.COM");
        assertTrue(fetched.isPresent(), "Lookup by service name should be case-insensitive");

        assertTrue(vaultItemDao.deleteVaultItem(aliceId, "github.com"));
        assertTrue(vaultItemDao.getVaultItemByService(aliceId, "github.com").isEmpty());
    }

    @Test
    @DisplayName("Enforces strict per-user isolation across list, get, and delete")
    void testPerUserIsolation() {
        byte[] ciphertext = new byte[]{99, 88, 77};
        byte[] nonce = new byte[12];

        assertTrue(vaultItemDao.addVaultItem(aliceId, "github.com", "alice_gh", ciphertext, nonce));

        // Bob must not see, fetch, or delete Alice's entry
        assertTrue(vaultItemDao.getServicesForUser(bobId).isEmpty(),
                "Bob's service list must not include Alice's items");
        assertTrue(vaultItemDao.getVaultItemByService(bobId, "github.com").isEmpty(),
                "Bob must not be able to fetch Alice's credential");
        assertFalse(vaultItemDao.deleteVaultItem(bobId, "github.com"),
                "Bob must not be able to delete Alice's credential");

        // Alice's item must remain intact
        assertTrue(vaultItemDao.getVaultItemByService(aliceId, "github.com").isPresent(),
                "Alice's credential must still exist after Bob's delete attempt");
    }

    @Test
    @DisplayName("Rejects invalid userId, service name, or account username before DB access")
    void testInputValidationInDao() {
        byte[] ciphertext = new byte[]{1, 2, 3};
        byte[] nonce = new byte[12];

        assertThrows(IllegalArgumentException.class,
                () -> vaultItemDao.addVaultItem(0, "github.com", "alice", ciphertext, nonce));
        assertThrows(IllegalArgumentException.class,
                () -> vaultItemDao.addVaultItem(aliceId, "github.com\ninjected", "alice", ciphertext, nonce));
        assertThrows(IllegalArgumentException.class,
                () -> vaultItemDao.addVaultItem(aliceId, "github.com", "alice\ninjected", ciphertext, nonce));
    }
}
