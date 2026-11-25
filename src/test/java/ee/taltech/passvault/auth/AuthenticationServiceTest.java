package ee.taltech.passvault.auth;

import ee.taltech.passvault.storage.DatabaseManager;
import ee.taltech.passvault.storage.UserDao;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.HexFormat;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class AuthenticationServiceTest {

    private static final Path DB_PATH = Path.of("vault.db");
    private static final Path BACKUP_PATH = Path.of("vault.db.testbackup");

    private AuthenticationService authService;
    private UserDao userDao;

    @BeforeAll
    static void backupExistingDatabase() throws IOException {
        if (Files.exists(DB_PATH)) {
            Files.copy(DB_PATH, BACKUP_PATH, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    @BeforeEach
    void setUp() throws IOException {
        deleteDbFiles();
        assertTrue(DatabaseManager.getInstance().initializeAndValidate());
        userDao = new UserDao();
        authService = new AuthenticationService();
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
    @DisplayName("registerUser stores salted Argon2id hash, rejects duplicates/empty inputs, and authenticates valid login")
    void testRegisterAndAuthenticateSuccess() {
        assertThrows(IllegalArgumentException.class,
                () -> authService.registerUser("", "StrongMasterPass123!".toCharArray()));
        assertThrows(IllegalArgumentException.class,
                () -> authService.registerUser("alice", new char[0]));

        assertTrue(authService.registerUser("alice", "StrongMasterPass123!".toCharArray()),
                "First registration for 'alice' must succeed");
        assertFalse(authService.registerUser("alice", "AnotherPassword123!".toCharArray()),
                "Duplicate username registration must return false");

        User storedUser = userDao.getUserByUsername("alice").orElseThrow();
        assertEquals(16, storedUser.getSalt().length, "Stored salt must be 16 bytes");
        assertNotNull(storedUser.getAuthHash());
        assertFalse(storedUser.getAuthHash().isBlank());

        Optional<UserSession> sessionOpt = authService.authenticate("alice", "StrongMasterPass123!".toCharArray());
        assertTrue(sessionOpt.isPresent(), "Valid credentials must create an active session");

        UserSession session = sessionOpt.get();
        assertEquals("alice", session.getUsername());
        assertEquals(32, session.getEncryptionKey().length, "Derived encryption key must be 256 bits (32 bytes)");
        session.invalidate();
    }

    @Test
    @DisplayName("Domain separation isolates K_enc from stored auth_hash and invalidate() wipes K_enc")
    void testDomainSeparationAndSessionInvalidation() {
        assertTrue(authService.registerUser("alice", "StrongMasterPass123!".toCharArray()));

        User storedUser = userDao.getUserByUsername("alice").orElseThrow();
        UserSession session = authService.authenticate("alice", "StrongMasterPass123!".toCharArray()).orElseThrow();

        byte[] keyRef = session.getEncryptionKey();
        String derivedEncKeyHex = HexFormat.of().formatHex(keyRef).toLowerCase();
        String storedAuthHashHex = storedUser.getAuthHash().toLowerCase();

        assertNotEquals(storedAuthHashHex, derivedEncKeyHex,
                "Vault encryption key (K_enc) must differ from stored authentication hash");

        session.invalidate();
        for (byte b : keyRef) {
            assertEquals((byte) 0, b, "All bytes of K_enc must be zeroed after session.invalidate()");
        }
    }

    @Test
    @DisplayName("Fails closed for wrong password, unknown user, and empty inputs")
    void testFailedLoginAndUnknownUser() {
        assertTrue(authService.registerUser("alice", "StrongMasterPass123!".toCharArray()));

        assertTrue(authService.authenticate("", "StrongMasterPass123!".toCharArray()).isEmpty());
        assertTrue(authService.authenticate("alice", new char[0]).isEmpty());
        assertTrue(authService.authenticate("alice", "WrongMasterPass123!".toCharArray()).isEmpty(),
                "Wrong password must not create a session");
        assertTrue(authService.authenticate("nonexistent_user", "AnyPassword123!".toCharArray()).isEmpty(),
                "Unknown username must not create a session");
    }

    @Test
    @DisplayName("Locks login on 5th failed attempt and persists lockout across service restarts")
    void testPersistentBruteForceLockout() {
        assertTrue(authService.registerUser("alice", "CorrectMaster123!".toCharArray()));

        // Attempts 1 to 4 fail normally with Optional.empty()
        for (int i = 0; i < 4; i++) {
            Optional<UserSession> attempt = authService.authenticate("alice", "WrongPassword123!".toCharArray());
            assertTrue(attempt.isEmpty(), "Failed attempt " + (i + 1) + " must return empty session");
        }

        // 5th failed attempt triggers checkIfNowLocked() immediately
        assertThrows(IllegalStateException.class,
                () -> authService.authenticate("alice", "WrongPassword123!".toCharArray()),
                "5th failed attempt must immediately lock the account");

        // Subsequent attempt with the correct password is blocked by the top-level lockout check
        assertThrows(IllegalStateException.class,
                () -> authService.authenticate("alice", "CorrectMaster123!".toCharArray()),
                "Login must remain blocked even with the correct password");

        // Simulate application restart with a fresh AuthenticationService instance on the same SQLite DB
        AuthenticationService restartedAuthService = new AuthenticationService();
        assertThrows(IllegalStateException.class,
                () -> restartedAuthService.authenticate("alice", "CorrectMaster123!".toCharArray()),
                "Brute-force lockout must persist across application restarts");
    }
}
