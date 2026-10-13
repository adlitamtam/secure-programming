package ee.taltech.passvault.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KeyDerivationServiceTest {

    private KeyDerivationService keyDerivationService;

    @BeforeEach
    void setUp() {
        keyDerivationService = new KeyDerivationService();
    }

    @Test
    @DisplayName("DeriveKey produces exact 32-byte (256-bit) key")
    void testDeriveKeyLength() {
        char[] password = "MasterPassword123!".toCharArray();
        byte[] salt = SecureRandomUtils.generateSalt();

        byte[] derivedKey = keyDerivationService.deriveKey(password, salt);

        assertNotNull(derivedKey);
        assertEquals(32, derivedKey.length, "Derived key must be exactly 256 bits (32 bytes)");
    }

    @Test
    @DisplayName("DeriveKey is deterministic for identical password and salt")
    void testDeterministicDerivation() {
        char[] password = "SamePassword123!".toCharArray();
        byte[] salt = SecureRandomUtils.generateSalt();

        byte[] key1 = keyDerivationService.deriveKey(password, salt);
        byte[] key2 = keyDerivationService.deriveKey(password, salt);

        assertArrayEquals(key1, key2, "Derived keys must be identical for same password and salt");
    }

    @Test
    @DisplayName("Different salts produce completely different derived keys")
    void testDifferentSaltsProduceDifferentKeys() {
        char[] password = "SamePassword123!".toCharArray();
        byte[] salt1 = SecureRandomUtils.generateSalt();
        byte[] salt2 = SecureRandomUtils.generateSalt();

        byte[] key1 = keyDerivationService.deriveKey(password, salt1);
        byte[] key2 = keyDerivationService.deriveKey(password, salt2);

        assertFalse(MemoryWiper.isEqual(
                new String(key1).toCharArray(),
                new String(key2).toCharArray()
        ), "Keys derived with different salts must not match");
    }

    @Test
    @DisplayName("DeriveKey throws IllegalArgumentException on null or empty password/salt")
    void testInvalidInputs() {
        byte[] validSalt = SecureRandomUtils.generateSalt();
        char[] validPassword = "Password123!".toCharArray();

        assertThrows(IllegalArgumentException.class, () -> keyDerivationService.deriveKey(null, validSalt));
        assertThrows(IllegalArgumentException.class, () -> keyDerivationService.deriveKey(new char[0], validSalt));
        assertThrows(IllegalArgumentException.class, () -> keyDerivationService.deriveKey(validPassword, null));
        assertThrows(IllegalArgumentException.class, () -> keyDerivationService.deriveKey(validPassword, new byte[0]));
    }
}
