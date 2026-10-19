package ee.taltech.passvault.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class VaultCipherTest {

    private VaultCipher cipher;
    private byte[] secretKey;
    private byte[] nonce;

    @BeforeEach
    void setUp() {
        cipher = new VaultCipher();
        // 256-bit dummy encryption key & 12-byte nonce
        secretKey = new byte[32];
        for (int i = 0; i < secretKey.length; i++) {
            secretKey[i] = (byte) (i + 1);
        }
        nonce = SecureRandomUtils.generateNonce();
    }

    @Test
    @DisplayName("Encrypt and decrypt restores original plaintext password")
    void testEncryptDecryptSuccess() {
        char[] originalPassword = "MySecretAccountPassword2026!".toCharArray();

        byte[] ciphertext = cipher.encrypt(originalPassword, secretKey, nonce);
        assertNotNull(ciphertext);
        assertTrue(ciphertext.length > 0);

        char[] decryptedPassword = cipher.decrypt(ciphertext, secretKey, nonce);

        assertNotNull(decryptedPassword);
        assertTrue(MemoryWiper.isEqual(originalPassword, decryptedPassword),
                "Decrypted password must match original plaintext");
    }

    @Test
    @DisplayName("Decryption fails with SecurityException when ciphertext is tampered with (GCM Tag Check)")
    void testTamperedCiphertextFails() {
        char[] originalPassword = "MySecretAccountPassword2026!".toCharArray();

        byte[] ciphertext = cipher.encrypt(originalPassword, secretKey, nonce);

        // Tamper with the last byte (part of GCM tag or ciphertext)
        ciphertext[ciphertext.length - 1] ^= 0x01;

        assertThrows(SecurityException.class, () -> cipher.decrypt(ciphertext, secretKey, nonce),
                "AES-GCM decryption must fail if ciphertext is manipulated");
    }

    @Test
    @DisplayName("Decryption fails with wrong encryption key")
    void testWrongKeyFails() {
        char[] originalPassword = "MySecretAccountPassword2026!".toCharArray();
        byte[] wrongKey = secretKey.clone();
        wrongKey[0] ^= 0xFF; // Modify key

        byte[] ciphertext = cipher.encrypt(originalPassword, secretKey, nonce);

        assertThrows(SecurityException.class, () -> cipher.decrypt(ciphertext, wrongKey, nonce),
                "AES-GCM decryption must fail when provided with incorrect key");
    }

    @Test
    @DisplayName("Encrypt/Decrypt throws IllegalArgumentException on null inputs")
    void testNullInputs() {
        char[] password = "Password123!".toCharArray();

        assertThrows(IllegalArgumentException.class, () -> cipher.encrypt(null, secretKey, nonce));
        assertThrows(IllegalArgumentException.class, () -> cipher.encrypt(password, null, nonce));
        assertThrows(IllegalArgumentException.class, () -> cipher.encrypt(password, secretKey, null));

        assertThrows(IllegalArgumentException.class, () -> cipher.decrypt(null, secretKey, nonce));
        assertThrows(IllegalArgumentException.class, () -> cipher.decrypt(new byte[10], null, nonce));
        assertThrows(IllegalArgumentException.class, () -> cipher.decrypt(new byte[10], secretKey, null));
    }
}
