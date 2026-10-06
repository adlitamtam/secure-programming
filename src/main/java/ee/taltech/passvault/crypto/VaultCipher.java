package ee.taltech.passvault.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Handles authenticated symmetric encryption and decryption using AES-256-GCM.
 */
public class VaultCipher {

    private static final Logger logger = LoggerFactory.getLogger(VaultCipher.class);

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128;

    /**
     * Encrypts a plaintext password char array using AES-256-GCM.
     *
     * @param plaintextPassword Password to encrypt (char[]).
     * @param key 256-bit encryption key (K_enc).
     * @param nonce 12-byte initialization vector.
     * @return Encrypted ciphertext bytes including GCM authentication tag.
     */
    public byte[] encrypt(char[] plaintextPassword, byte[] key, byte[] nonce) {
        if (plaintextPassword == null || key == null || nonce == null) {
            throw new IllegalArgumentException("Inputs to encryption cannot be null.");
        }

        byte[] plainBytes = charArrayToByteArray(plaintextPassword);

        try {
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

            return cipher.doFinal(plainBytes);

        } catch (Exception e) {
            logger.error("AES-GCM encryption failed: {}", e.getMessage());
            throw new RuntimeException("Encryption operation failed.", e);
        } finally {
            MemoryWiper.wipe(plainBytes);
        }
    }

    /**
     * Decrypts an AES-256-GCM ciphertext back into a plaintext password char array.
     *
     * @param ciphertext Encrypted bytes.
     * @param key 256-bit encryption key (K_enc).
     * @param nonce 12-byte initialization vector.
     * @return Decrypted password as char array.
     */
    public char[] decrypt(byte[] ciphertext, byte[] key, byte[] nonce) {
        if (ciphertext == null || key == null || nonce == null) {
            throw new IllegalArgumentException("Inputs to decryption cannot be null.");
        }

        byte[] decryptedBytes = null;
        try {
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

            decryptedBytes = cipher.doFinal(ciphertext);
            return byteArrayToCharArray(decryptedBytes);

        } catch (Exception e) {
            logger.error("AES-GCM decryption failed (tampering or wrong key): {}", e.getMessage());
            throw new SecurityException("Decryption failed. Invalid key or corrupted data.", e);
        } finally {
            MemoryWiper.wipe(decryptedBytes);
        }
    }

    private byte[] charArrayToByteArray(char[] chars) {
        ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
        byte[] bytes = new byte[byteBuffer.remaining()];
        byteBuffer.get(bytes);
        if (byteBuffer.hasArray()) {
            MemoryWiper.wipe(byteBuffer.array());
        }
        return bytes;
    }

    private char[] byteArrayToCharArray(byte[] bytes) {
        CharBuffer charBuffer = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(bytes));
        char[] chars = new char[charBuffer.remaining()];
        charBuffer.get(chars);
        if (charBuffer.hasArray()) {
            MemoryWiper.wipe(charBuffer.array());
        }
        return chars;
    }
}
