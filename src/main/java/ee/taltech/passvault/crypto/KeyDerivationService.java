package ee.taltech.passvault.crypto;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Service providing key derivation and password hashing using Argon2id via Bouncy Castle.
 */
public class KeyDerivationService {

    private static final Logger logger = LoggerFactory.getLogger(KeyDerivationService.class);

    // Recommended parameters for Argon2id in university/production environments
    private static final int ARGON2_ITERATIONS = 3;
    private static final int ARGON2_MEMORY_KB = 65536; // 64 MB
    private static final int ARGON2_PARALLELISM = 1;
    private static final int DERIVED_KEY_LENGTH_BYTES = 32; // 256 bits

    /**
     * Derives a 256-bit key from a master password and salt using Argon2id.
     *
     * @param password Master password as char array.
     * @param salt Cryptographic random salt.
     * @return Derived key bytes (256 bits).
     */
    public byte[] deriveKey(char[] password, byte[] salt) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password cannot be null or empty.");
        }
        if (salt == null || salt.length == 0) {
            throw new IllegalArgumentException("Salt cannot be null or empty.");
        }

        byte[] passwordBytes = charArrayToByteArray(password);

        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(ARGON2_ITERATIONS)
                .withMemoryAsKB(ARGON2_MEMORY_KB)
                .withParallelism(ARGON2_PARALLELISM)
                .withSalt(salt);

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(builder.build());

        byte[] derivedKey = new byte[DERIVED_KEY_LENGTH_BYTES];
        generator.generateBytes(passwordBytes, derivedKey, 0, derivedKey.length);

        // Wipe intermediate UTF-8 byte array immediately
        MemoryWiper.wipe(passwordBytes);

        return derivedKey;
    }

    /**
     * Converts a char array to UTF-8 byte array for cryptographic processing without using Immutable Strings.
     */
    private byte[] charArrayToByteArray(char[] chars) {
        ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
        byte[] bytes = new byte[byteBuffer.remaining()];
        byteBuffer.get(bytes);
        // Zero-fill internal ByteBuffer array if backed
        if (byteBuffer.hasArray()) {
            MemoryWiper.wipe(byteBuffer.array());
        }
        return bytes;
    }
}
