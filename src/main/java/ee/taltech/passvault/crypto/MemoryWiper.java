package ee.taltech.passvault.crypto;

import java.util.Arrays;

/**
 * Utility class to securely zero-out sensitive byte and char arrays in memory,
 * and provide constant-time array comparisons to prevent timing attacks.
 */
public class MemoryWiper {

    private MemoryWiper() {
        // Utility class
    }

    /**
     * Overwrites a character array with null characters ('\0').
     */
    public static void wipe(char[] buffer) {
        if (buffer != null) {
            Arrays.fill(buffer, '\0');
        }
    }

    /**
     * Overwrites a byte array with zeroes (0x00).
     */
    public static void wipe(byte[] buffer) {
        if (buffer != null) {
            Arrays.fill(buffer, (byte) 0);
        }
    }

    /**
     * Constant-time comparison of two char arrays to mitigate timing attacks.
     */
    public static boolean isEqual(char[] a, char[] b) {
        if (a == null || b == null) {
            return a == b;
        }
        if (a.length != b.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}
