package ee.taltech.passvault.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MemoryWiperTest {

    @Test
    @DisplayName("Wipe char array fills all elements with null characters ('\\0')")
    void testWipeCharArray() {
        char[] secretChars = "SecretPassword123!".toCharArray();

        MemoryWiper.wipe(secretChars);

        for (char c : secretChars) {
            assertEquals('\0', c, "Each character in the array must be zeroed out");
        }
    }

    @Test
    @DisplayName("Wipe byte array fills all elements with zeroes (0x00)")
    void testWipeByteArray() {
        byte[] secretBytes = new byte[]{0x12, 0x34, 0x56, 0x78, (byte) 0x9A};

        MemoryWiper.wipe(secretBytes);

        for (byte b : secretBytes) {
            assertEquals((byte) 0, b, "Each byte in the array must be zeroed out");
        }
    }

    @Test
    @DisplayName("Wipe handles null arrays gracefully without throwing NullPointerException")
    void testWipeNullArrays() {
        assertDoesNotThrow(() -> MemoryWiper.wipe((char[]) null));
        assertDoesNotThrow(() -> MemoryWiper.wipe((byte[]) null));
    }

    @Test
    @DisplayName("IsEqual correctly compares char arrays in constant time")
    void testIsEqualCharArray() {
        char[] a = "SamePassword".toCharArray();
        char[] b = "SamePassword".toCharArray();
        char[] c = "DiffPassword".toCharArray();
        char[] d = "Short".toCharArray();

        assertTrue(MemoryWiper.isEqual(a, b), "Identical char arrays must return true");
        assertFalse(MemoryWiper.isEqual(a, c), "Different char arrays must return false");
        assertFalse(MemoryWiper.isEqual(a, d), "Different length char arrays must return false");
        assertTrue(MemoryWiper.isEqual(null, null), "Two null references must return true");
        assertFalse(MemoryWiper.isEqual(a, null), "Comparing array to null must return false");
    }
}
