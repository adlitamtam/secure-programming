package ee.taltech.passvault.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InputValidationTest {

    @Test
    @DisplayName("Valid usernames pass validation")
    void testValidUsernames() {
        assertDoesNotThrow(() -> InputValidator.validateUsername("alice_123"));
        assertDoesNotThrow(() -> InputValidator.validateUsername("user.name-test"));
    }

    @Test
    @DisplayName("Overly long usernames trigger Heap Overflow protection")
    void testTooLongUsername() {
        String longUsername = "a".repeat(InputValidator.MAX_USERNAME_LENGTH + 1);
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateUsername(longUsername));
    }

    @Test
    @DisplayName("Usernames containing invalid characters or control characters are rejected")
    void testInvalidUsernameCharacters() {
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateUsername("alice; DROP TABLE users;--"));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateUsername("user\nname"));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateUsername("user name"));
    }

    @Test
    @DisplayName("Password length boundaries are enforced correctly")
    void testPasswordBoundaries() {
        char[] shortPass = "123457".toCharArray(); // 7 chars
        char[] longPass = "a".repeat(InputValidator.MAX_PASSWORD_LENGTH + 1).toCharArray();

        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateMasterPassword(shortPass));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateMasterPassword(longPass));
    }

    @Test
    @DisplayName("Invalid or non-positive User IDs are rejected (Integer Range Check)")
    void testUserIdValidation() {
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateUserId(0));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateUserId(-1));
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateUserId(Integer.MIN_VALUE));
        assertDoesNotThrow(() -> InputValidator.validateUserId(1));
    }

    @Test
    @DisplayName("LogSanitizer replaces newlines and control characters to prevent Log Injection")
    void testLogSanitizer() {
        String maliciousInput = "alice\n[INFO] Admin logged in\r\t";
        String sanitized = LogSanitizer.sanitize(maliciousInput);

        assertFalse(sanitized.contains("\n"));
        assertFalse(sanitized.contains("\r"));
        assertEquals("alice_[INFO] Admin logged in__", sanitized);
    }
}
