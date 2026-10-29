package ee.taltech.passvault.security;

import java.util.regex.Pattern;

/**
 * Central input validation service enforcing strict security boundaries,
 * character whitelists, and buffer limit checks to mitigate DoS and injection attacks.
 */
public class InputValidator {

    // Maximum field length constraints to prevent Memory Exhaustion (Heap Overflows)
    public static final int MAX_USERNAME_LENGTH = 64;
    public static final int MIN_PASSWORD_LENGTH = 8;
    public static final int MAX_PASSWORD_LENGTH = 128;
    public static final int MAX_SERVICE_LENGTH = 128;
    public static final int MAX_ACCOUNT_USERNAME_LENGTH = 128;

    // Strict Whitelisted Character Patterns
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_.-]+$");
    private static final Pattern SERVICE_PATTERN = Pattern.compile("^[a-zA-Z0-9_.:/@-]+$");

    private InputValidator() {
        // Utility class
    }

    /**
     * Validates a username against length constraints and allowed character set.
     */
    public static void validateUsername(String username) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Username cannot be empty.");
        }
        if (username.length() > MAX_USERNAME_LENGTH) {
            throw new IllegalArgumentException("Username exceeds maximum length of " + MAX_USERNAME_LENGTH + " characters.");
        }
        if (!USERNAME_PATTERN.matcher(username).matches()) {
            throw new IllegalArgumentException("Username contains invalid characters.");
        }
    }

    /**
     * Validates master password length boundaries.
     */
    public static void validateMasterPassword(char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Master password cannot be empty.");
        }
        if (password.length < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Master password must be at least " + MIN_PASSWORD_LENGTH + " characters long.");
        }
        if (password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Master password exceeds maximum length of " + MAX_PASSWORD_LENGTH + " characters.");
        }
    }

    /**
     * Validates a service/domain name.
     */
    public static void validateService(String service) {
        if (service == null || service.isBlank()) {
            throw new IllegalArgumentException("Service name cannot be empty.");
        }
        if (service.length() > MAX_SERVICE_LENGTH) {
            throw new IllegalArgumentException("Service name exceeds maximum length of " + MAX_SERVICE_LENGTH + " characters.");
        }
        if (!SERVICE_PATTERN.matcher(service).matches()) {
            throw new IllegalArgumentException("Service name contains invalid characters.");
        }
    }

    /**
     * Validates account username/email.
     */
    public static void validateAccountUsername(String accountUsername) {
        if (accountUsername == null || accountUsername.isBlank()) {
            throw new IllegalArgumentException("Account username cannot be empty.");
        }
        if (accountUsername.length() > MAX_ACCOUNT_USERNAME_LENGTH) {
            throw new IllegalArgumentException("Account username exceeds maximum length of " + MAX_ACCOUNT_USERNAME_LENGTH + " characters.");
        }
        // Basic control-character check to prevent newline injection
        if (accountUsername.contains("\n") || accountUsername.contains("\r") || accountUsername.contains("\0")) {
            throw new IllegalArgumentException("Account username contains illegal control characters.");
        }
    }

    /**
     * Validates integer IDs to prevent negative or zero index logic bypass.
     */
    public static void validateUserId(int userId) {
        if (userId <= 0) {
            throw new IllegalArgumentException("Invalid user ID. Must be a positive integer.");
        }
    }
}
