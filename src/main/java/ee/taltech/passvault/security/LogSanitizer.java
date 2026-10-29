package ee.taltech.passvault.security;

/**
 * Utility to sanitize user-provided inputs before logging to prevent Log Injection / Log Forging.
 */
public class LogSanitizer {

    private LogSanitizer() {
        // Utility class
    }

    /**
     * Sanitizes a string by replacing newline characters and non-printable control characters.
     *
     * @param input Raw string to sanitize.
     * @return Safe string for logging.
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "[null]";
        }
        // Replace CR, LF and control characters with underscores
        return input.replaceAll("[\\r\\n\\t]", "_")
                .replaceAll("[^\\x20-\\x7E]", "?");
    }
}
