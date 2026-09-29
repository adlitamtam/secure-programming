package ee.taltech.passvault.ui;

import ee.taltech.passvault.crypto.MemoryWiper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Console;

/**
 * Securely reads user inputs from the system console.
 * Enforces masked inputs for sensitive fields using char arrays.
 */
public class ConsoleReader {

    private static final Logger logger = LoggerFactory.getLogger(ConsoleReader.class);
    private final Console console;

    public ConsoleReader() {
        this.console = System.console();
        if (this.console == null) {
            logger.warn("No interactive console available. The application must be run from a standard terminal.");
        }
    }

    /**
     * Checks if a secure, interactive TTY console is available.
     *
     * @return true if System.console() is accessible.
     */
    public boolean isConsoleAvailable() {
        return this.console != null;
    }

    /**
     * Securely reads a password or secret input from the console without terminal echo.
     *
     * @param prompt User-facing prompt message.
     * @return char array containing the entered password.
     * @throws IllegalStateException if running in a non-interactive environment.
     */
    public char[] readPassword(String prompt) {
        if (!isConsoleAvailable()) {
            logger.error("Attempted to read password without an attached TTY console.");
            throw new IllegalStateException("Interactive TTY console required for secure password input.");
        }

        char[] password = console.readPassword("%s", prompt);

        if (password == null) {
            logger.warn("User terminated console input (EOF/Ctrl+D).");
            return new char[0];
        }

        return password;
    }

    /**
     * Reads a double-entered password and verifies that both matches.
     * Wipes intermediate buffers immediately if confirmation fails.
     *
     * @param prompt Prompt for initial password.
     * @param confirmPrompt Prompt for confirmation password.
     * @return Verified password as char array.
     * @throws IllegalArgumentException if passwords do not match.
     */
    public char[] readAndConfirmPassword(String prompt, String confirmPrompt) {
        char[] pass1 = readPassword(prompt);
        char[] pass2 = readPassword(confirmPrompt);

        if (!MemoryWiper.isEqual(pass1, pass2)) {
            MemoryWiper.wipe(pass1);
            MemoryWiper.wipe(pass2);
            throw new IllegalArgumentException("Passwords do not match. Please try again.");
        }

        // Wipe the confirmation copy immediately; return pass1
        MemoryWiper.wipe(pass2);
        return pass1;
    }

    /**
     * Reads a non-sensitive text line (e.g., username, service name) from the console.
     *
     * @param prompt User-facing prompt message.
     * @return Trimmed String input.
     */
    public String readLine(String prompt) {
        if (!isConsoleAvailable()) {
            logger.error("Attempted to read input line without an attached TTY console.");
            throw new IllegalStateException("Interactive TTY console required.");
        }

        String input = console.readLine("%s", prompt);
        return (input != null) ? input.trim() : "";
    }
}
