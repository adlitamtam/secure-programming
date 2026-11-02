package ee.taltech.passvault.ui;

import ee.taltech.passvault.crypto.MemoryWiper;

import java.io.Console;
import java.util.Arrays;
import java.util.Scanner;

/**
 * Securely reads user inputs from the system console.
 * Enforces masked inputs for sensitive fields using char arrays.
 */
public class ConsoleReader {

    private final Console console;
    private final Scanner fallbackScanner;

    public ConsoleReader() {
        this.console = System.console();
        this.fallbackScanner = (console == null) ? new Scanner(System.in) : null;
    }

    /**
     * Checks if a secure, interactive TTY console is available.
     *
     * @return true if System.console() is accessible.
     */
    public boolean isConsoleAvailable() {
        return console != null || fallbackScanner != null;
    }

    public String readLine(String prompt) {
        System.out.print(prompt);
        String input = null;
        if (console != null) {
            input = console.readLine();
        } else if (fallbackScanner != null && fallbackScanner.hasNextLine()) {
            input = fallbackScanner.nextLine();
        }
        if (input == null) {
            return null;
        }
        return input.replace("\r", "");
    }

    public char[] readPassword(String prompt) {
        System.out.print(prompt);
        if (console != null) {
            char[] pwd = console.readPassword();
            return (pwd != null) ? pwd : new char[0];
        } else {
            if (fallbackScanner != null && fallbackScanner.hasNextLine()) {
                String line = fallbackScanner.nextLine().replace("\r", "");
                return line.toCharArray();
            }
            return new char[0];
        }
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
        char[] pwd1 = readPassword(prompt);
        char[] pwd2 = readPassword(confirmPrompt);

        if (!Arrays.equals(pwd1, pwd2)) {
            MemoryWiper.wipe(pwd1);
            MemoryWiper.wipe(pwd2);
            throw new IllegalArgumentException("Passwords do not match.");
        }

        MemoryWiper.wipe(pwd2);
        return pwd1;
    }
}
