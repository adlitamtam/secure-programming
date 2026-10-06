package ee.taltech.passvault.ui;

import ee.taltech.passvault.auth.AuthenticationService;
import ee.taltech.passvault.auth.UserSession;
import ee.taltech.passvault.crypto.MemoryWiper;
import ee.taltech.passvault.storage.VaultService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Interactive Command Line Interface for PassVault.
 * Handles menu navigation, user interaction, and delegates actions to services.
 */
public class CommandLineInterface {

    private static final Logger logger = LoggerFactory.getLogger(CommandLineInterface.class);

    private final ConsoleReader consoleReader;
    private final ClipboardService clipboardService;

    private boolean isLoggedIn = false;
    private String activeUser = null;

    private final AuthenticationService authService;
    private UserSession activeSession = null;
    private final VaultService vaultService;

    public CommandLineInterface() {
        this.consoleReader = new ConsoleReader();
        this.clipboardService = new ClipboardService();
        this.authService = new AuthenticationService();
        this.vaultService = new VaultService();
    }

    /**
     * Entry point to launch the interactive CLI loop.
     */
    public void start() {
        if (!consoleReader.isConsoleAvailable()) {
            System.err.println("Error: No interactive terminal session found.");
            System.err.println("Please run this application directly from a command line / terminal.");
            logger.error("Application execution aborted: No System.console() available.");
            return;
        }

        printHeader();

        boolean running = true;
        while (running) {
            if (!isLoggedIn) {
                running = showMainMenu();
            } else {
                showVaultMenu();
            }
        }

        shutdown();
    }

    private void printHeader() {
        System.out.println("==================================================");
        System.out.println("                    PassVault                     ");
        System.out.println("==================================================");
    }

    /**
     * Displays the unauthenticated main menu.
     *
     * @return false if the user chooses to exit, true otherwise.
     */
    private boolean showMainMenu() {
        System.out.println("\n--- MAIN MENU ---");
        System.out.println("1. Login");
        System.out.println("2. Register");
        System.out.println("3. Exit");

        String choice = consoleReader.readLine("> Choice: ");

        switch (choice) {
            case "1":
                handleLogin();
                break;
            case "2":
                handleRegister();
                break;
            case "3":
                System.out.println("Exiting PassVault. Goodbye!");
                return false;
            default:
                System.out.println("Invalid option. Please enter 1, 2, or 3.");
        }
        return true;
    }

    /**
     * Handles user registration workflow.
     */
    private void handleRegister() {
        System.out.println("\n--- User Registration ---");
        String username = consoleReader.readLine("Enter new username: ");

        if (username.isBlank()) {
            System.out.println("Username cannot be empty.");
            return;
        }

        char[] masterPassword = null;
        try {
            masterPassword = consoleReader.readAndConfirmPassword(
                    "Enter Master Password: ",
                    "Confirm Master Password: "
            );

            if (masterPassword.length < 8) {
                System.out.println("Registration failed: Password must be at least 8 characters long.");
                return;
            }

            boolean success = authService.registerUser(username, masterPassword);
            if (success) {
                System.out.println("SUCCESS: User '" + username + "' successfully registered!");
            } else {
                System.out.println("Error: Username '" + username + "' is already taken.");
            }

        } catch (IllegalArgumentException e) {
            System.out.println("Error: " + e.getMessage());
        } finally {
            MemoryWiper.wipe(masterPassword);
        }
    }

    /**
     * Handles user login workflow.
     */
    private void handleLogin() {
        System.out.println("\n--- Vault Login ---");
        String username = consoleReader.readLine("Username: ");

        if (username.isBlank()) {
            System.out.println("Username cannot be empty.");
            return;
        }

        char[] masterPassword = consoleReader.readPassword("Master Password: ");

        try {
            var sessionOpt = authService.authenticate(username, masterPassword);
            if (sessionOpt.isPresent()) {
                this.activeSession = sessionOpt.get();
                this.isLoggedIn = true;
                this.activeUser = activeSession.getUsername();
                System.out.println("SUCCESS: Vault unlocked for user '" + activeUser + "'.");
            } else {
                System.out.println("Authentication failed: Invalid username or master password.");
            }
        } finally {
            MemoryWiper.wipe(masterPassword);
        }
    }

    /**
     * Displays the authenticated vault command menu loop.
     */
    private void showVaultMenu() {
        System.out.println("\n[" + activeUser + "@vault] Enter command ('help' for options):");
        String input = consoleReader.readLine("> ");

        String[] tokens = input.split("\\s+", 2);
        String command = tokens[0].toLowerCase();
        String argument = (tokens.length > 1) ? tokens[1].trim() : "";

        switch (command) {
            case "help":
                printVaultHelp();
                break;
            case "list":
                handleListItems();
                break;
            case "add":
                handleAddCredential(argument);
                break;
            case "get":
                handleGetCredential(argument);
                break;
            case "delete":
                handleDeleteCredential(argument);
                break;
            case "lock":
            case "logout":
                handleLogout();
                break;
            default:
                System.out.println("Unknown command: '" + command + "'. Type 'help' to see available commands.");
        }
    }

    private void printVaultHelp() {
        System.out.println("\nAvailable Commands:");
        System.out.println("  list                 - List all stored service names");
        System.out.println("  add <service>        - Store a new credential (e.g., add github.com)");
        System.out.println("  get <service>        - Copy password for a service to clipboard");
        System.out.println("  delete <service>     - Delete a stored credential");
        System.out.println("  lock / logout        - Lock the vault and return to main menu");
        System.out.println("  help                 - Show this help message");
    }

    private void handleListItems() {
        List<String> services = vaultService.listServices(activeSession);
        System.out.println("\nStored Services for '" + activeUser + "':");
        if (services.isEmpty()) {
            System.out.println(" (No entries found in vault)");
        } else {
            for (String s : services) {
                System.out.println(" - " + s);
            }
        }
    }

    private void handleAddCredential(String service) {
        if (service.isBlank()) {
            service = consoleReader.readLine("Enter service/domain name (e.g. github.com): ");
        }
        if (service.isBlank()) {
            System.out.println("Error: Service name cannot be empty.");
            return;
        }

        String accountUsername = consoleReader.readLine("Enter account username/email: ");
        char[] password = consoleReader.readPassword("Enter password for " + service + ": ");

        try {
            if (password.length == 0) {
                System.out.println("Error: Password cannot be empty.");
                return;
            }

            boolean success = vaultService.addEntry(activeSession, service, accountUsername, password);
            if (success) {
                System.out.println("SUCCESS: Credential for '" + service + "' encrypted and stored!");
            } else {
                System.out.println("Error: Could not store credential.");
            }
        } finally {
            MemoryWiper.wipe(password);
        }
    }

    private void handleGetCredential(String service) {
        if (service.isBlank()) {
            service = consoleReader.readLine("Enter service name to retrieve: ");
        }
        if (service.isBlank()) {
            System.out.println("Error: Service name cannot be empty.");
            return;
        }

        var passwordOpt = vaultService.getDecryptedPassword(activeSession, service);
        if (passwordOpt.isPresent()) {
            char[] decryptedPassword = passwordOpt.get();
            try {
                clipboardService.copyToClipboard(decryptedPassword, 30);
                System.out.println("SUCCESS: Password for '" + service + "' copied to system clipboard.");
                System.out.println("Notice: Clipboard will automatically be cleared in 30 seconds.");
            } finally {
                MemoryWiper.wipe(decryptedPassword);
            }
        } else {
            System.out.println("Error: No entry found for service '" + service + "'.");
        }
    }

    private void handleDeleteCredential(String service) {
        if (service.isBlank()) {
            service = consoleReader.readLine("Enter service name to delete: ");
        }
        if (service.isBlank()) {
            System.out.println("Error: Service name cannot be empty.");
            return;
        }

        String confirm = consoleReader.readLine("Are you sure you want to delete '" + service + "'? (y/N): ");
        if (confirm.equalsIgnoreCase("y")) {
            boolean success = vaultService.deleteEntry(activeSession, service);
            if (success) {
                System.out.println("SUCCESS: Entry for '" + service + "' removed from vault.");
            } else {
                System.out.println("Error: Could not delete entry (item not found).");
            }
        } else {
            System.out.println("Deletion canceled.");
        }
    }

    private void handleLogout() {
        if (activeSession != null) {
            activeSession.invalidate(); // Clear K_enc from RAM!
            activeSession = null;
        }
        System.out.println("Vault locked. Active session and encryption keys cleared from memory.");
        this.isLoggedIn = false;
        this.activeUser = null;
    }

    private void shutdown() {
        clipboardService.shutdown();
        logger.info("Application shut down cleanly.");
    }
}

