package ee.taltech.passvault.ui;

import ee.taltech.passvault.auth.AuthenticationService;
import ee.taltech.passvault.auth.UserSession;
import ee.taltech.passvault.crypto.MemoryWiper;
import ee.taltech.passvault.security.InputValidator;
import ee.taltech.passvault.storage.VaultService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class CommandLineInterface {

    private static final Logger logger = LoggerFactory.getLogger(CommandLineInterface.class);

    private final ConsoleReader consoleReader;
    private final ClipboardService clipboardService;
    private final AuthenticationService authService;
    private final VaultService vaultService;

    private boolean isLoggedIn = false;
    private String activeUser = null;
    private UserSession activeSession = null;

    public CommandLineInterface() {
        this.consoleReader = new ConsoleReader();
        this.clipboardService = new ClipboardService();
        this.authService = new AuthenticationService();
        this.vaultService = new VaultService();
    }

    public void start() {
        if (!consoleReader.isConsoleAvailable()) {
            System.err.println("Error: Neither interactive console nor stdin available.");
            return;
        }
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (activeSession != null) {
                activeSession.invalidate();
                logger.info("Shutdown hook executed: Active session memory wiped.");
            }
        }));
        printHeader();
        boolean running = true;
        while (running) {
            try {
                if (!isLoggedIn) {
                    running = showMainMenu();
                } else {
                    showVaultMenu();
                }
            } catch (Exception e) {
                System.out.println("An unexpected error occurred: " + e.getMessage());
                logger.error("Unhandled top-level error in CLI loop", e);
            }
        }
        shutdown();
    }

    private void printHeader() {
        System.out.println("==================================================");
        System.out.println("                    PassVault                     ");
        System.out.println("==================================================");
    }

    private boolean showMainMenu() {
        System.out.println("\n--- MAIN MENU ---");
        System.out.println("1. Login");
        System.out.println("2. Register");
        System.out.println("3. Exit");
        String choice = consoleReader.readLine("> Choice: ");

        if (choice == null) {
            System.out.println("\nSession terminated by user. Goodbye!");
            return false;
        }

        switch (choice.trim()) {
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

    private void handleRegister() {
        if (!verifyDatabaseHealth()) return;
        System.out.println("\n--- User Registration ---");
        String username = consoleReader.readLine("Enter new username: ");
        char[] masterPassword = null;

        try {
            InputValidator.validateUsername(username);

            masterPassword = consoleReader.readAndConfirmPassword(
                    "Enter Master Password: ",
                    "Confirm Master Password: "
            );

            InputValidator.validateMasterPassword(masterPassword);

            boolean success = authService.registerUser(username, masterPassword);
            if (success) {
                System.out.println("SUCCESS: User '" + username + "' successfully registered!");
            } else {
                System.out.println("Error: Username '" + username + "' is already taken.");
            }

        } catch (IllegalArgumentException e) {
            System.out.println("Error: Registration failed due to an internal system error.");
            logger.error("Unexpected error during registration", e);
        } finally {
            MemoryWiper.wipe(masterPassword);
        }
    }

    private void handleLogin() {
        if (!verifyDatabaseHealth()) return;
        System.out.println("\n--- Vault Login ---");
        String username = consoleReader.readLine("Username: ");
        char[] masterPassword = consoleReader.readPassword("Master Password: ");

        try {
            InputValidator.validateUsername(username);

            var sessionOpt = authService.authenticate(username, masterPassword);
            if (sessionOpt.isPresent()) {
                this.activeSession = sessionOpt.get();
                this.isLoggedIn = true;
                this.activeUser = activeSession.getUsername();
                System.out.println("SUCCESS: Vault unlocked for user '" + activeUser + "'.");
            } else {
                System.out.println("Authentication failed: Invalid username or master password.");
            }
        } catch (IllegalArgumentException e) {
            System.out.println("Authentication failed: Invalid input format.");
        } finally {
            MemoryWiper.wipe(masterPassword);
        }
    }

    private void showVaultMenu() {
        System.out.println("\n[" + activeUser + "@vault] Enter command ('help' for options):");
        String input = consoleReader.readLine("> ");

        if (input == null) {
            System.out.println("\nSession terminated by user. Locking vault...");
            handleLogout();
            return;
        }

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
        System.out.println("  get <service>        - Display username and copy password to clipboard");
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
        if (!verifyDatabaseHealth()) return;
        if (service.isBlank()) {
            service = consoleReader.readLine("Enter service/domain name (e.g. github.com): ");
        }

        String accountUsername = consoleReader.readLine("Enter account username/email: ");
        char[] password = consoleReader.readPassword("Enter password for " + service + ": ");

        try {
            InputValidator.validateService(service);
            InputValidator.validateAccountUsername(accountUsername);

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
        } catch (IllegalArgumentException e) {
            System.out.println("Validation Error: " + e.getMessage());
        } finally {
            MemoryWiper.wipe(password);
        }
    }

    private void handleGetCredential(String service) {
        if (!verifyDatabaseHealth()) return;
        if (service.isBlank()) {
            service = consoleReader.readLine("Enter service name to retrieve: ");
        }

        try {
            InputValidator.validateService(service);

            var credOpt = vaultService.getCredential(activeSession, service);
            if (credOpt.isPresent()) {
                var credential = credOpt.get();
                char[] decryptedPassword = credential.password();

                try {
                    System.out.println("\nCredential found for '" + service + "':");
                    System.out.println("Username: " + credential.accountUsername());
                    System.out.println("Password: [COPIED TO CLIPBOARD]");

                    clipboardService.copyToClipboard(decryptedPassword, 30);
                    System.out.println("Notice: Clipboard will automatically be cleared in 30 seconds.");
                } finally {
                    MemoryWiper.wipe(decryptedPassword);
                }
            } else {
                System.out.println("Error: No entry found for service '" + service + "'.");
            }
        } catch (IllegalArgumentException e) {
            System.out.println("Validation Error: " + e.getMessage());
        }
    }

    private void handleDeleteCredential(String service) {
        if (!verifyDatabaseHealth()) return;
        if (service.isBlank()) {
            service = consoleReader.readLine("Enter service name to delete: ");
        }

        try {
            InputValidator.validateService(service);

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
        } catch (IllegalArgumentException e) {
            System.out.println("Validation Error: " + e.getMessage());
        }
    }

    private void handleLogout() {
        if (activeSession != null) {
            activeSession.invalidate();
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

    private boolean verifyDatabaseHealth() {
        if (!ee.taltech.passvault.storage.DatabaseManager.getInstance().isDatabaseAlive()) {
            System.out.println("\n[ERROR] Database file is missing or corrupted!");
            System.out.println("Emergency action: Re-initializing schema. Active session will be locked.");
            handleLogout();
            ee.taltech.passvault.storage.DatabaseManager.getInstance().initializeAndValidate();
            return false;
        }
        return true;
    }
}
