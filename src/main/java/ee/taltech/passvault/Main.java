package ee.taltech.passvault;

import ee.taltech.passvault.storage.DatabaseManager;
import ee.taltech.passvault.ui.CommandLineInterface;

public class Main {
    public static void main(String[] args) {
        // Initialize SQLite database and tables
        DatabaseManager.getInstance();

        // Launch interactive CLI
        CommandLineInterface cli = new CommandLineInterface();
        cli.start();
    }
}
