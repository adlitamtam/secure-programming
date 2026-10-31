package ee.taltech.passvault;

import ee.taltech.passvault.storage.DatabaseManager;
import ee.taltech.passvault.ui.CommandLineInterface;

public class Main {

    public static void main(String[] args) {
        if (!DatabaseManager.getInstance().initializeAndValidate()) {
            System.err.println("Fatal: PassVault cannot start due to database initialization failure.");
            System.exit(1);
        }

        CommandLineInterface cli = new CommandLineInterface();
        cli.start();
    }
}
