package ee.taltech.passvault;

import ee.taltech.passvault.security.TamperEvidentFileAppender;
import ee.taltech.passvault.storage.DatabaseManager;
import ee.taltech.passvault.ui.CommandLineInterface;

public class Main {

    public static void main(String[] args) {
        if (!TamperEvidentFileAppender.verifyLogIntegrity("passvault.log")) {
            System.err.println("[SECURITY WARNING] Tampering or unauthorized modification detected in passvault.log!");
        }

        if (!DatabaseManager.getInstance().initializeAndValidate()) {
            System.err.println("Fatal: PassVault cannot start due to database initialization failure.");
            System.exit(1);
        }

        CommandLineInterface cli = new CommandLineInterface();
        cli.start();
    }
}
