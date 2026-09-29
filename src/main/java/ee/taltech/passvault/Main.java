package ee.taltech.passvault;

import ee.taltech.passvault.storage.DatabaseManager;

public class Main {
    public static void main(String[] args) {
        System.out.println("Starting PassVault...");
        DatabaseManager.getInstance();
        System.out.println("PassVault initialized successfully.");
    }
}
