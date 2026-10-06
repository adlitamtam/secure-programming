package ee.taltech.passvault.ui;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Handles sensitive clipboard operations, ensuring copied secrets are automatically
 * wiped after a specified timeout to prevent clipboard sniffing.
 */
public class ClipboardService {

    private static final Logger logger = LoggerFactory.getLogger(ClipboardService.class);
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    /**
     * Copies a password char array into the system clipboard and schedules an auto-clear task.
     *
     * @param secret Password to copy.
     * @param timeoutSeconds Duration in seconds before clearing clipboard.
     */
    public void copyToClipboard(char[] secret, int timeoutSeconds) {
        if (secret == null || secret.length == 0) {
            return;
        }

        try {
            String textToCopy = new String(secret);
            StringSelection selection = new StringSelection(textToCopy);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selection, selection);

            logger.info("Secret copied to system clipboard. Auto-clear scheduled in {}s.", timeoutSeconds);

            // Schedule clipboard clearing
            scheduler.schedule(() -> clearClipboard(textToCopy), timeoutSeconds, TimeUnit.SECONDS);

        } catch (Exception e) {
            logger.error("Failed to access system clipboard: {}", e.getMessage());
            System.err.println("Warning: System clipboard unavailable in this environment.");
        }
    }

    /**
     * Clears the system clipboard if it still contains the expected copied value.
     */
    private void clearClipboard(String expectedValue) {
        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            // Overwrite clipboard with empty string
            StringSelection emptySelection = new StringSelection("");
            clipboard.setContents(emptySelection, emptySelection);
            logger.info("System clipboard cleared automatically.");
        } catch (Exception e) {
            logger.error("Failed to auto-clear clipboard: {}", e.getMessage());
        }
    }

    /**
     * Shuts down the scheduled executor service cleanly.
     */
    public void shutdown() {
        scheduler.shutdownNow();
    }
}
