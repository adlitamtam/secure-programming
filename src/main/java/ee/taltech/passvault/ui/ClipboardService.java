package ee.taltech.passvault.ui;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.GraphicsEnvironment;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;

/**
 * Handles copying passwords to the system clipboard and clearing them after a delay.
 */
public class ClipboardService {

    private static final Logger logger = LoggerFactory.getLogger(ClipboardService.class);

    /**
     * Copies a secret to the clipboard and starts a background thread to wipe it after timeout.
     */
    public void copyToClipboard(char[] secret, int timeoutSeconds) {
        if (secret == null || secret.length == 0) {
            return;
        }

        if (GraphicsEnvironment.isHeadless()) {
            logger.warn("Headless environment detected. Skipping system clipboard operation.");
            System.out.println("Notice: Headless environment detected - password clipboard copy skipped.");
            return;
        }

        try {
            String textToCopy = new String(secret);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(new StringSelection(textToCopy), null);

            logger.info("Copied secret to clipboard. Auto-clear in {}s.", timeoutSeconds);

            Thread clearThread = new Thread(() -> {
                try {
                    Thread.sleep(timeoutSeconds * 1000L);
                    clipboard.setContents(new StringSelection(""), null);
                    logger.info("Clipboard auto-cleared.");
                    System.out.println("\n[NOTICE] Clipboard cleared.");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (Throwable e) {
                    logger.error("Failed to clear clipboard: {}", e.getMessage());
                }
            });

            clearThread.setDaemon(true);
            clearThread.start();

        } catch (Throwable e) {
            logger.error("Clipboard unavailable: {}", e.getMessage());
            System.err.println("Warning: System clipboard unavailable in this environment.");
        }
    }

    public void shutdown() {
    }
}
