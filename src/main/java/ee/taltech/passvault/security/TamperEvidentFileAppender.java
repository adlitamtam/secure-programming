package ee.taltech.passvault.security;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.rolling.RollingFileAppender;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

/**
 * RollingFileAppender with owner-only file permissions, runtime self-healing
 * if deleted, and an SHA-256 hash chain to detect external log tampering.
 */
public class TamperEvidentFileAppender extends RollingFileAppender<ILoggingEvent> {

    private static final String GENESIS_HASH = "GENESIS";
    private static final String SIG_PREFIX = " [sig=";
    private String previousHash = GENESIS_HASH;

    /**
     * Verifies the SHA-256 hash chain of the existing log file on startup.
     *
     * @return true if intact or file does not exist yet; false if tampering is detected.
     */
    public static boolean verifyLogIntegrity(String filePath) {
        Path path = Path.of(filePath);
        if (!Files.exists(path)) {
            return true;
        }

        try {
            List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
            String expectedPrevHash = GENESIS_HASH;

            for (String line : lines) {
                if (line.isBlank()) {
                    continue;
                }
                int sigIndex = line.lastIndexOf(SIG_PREFIX);
                if (sigIndex == -1 || !line.endsWith("]")) {
                    return false; // Missing or malformed signature
                }

                String rawMessage = line.substring(0, sigIndex);
                String recordedHash = line.substring(sigIndex + SIG_PREFIX.length(), line.length() - 1);
                String recomputedHash = computeSha256(expectedPrevHash + "|" + rawMessage);

                if (!MessageDigest.isEqual(
                        recordedHash.getBytes(StandardCharsets.UTF_8),
                        recomputedHash.getBytes(StandardCharsets.UTF_8))) {
                    return false; // Hash mismatch -> line was modified or deleted
                }
                expectedPrevHash = recordedHash;
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static void restrictPermissions(File file) {
        if (!file.exists()) {
            return;
        }
        try {
            Files.setPosixFilePermissions(file.toPath(), PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException ignored) {
            file.setReadable(false, false);
            file.setReadable(true, true);
            file.setWritable(false, false);
            file.setWritable(true, true);
        }
    }

    private static String computeSha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 algorithm unavailable", e);
        }
    }

    @Override
    public void start() {
        super.start();
        File logFile = new File(getFile());
        restrictPermissions(logFile);
        this.previousHash = loadLastHash(logFile);
    }

    @Override
    protected void subAppend(ILoggingEvent event) {
        if (!isStarted()) {
            return;
        }

        File logFile = new File(getFile());
        // Self-healing: recreate file immediately if deleted at runtime
        if (!logFile.exists()) {
            try {
                openFile(getFile());
                restrictPermissions(logFile);
                this.previousHash = GENESIS_HASH;
                writeSignedLine("[SECURITY ALERT] Log file was deleted at runtime and recreated!");
            } catch (IOException e) {
                addError("Failed to recreate deleted log file", e);
                return;
            }
        }

        super.subAppend(event);
    }

    @Override
    protected void writeOut(ILoggingEvent event) throws IOException {
        File logFile = new File(getFile());
        // Reset chain if file is empty (fresh creation or right after log rotation)
        if (logFile.length() == 0) {
            this.previousHash = GENESIS_HASH;
        }

        String rawMessage = new String(this.encoder.encode(event), StandardCharsets.UTF_8).stripTrailing();
        writeSignedLine(rawMessage);
    }

    private void writeSignedLine(String rawMessage) throws IOException {
        String currentHash = computeSha256(previousHash + "|" + rawMessage);
        String signedLine = rawMessage + SIG_PREFIX + currentHash + "]" + System.lineSeparator();

        getOutputStream().write(signedLine.getBytes(StandardCharsets.UTF_8));
        if (isImmediateFlush()) {
            getOutputStream().flush();
        }
        this.previousHash = currentHash;
    }

    private String loadLastHash(File logFile) {
        if (!logFile.exists() || logFile.length() == 0) {
            return GENESIS_HASH;
        }
        try {
            List<String> lines = Files.readAllLines(logFile.toPath(), StandardCharsets.UTF_8);
            for (int i = lines.size() - 1; i >= 0; i--) {
                String line = lines.get(i);
                int sigIndex = line.lastIndexOf(SIG_PREFIX);
                if (sigIndex != -1 && line.endsWith("]")) {
                    return line.substring(sigIndex + SIG_PREFIX.length(), line.length() - 1);
                }
            }
        } catch (IOException ignored) {
        }
        return GENESIS_HASH;
    }
}
