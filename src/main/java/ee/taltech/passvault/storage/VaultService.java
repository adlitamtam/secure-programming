package ee.taltech.passvault.storage;

import ee.taltech.passvault.auth.UserSession;
import ee.taltech.passvault.crypto.SecureRandomUtils;
import ee.taltech.passvault.crypto.VaultCipher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;

/**
 * Business service for managing vault items (add, list, decrypt, delete).
 */
public class VaultService {

    private static final Logger logger = LoggerFactory.getLogger(VaultService.class);

    private final VaultItemDao vaultItemDao;
    private final VaultCipher cipher;

    public VaultService() {
        this.vaultItemDao = new VaultItemDao();
        this.cipher = new VaultCipher();
    }

    public boolean addEntry(UserSession session, String service, String accountUsername, char[] password) {
        if (session == null || service.isBlank() || password == null || password.length == 0) {
            return false;
        }

        byte[] nonce = SecureRandomUtils.generateNonce();
        byte[] ciphertext = cipher.encrypt(password, session.getEncryptionKey(), nonce);

        return vaultItemDao.addVaultItem(session.getUserId(), service, accountUsername, ciphertext, nonce);
    }

    public List<String> listServices(UserSession session) {
        if (session == null) {
            return List.of();
        }
        return vaultItemDao.getServicesForUser(session.getUserId());
    }

    public Optional<char[]> getDecryptedPassword(UserSession session, String service) {
        if (session == null || service.isBlank()) {
            return Optional.empty();
        }

        Optional<VaultItem> itemOpt = vaultItemDao.getVaultItemByService(session.getUserId(), service);
        if (itemOpt.isEmpty()) {
            return Optional.empty();
        }

        VaultItem item = itemOpt.get();
        try {
            char[] decryptedPassword = cipher.decrypt(item.getCiphertext(), session.getEncryptionKey(), item.getNonce());
            return Optional.of(decryptedPassword);
        } catch (SecurityException e) {
            logger.error("Failed to decrypt item for service '{}': {}", service, e.getMessage());
            return Optional.empty();
        }
    }

    public boolean deleteEntry(UserSession session, String service) {
        if (session == null || service.isBlank()) {
            return false;
        }
        return vaultItemDao.deleteVaultItem(session.getUserId(), service);
    }
}
