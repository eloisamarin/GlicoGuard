package com.glicoguard.site.repository;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import com.glicoguard.site.database.InMemoryDatabase;
import com.glicoguard.site.model.AuditEntry;
import com.glicoguard.site.model.UserAccount;
import com.glicoguard.site.service.CryptoService;
import com.glicoguard.site.service.ProtectedStorageService;

public class UserStore {

    private final InMemoryDatabase database;
    private final CryptoService cryptoService;
    private final ProtectedStorageService protectedStorageService;

    public UserStore(CryptoService cryptoService, ProtectedStorageService protectedStorageService) {
        this.database = new InMemoryDatabase();
        this.cryptoService = cryptoService;
        this.protectedStorageService = protectedStorageService;
    }

    public boolean containsEmail(String normalizedEmail) {
        return database.getUsersByEmail().containsKey(normalizedEmail);
    }

    public Optional<UserAccount> findByEmail(String normalizedEmail) {
        return Optional.ofNullable(database.getUsersByEmail().get(normalizedEmail));
    }

    public UserAccount getByEmail(String normalizedEmail) {
        return database.getUsersByEmail().get(normalizedEmail);
    }

    public void saveUser(UserAccount user) {
        database.getUsersByEmail().put(user.getEmail().toLowerCase(), user);
    }

    public void removeByEmail(String normalizedEmail) {
        database.getUsersByEmail().remove(normalizedEmail);
    }

    public Collection<UserAccount> allUsers() {
        return database.getUsersByEmail().values();
    }

    public List<AuditEntry> auditEntries() {
        return database.getAuditEntries();
    }

    public void addAudit(UserAccount account, String action, String result, String detail) {
        addAudit(account.getId(), account.getEmail(), action, result, detail);
    }

    public void addAudit(String userId, String userEmail, String action, String result, String detail) {
        LocalDateTime now = LocalDateTime.now();
        String material = now + "|" + userId + "|" + userEmail + "|" + action + "|" + result + "|" + detail + "|" + database.getLastAuditHash();
        String integrityHash = cryptoService.digest(material);
        database.getAuditEntries().add(new AuditEntry(now, userId, userEmail, action, result, detail, database.getLastAuditHash(), integrityHash));
        database.setLastAuditHash(integrityHash);
    }

    public void persist() {
        protectedStorageService.storeEncryptedUserSnapshot(database.getUsersByEmail().values());
        protectedStorageService.storeEncryptedAuditSnapshot(database.getAuditEntries());
    }
}
