package com.glicoguard.site.database;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.glicoguard.site.model.AuditEntry;
import com.glicoguard.site.model.UserAccount;

public class InMemoryDatabase {

    private final Map<String, UserAccount> usersByEmail = new ConcurrentHashMap<>();
    private final List<AuditEntry> auditEntries = new ArrayList<>();
    private String lastAuditHash = "GENESIS";

    public Map<String, UserAccount> getUsersByEmail() {
        return usersByEmail;
    }

    public List<AuditEntry> getAuditEntries() {
        return auditEntries;
    }

    public String getLastAuditHash() {
        return lastAuditHash;
    }

    public void setLastAuditHash(String lastAuditHash) {
        this.lastAuditHash = lastAuditHash;
    }
}
