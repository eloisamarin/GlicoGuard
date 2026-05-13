package com.glicoguard.site.model;

import java.time.LocalDateTime;

public record AuditEntry(
        LocalDateTime timestamp,
        String userId,
        String userEmail,
        String action,
        String result,
        String detail,
        String previousHash,
        String integrityHash
) {
}
