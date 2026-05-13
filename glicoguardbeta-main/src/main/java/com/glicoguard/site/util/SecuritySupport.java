package com.glicoguard.site.util;

import java.nio.charset.StandardCharsets;

public final class SecuritySupport {

    private SecuritySupport() {
    }

    public static boolean constantTimeEquals(String left, String right) {
        return java.security.MessageDigest.isEqual(
                left.getBytes(StandardCharsets.UTF_8),
                right.getBytes(StandardCharsets.UTF_8)
        );
    }

    public static String normalizeEmail(String email) {
        return email == null ? "" : email.trim().toLowerCase();
    }

    public static String normalizeCpf(String cpf) {
        return cpf == null ? "" : cpf.replaceAll("\\D", "");
    }

    public static String sanitizeFilePart(String value) {
        return value.replaceAll("[^a-zA-Z0-9.-]", "_");
    }
}
