package com.glicoguard.site.util;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public final class FormatSupport {

    public static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");
    public static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("dd/MM/yyyy");

    private FormatSupport() {
    }

    public static String formatDate(LocalDate value) {
        return DATE_FORMATTER.format(value);
    }

    public static String formatDateTime(LocalDateTime value) {
        return DATE_TIME_FORMATTER.format(value);
    }
}
