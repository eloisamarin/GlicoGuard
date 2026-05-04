package com.glicoguard.site;

import java.time.LocalDateTime;

public class MedicationEntry {

    private final String medicationName;
    private final String dose;
    private final String frequency;
    private final LocalDateTime scheduledAt;
    private final String registeredByEmail;
    private final LocalDateTime createdAt;

    public MedicationEntry(String medicationName,
                           String dose,
                           String frequency,
                           LocalDateTime scheduledAt,
                           String registeredByEmail) {
        this.medicationName = medicationName;
        this.dose = dose;
        this.frequency = frequency;
        this.scheduledAt = scheduledAt;
        this.registeredByEmail = registeredByEmail;
        this.createdAt = LocalDateTime.now();
    }

    public String getMedicationName() {
        return medicationName;
    }

    public String getDose() {
        return dose;
    }

    public String getFrequency() {
        return frequency;
    }

    public LocalDateTime getScheduledAt() {
        return scheduledAt;
    }

    public String getRegisteredByEmail() {
        return registeredByEmail;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }
}
