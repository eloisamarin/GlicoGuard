package com.glicoguard.site.model;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public class UserAccount {

    private final String id;
    private final String name;
    private String email;
    private final String cpf;
    private final LocalDate birthDate;
    private final UserRole role;
    private AccessLevel accessLevel;
    private String linkedPatientEmail;
    private String passwordHash;
    private String passwordSalt;
    private boolean consentSigned;
    private String consentVersion;
    private String consentPurpose;
    private LocalDateTime consentSignedAt;
    private LocalDateTime consentRevokedAt;
    private final Set<String> knownDevices;
    private final LocalDateTime createdAt;
    private int failedLoginAttempts;
    private LocalDateTime lockedUntil;
    private String currentTwoFactorHash;
    private LocalDateTime currentTwoFactorExpiresAt;
    private String passwordResetTokenHash;
    private LocalDateTime passwordResetExpiresAt;
    private String caregiverInviteTokenHash;
    private LocalDateTime caregiverInviteTokenExpiresAt;
    private final List<MedicationEntry> medications;

    public UserAccount(String name,
                       String email,
                       String cpf,
                       LocalDate birthDate,
                       UserRole role,
                       AccessLevel accessLevel,
                       String linkedPatientEmail,
                       String passwordHash,
                       String passwordSalt) {
        this.id = UUID.randomUUID().toString();
        this.name = name;
        this.email = email;
        this.cpf = cpf;
        this.birthDate = birthDate;
        this.role = role;
        this.accessLevel = accessLevel;
        this.linkedPatientEmail = linkedPatientEmail;
        this.passwordHash = passwordHash;
        this.passwordSalt = passwordSalt;
        this.knownDevices = new HashSet<>();
        this.medications = new ArrayList<>();
        this.createdAt = LocalDateTime.now();
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }

    public String getCpf() {
        return cpf;
    }

    public LocalDate getBirthDate() {
        return birthDate;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public UserRole getRole() {
        return role;
    }

    public AccessLevel getAccessLevel() {
        return accessLevel;
    }

    public void setAccessLevel(AccessLevel accessLevel) {
        this.accessLevel = accessLevel;
    }

    public String getLinkedPatientEmail() {
        return linkedPatientEmail;
    }

    public void setLinkedPatientEmail(String linkedPatientEmail) {
        this.linkedPatientEmail = linkedPatientEmail;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public String getPasswordSalt() {
        return passwordSalt;
    }

    public void setPasswordSalt(String passwordSalt) {
        this.passwordSalt = passwordSalt;
    }

    public boolean isConsentSigned() {
        return consentSigned;
    }

    public void setConsentSigned(boolean consentSigned) {
        this.consentSigned = consentSigned;
    }

    public String getConsentVersion() {
        return consentVersion;
    }

    public void setConsentVersion(String consentVersion) {
        this.consentVersion = consentVersion;
    }

    public String getConsentPurpose() {
        return consentPurpose;
    }

    public void setConsentPurpose(String consentPurpose) {
        this.consentPurpose = consentPurpose;
    }

    public LocalDateTime getConsentSignedAt() {
        return consentSignedAt;
    }

    public void setConsentSignedAt(LocalDateTime consentSignedAt) {
        this.consentSignedAt = consentSignedAt;
    }

    public LocalDateTime getConsentRevokedAt() {
        return consentRevokedAt;
    }

    public void setConsentRevokedAt(LocalDateTime consentRevokedAt) {
        this.consentRevokedAt = consentRevokedAt;
    }

    public Set<String> getKnownDevices() {
        return knownDevices;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public int getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    public void setFailedLoginAttempts(int failedLoginAttempts) {
        this.failedLoginAttempts = failedLoginAttempts;
    }

    public LocalDateTime getLockedUntil() {
        return lockedUntil;
    }

    public void setLockedUntil(LocalDateTime lockedUntil) {
        this.lockedUntil = lockedUntil;
    }

    public String getCurrentTwoFactorHash() {
        return currentTwoFactorHash;
    }

    public void setCurrentTwoFactorHash(String currentTwoFactorHash) {
        this.currentTwoFactorHash = currentTwoFactorHash;
    }

    public LocalDateTime getCurrentTwoFactorExpiresAt() {
        return currentTwoFactorExpiresAt;
    }

    public void setCurrentTwoFactorExpiresAt(LocalDateTime currentTwoFactorExpiresAt) {
        this.currentTwoFactorExpiresAt = currentTwoFactorExpiresAt;
    }

    public String getPasswordResetTokenHash() {
        return passwordResetTokenHash;
    }

    public void setPasswordResetTokenHash(String passwordResetTokenHash) {
        this.passwordResetTokenHash = passwordResetTokenHash;
    }

    public LocalDateTime getPasswordResetExpiresAt() {
        return passwordResetExpiresAt;
    }

    public void setPasswordResetExpiresAt(LocalDateTime passwordResetExpiresAt) {
        this.passwordResetExpiresAt = passwordResetExpiresAt;
    }

    public String getCaregiverInviteTokenHash() {
        return caregiverInviteTokenHash;
    }

    public void setCaregiverInviteTokenHash(String caregiverInviteTokenHash) {
        this.caregiverInviteTokenHash = caregiverInviteTokenHash;
    }

    public LocalDateTime getCaregiverInviteTokenExpiresAt() {
        return caregiverInviteTokenExpiresAt;
    }

    public void setCaregiverInviteTokenExpiresAt(LocalDateTime caregiverInviteTokenExpiresAt) {
        this.caregiverInviteTokenExpiresAt = caregiverInviteTokenExpiresAt;
    }

    public List<MedicationEntry> getMedications() {
        return medications;
    }
}
