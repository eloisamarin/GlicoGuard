package com.glicoguard.site.service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.glicoguard.site.model.AccessLevel;
import com.glicoguard.site.model.UserAccount;
import com.glicoguard.site.model.UserRole;
import com.glicoguard.site.repository.UserStore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserStore store;
    private final AuthenticationService authenticationService;
    private final AdministrationService administrationService;
    private final PrivacyService privacyService;
    private final MedicationService medicationService;
    private final EmailService emailService;
    private final int maxAttempts;
    private final int lockMinutes;
    private final int twoFactorExpirationMinutes;

    public AuthService(CryptoService cryptoService,
                       ProtectedStorageService protectedStorageService,
                       EmailService emailService,
                       @Value("${glicoguard.security.login.max-attempts}") int maxAttempts,
                       @Value("${glicoguard.security.login.lock-minutes}") int lockMinutes,
                       @Value("${glicoguard.security.two-factor.expiration-minutes}") int twoFactorExpirationMinutes,
                       @Value("${glicoguard.security.reset.expiration-minutes}") int resetExpirationMinutes,
                       @Value("${glicoguard.security.consent.version}") String consentVersion,
                       @Value("${glicoguard.security.consent.purpose}") String consentPurpose) {
        this.store = new UserStore(cryptoService, protectedStorageService);
        this.emailService = emailService;
        this.maxAttempts = maxAttempts;
        this.lockMinutes = lockMinutes;
        this.twoFactorExpirationMinutes = twoFactorExpirationMinutes;
        this.authenticationService = new AuthenticationService(
                store,
                cryptoService,
                emailService,
                maxAttempts,
                lockMinutes,
                twoFactorExpirationMinutes,
                resetExpirationMinutes
        );
        this.administrationService = new AdministrationService(store);
        this.privacyService = new PrivacyService(store, protectedStorageService, consentVersion, consentPurpose);
        this.medicationService = new MedicationService(store);
        initializeDefaultAdministrator(cryptoService);
    }

    private void initializeDefaultAdministrator(CryptoService cryptoService) {
        CryptoService.PasswordHash adminPassword = cryptoService.createPasswordHash("admin123");
        UserAccount admin = new UserAccount(
                "Administrador",
                "admin@glicoguard.com",
                "00000000000",
                LocalDate.of(1996, 1, 1),
                UserRole.ADMINISTRADOR,
                AccessLevel.EDICAO,
                null,
                adminPassword.hash(),
                adminPassword.salt()
        );
        store.saveUser(admin);
        privacyService.signConsent(admin);
        store.addAudit(admin, "Conta inicial criada", "SUCESSO", "Administrador padrao do sistema.");
        store.persist();
    }

    public synchronized RegistrationResult register(String name,
                                                    String email,
                                                    String cpf,
                                                    LocalDate birthDate,
                                                    String password,
                                                    UserRole role,
                                                    AccessLevel accessLevel,
                                                    String caregiverInviteToken) {
        return authenticationService.register(name, email, cpf, birthDate, password, role, accessLevel, caregiverInviteToken);
    }

    public synchronized LoginChallenge startPrimaryAuthentication(String email, String password, String deviceFingerprint, String sourceIp) {
        return authenticationService.startPrimaryAuthentication(email, password, deviceFingerprint, sourceIp);
    }

    public synchronized Optional<UserAccount> completeTwoFactorAuthentication(String email, String twoFactorCode, String deviceFingerprint, String sourceIp) {
        return authenticationService.completeTwoFactorAuthentication(email, twoFactorCode, deviceFingerprint, sourceIp);
    }

    public synchronized PasswordResetView createPasswordReset(String email) {
        return authenticationService.createPasswordReset(email);
    }

    public synchronized void resetPassword(String email, String token, String newPassword) {
        authenticationService.resetPassword(email, token, newPassword);
    }

    public synchronized void updateEmail(UserAccount account, String newEmail) {
        administrationService.updateEmail(account, newEmail);
    }

    public synchronized void updatePassword(UserAccount account, String currentPassword, String newPassword) {
        authenticationService.updatePassword(account, currentPassword, newPassword);
    }

    public synchronized void updateAccessLevel(UserAccount account, AccessLevel accessLevel) {
        administrationService.updateAccessLevel(account, accessLevel);
    }

    public synchronized void signConsent(UserAccount account) {
        privacyService.signConsent(account);
    }

    public synchronized void revokeConsent(UserAccount account) {
        privacyService.revokeConsent(account);
    }

    public synchronized ResponseEntity<byte[]> exportUserData(UserAccount account) {
        return privacyService.exportUserData(account);
    }

    public synchronized void deleteUser(UserAccount account) {
        administrationService.deleteUser(account);
    }

    public synchronized void deleteUserByAdministrator(UserAccount administrator, String targetEmail) {
        administrationService.deleteUserByAdministrator(administrator, targetEmail);
    }

    public synchronized void blockUserByAdministrator(UserAccount administrator, String targetEmail) {
        administrationService.blockUserByAdministrator(administrator, targetEmail);
    }

    public synchronized void unblockUserByAdministrator(UserAccount administrator, String targetEmail) {
        administrationService.unblockUserByAdministrator(administrator, targetEmail);
    }

    public synchronized void registerMedication(UserAccount actor,
                                                String medicationName,
                                                String dose,
                                                String frequency,
                                                LocalDateTime scheduledAt) {
        medicationService.registerMedication(actor, medicationName, dose, frequency, scheduledAt);
    }

    public List<AuditEntryView> buildAuditView(UserAccount account) {
        return administrationService.buildAuditView(account);
    }

    public List<CollectedDataView> buildCollectedDataView(UserAccount account) {
        return privacyService.buildCollectedDataView(account);
    }

    public List<PrivacyExplanationView> buildPrivacyExplanations(UserAccount account) {
        return privacyService.buildPrivacyExplanations(account);
    }

    public List<String> buildDataSubjectRights() {
        return privacyService.buildDataSubjectRights();
    }

    public ConsentDocumentView buildConsentDocumentView(UserAccount account) {
        return privacyService.buildConsentDocumentView(account);
    }

    public Map<String, String> buildSecurityControlsSummary() {
        Map<String, String> controls = new LinkedHashMap<>();
        controls.put("Hash de senha", "PBKDF2WithHmacSHA256 com salt unico por usuario.");
        controls.put("2FA", "Codigo de 6 caracteres enviado por e-mail e valido por " + twoFactorExpirationMinutes + " minutos.");
        controls.put("Forca bruta", "Bloqueio apos " + maxAttempts + " falhas por " + lockMinutes + " minutos.");
        controls.put("Recuperacao", "Token seguro, temporario e invalidado apos uso.");
        controls.put("Criptografia em repouso", "Snapshots e exportacoes protegidos com AES/GCM.");
        controls.put("Logs", "Auditoria com hash encadeado e visibilidade global apenas para administrador.");
        return controls;
    }

    public Optional<UserAccount> findByEmail(String email) {
        return administrationService.findByEmail(email);
    }

    public Collection<UserAccount> getAllUsers() {
        return administrationService.getAllUsers();
    }

    public List<UserSummaryView> buildUserSummaryView() {
        return administrationService.buildUserSummaryView();
    }

    public Map<String, String> buildAdministratorSummary() {
        return administrationService.buildAdministratorSummary();
    }

    public List<String> describeProtectedAssets() {
        return privacyService.describeProtectedAssets();
    }

    public List<MedicationView> buildMedicationView(UserAccount actor) {
        return medicationService.buildMedicationView(actor);
    }

    public List<EmailService.EmailView> buildEmailView() {
        return emailService.buildEmailView();
    }

    public record LoginChallenge(String expiresAt) {
    }

    public record PasswordResetView(String token, String expiresAt) {
    }

    public record RegistrationResult(String errorMessage) {

        public static RegistrationResult error(String errorMessage) {
            return new RegistrationResult(errorMessage);
        }

        public static RegistrationResult success() {
            return new RegistrationResult(null);
        }

        public boolean hasError() {
            return errorMessage != null;
        }
    }

    public record AuditEntryView(
            String timestamp,
            String userEmail,
            String action,
            String result,
            String detail,
            String integritySnippet
    ) {
    }

    public record CollectedDataView(String dataName, String sampleValue, String purpose) {
    }

    public record PrivacyExplanationView(
            String title,
            String explanation,
            String codeReference
    ) {
    }

    public record ConsentDocumentView(
            String title,
            String version,
            String purpose,
            String status,
            String signedAt,
            String revokedAt,
            String statement
    ) {
    }

    public record MedicationView(
            String medicationName,
            String dose,
            String frequency,
            String scheduledAt,
            String registeredByEmail,
            String createdAt
    ) {
    }

    public record UserSummaryView(
            String name,
            String email,
            String role,
            String linkedPatientEmail,
            String status
    ) {
    }
}
