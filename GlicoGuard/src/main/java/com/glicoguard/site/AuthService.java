package com.glicoguard.site;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");
    private static final int CAREGIVER_INVITE_EXPIRATION_DAYS = 7;

    private final Map<String, UserAccount> usersByEmail = new ConcurrentHashMap<>();
    private final List<AuditEntry> auditEntries = new ArrayList<>();
    private final CryptoService cryptoService;
    private final ProtectedStorageService protectedStorageService;
    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
    private final int maxAttempts;
    private final int lockMinutes;
    private final int twoFactorExpirationMinutes;
    private final int resetExpirationMinutes;
    private final String consentVersion;
    private final String consentPurpose;
    private String lastAuditHash = "GENESIS";

    public AuthService(CryptoService cryptoService,
                       ProtectedStorageService protectedStorageService,
                       @Value("${glicoguard.security.login.max-attempts}") int maxAttempts,
                       @Value("${glicoguard.security.login.lock-minutes}") int lockMinutes,
                       @Value("${glicoguard.security.two-factor.expiration-minutes}") int twoFactorExpirationMinutes,
                       @Value("${glicoguard.security.reset.expiration-minutes}") int resetExpirationMinutes,
                       @Value("${glicoguard.security.consent.version}") String consentVersion,
                       @Value("${glicoguard.security.consent.purpose}") String consentPurpose) {
        this.cryptoService = cryptoService;
        this.protectedStorageService = protectedStorageService;
        this.maxAttempts = maxAttempts;
        this.lockMinutes = lockMinutes;
        this.twoFactorExpirationMinutes = twoFactorExpirationMinutes;
        this.resetExpirationMinutes = resetExpirationMinutes;
        this.consentVersion = consentVersion;
        this.consentPurpose = consentPurpose;

        CryptoService.PasswordHash adminPassword = cryptoService.createPasswordHash("admin123");
        UserAccount admin = new UserAccount(
                "Administrador",
                "admin@glicoguard.com",
                "00000000000",
                30,
                UserRole.ADMINISTRADOR,
                AccessLevel.EDICAO,
                null,
                adminPassword.hash(),
                adminPassword.salt()
        );
        signConsent(admin);
        usersByEmail.put(admin.getEmail().toLowerCase(), admin);
        addAudit(admin, "Conta inicial criada", "SUCESSO", "Administrador padrao do sistema.");
        persistProtectedState();
    }

    public synchronized RegistrationResult register(String name,
                                                    String email,
                                                    String cpf,
                                                    int age,
                                                    String password,
                                                    UserRole role,
                                                    AccessLevel accessLevel,
                                                    String caregiverInviteToken) {
        String normalizedEmail = normalizeEmail(email);
        if (usersByEmail.containsKey(normalizedEmail)) {
            return RegistrationResult.error("Ja existe um usuario com este e-mail.");
        }
        String normalizedCpf = normalizeCpf(cpf);
        if (normalizedCpf.length() != 11) {
            return RegistrationResult.error("Informe um CPF com 11 digitos.");
        }
        if (age <= 0 || age > 120) {
            return RegistrationResult.error("Informe uma idade valida.");
        }
        if (usersByEmail.values().stream().anyMatch(user -> user.getCpf().equals(normalizedCpf))) {
            return RegistrationResult.error("Ja existe um usuario com este CPF.");
        }
        String caregiverLink = null;
        if (role == UserRole.CUIDADOR) {
            if (caregiverInviteToken == null || caregiverInviteToken.isBlank()) {
                return RegistrationResult.error("Para cuidador, informe o token de vinculacao do paciente.");
            }
            UserAccount patient = findPatientByInviteToken(caregiverInviteToken);
            if (patient == null) {
                return RegistrationResult.error("Token de vinculacao invalido ou expirado.");
            }
            caregiverLink = patient.getEmail();
        }

        CryptoService.PasswordHash passwordHash = cryptoService.createPasswordHash(password);
        UserAccount account = new UserAccount(
                name.trim(),
                normalizedEmail,
                normalizedCpf,
                age,
                role,
                accessLevel,
                caregiverLink,
                passwordHash.hash(),
                passwordHash.salt()
        );
        usersByEmail.put(normalizedEmail, account);
        String generatedInviteToken = null;
        if (role == UserRole.PACIENTE) {
            generatedInviteToken = createCaregiverInviteToken(account);
        }
        if (role == UserRole.CUIDADOR) {
            invalidateCaregiverInvite(caregiverLink);
        }
        String detail = role == UserRole.CUIDADOR
                ? "Conta criada com sucesso e vinculada ao paciente " + caregiverLink + "."
                : "Conta criada com sucesso.";
        addAudit(account, "Cadastro realizado", "SUCESSO", detail);
        persistProtectedState();
        return RegistrationResult.success(generatedInviteToken);
    }

    public synchronized LoginChallenge startPrimaryAuthentication(String email, String password, String deviceFingerprint, String sourceIp) {
        UserAccount account = usersByEmail.get(normalizeEmail(email));
        if (account == null) {
            addAudit("desconhecido", normalizeEmail(email), "Login primario", "FALHA", "Usuario inexistente. Origem: " + sourceIp);
            throw new IllegalArgumentException("E-mail ou senha invalidos.");
        }

        if (account.getLockedUntil() != null && LocalDateTime.now().isBefore(account.getLockedUntil())) {
            addAudit(account, "Login primario", "FALHA", "Conta temporariamente bloqueada por tentativas sucessivas.");
            throw new IllegalArgumentException("Conta temporariamente bloqueada ate " + FORMATTER.format(account.getLockedUntil()) + ".");
        }

        if (!cryptoService.matchesPassword(password, account.getPasswordHash(), account.getPasswordSalt())) {
            registerFailedAttempt(account);
            addAudit(account, "Login primario", "FALHA", "Senha incorreta. Origem: " + sourceIp);
            persistProtectedState();
            throw new IllegalArgumentException("E-mail ou senha invalidos.");
        }

        account.setFailedLoginAttempts(0);
        account.setLockedUntil(null);
        String twoFactorCode = cryptoService.generateTwoFactorCode();
        account.setCurrentTwoFactorHash(cryptoService.digest(twoFactorCode));
        account.setCurrentTwoFactorExpiresAt(LocalDateTime.now().plusMinutes(twoFactorExpirationMinutes));
        addAudit(account, "2FA gerado", "SUCESSO",
                "Codigo temporario emitido para autenticacao em dois fatores. Origem: " + sourceIp);
        persistProtectedState();
        return new LoginChallenge(twoFactorCode, FORMATTER.format(account.getCurrentTwoFactorExpiresAt()));
    }

    public synchronized Optional<UserAccount> completeTwoFactorAuthentication(String email, String twoFactorCode, String deviceFingerprint, String sourceIp) {
        UserAccount account = usersByEmail.get(normalizeEmail(email));
        if (account == null) {
            addAudit("desconhecido", normalizeEmail(email), "2FA", "FALHA", "Usuario inexistente. Origem: " + sourceIp);
            return Optional.empty();
        }

        if (account.getCurrentTwoFactorHash() == null || account.getCurrentTwoFactorExpiresAt() == null) {
            addAudit(account, "2FA", "FALHA", "Nenhum desafio 2FA ativo.");
            return Optional.empty();
        }

        if (LocalDateTime.now().isAfter(account.getCurrentTwoFactorExpiresAt())) {
            clearTwoFactor(account);
            addAudit(account, "2FA", "FALHA", "Codigo expirado.");
            persistProtectedState();
            return Optional.empty();
        }

        String providedDigest = cryptoService.digest(twoFactorCode.trim());
        if (!MessageDigestFacade.equals(account.getCurrentTwoFactorHash(), providedDigest)) {
            addAudit(account, "2FA", "FALHA", "Codigo incorreto.");
            persistProtectedState();
            return Optional.empty();
        }

        clearTwoFactor(account);
        if (account.getKnownDevices().add(deviceFingerprint)) {
            addAudit(account, "Novo dispositivo detectado", "SUCESSO",
                    "Um alerta seria enviado ao e-mail " + account.getEmail() + ". Origem: " + sourceIp);
        }
        addAudit(account, "Login concluido", "SUCESSO", "Autenticacao primaria e 2FA concluidos.");
        persistProtectedState();
        return Optional.of(account);
    }

    public synchronized PasswordResetView createPasswordReset(String email) {
        UserAccount account = usersByEmail.get(normalizeEmail(email));
        if (account == null) {
            addAudit("desconhecido", normalizeEmail(email), "Recuperacao de senha", "FALHA", "Solicitacao para usuario inexistente.");
            throw new IllegalArgumentException("Nao existe usuario cadastrado com este e-mail.");
        }

        String token = cryptoService.generateSecureToken();
        account.setPasswordResetTokenHash(cryptoService.digest(token));
        account.setPasswordResetExpiresAt(LocalDateTime.now().plusMinutes(resetExpirationMinutes));
        addAudit(account, "Recuperacao de senha", "SUCESSO",
                "Token criptograficamente seguro gerado para redefinicao da senha.");
        persistProtectedState();
        return new PasswordResetView(token, FORMATTER.format(account.getPasswordResetExpiresAt()));
    }

    public synchronized void resetPassword(String email, String token, String newPassword) {
        UserAccount account = usersByEmail.get(normalizeEmail(email));
        if (account == null) {
            addAudit("desconhecido", normalizeEmail(email), "Redefinicao de senha", "FALHA", "Usuario nao encontrado.");
            throw new IllegalArgumentException("Usuario nao encontrado.");
        }

        if (account.getPasswordResetTokenHash() == null || account.getPasswordResetExpiresAt() == null) {
            addAudit(account, "Redefinicao de senha", "FALHA", "Nenhum token de recuperacao foi solicitado.");
            throw new IllegalArgumentException("Solicite um token de recuperacao antes de redefinir a senha.");
        }

        if (LocalDateTime.now().isAfter(account.getPasswordResetExpiresAt())) {
            clearPasswordReset(account);
            addAudit(account, "Redefinicao de senha", "FALHA", "Token expirado.");
            persistProtectedState();
            throw new IllegalArgumentException("O token expirou. Solicite uma nova recuperacao.");
        }

        if (!MessageDigestFacade.equals(account.getPasswordResetTokenHash(), cryptoService.digest(token.trim()))) {
            addAudit(account, "Redefinicao de senha", "FALHA", "Token invalido.");
            persistProtectedState();
            throw new IllegalArgumentException("Token de recuperacao invalido.");
        }

        CryptoService.PasswordHash passwordHash = cryptoService.createPasswordHash(newPassword);
        account.setPasswordHash(passwordHash.hash());
        account.setPasswordSalt(passwordHash.salt());
        clearPasswordReset(account);
        addAudit(account, "Redefinicao de senha", "SUCESSO", "Senha alterada com token temporario.");
        persistProtectedState();
    }

    public synchronized void updateEmail(UserAccount account, String newEmail) {
        String normalizedEmail = normalizeEmail(newEmail);
        if (!account.getEmail().equalsIgnoreCase(normalizedEmail) && usersByEmail.containsKey(normalizedEmail)) {
            throw new IllegalArgumentException("Este e-mail ja esta em uso.");
        }

        usersByEmail.remove(account.getEmail().toLowerCase());
        account.setEmail(normalizedEmail);
        usersByEmail.put(normalizedEmail, account);
        addAudit(account, "E-mail atualizado", "SUCESSO", "Novo e-mail cadastrado: " + normalizedEmail);
        persistProtectedState();
    }

    public synchronized void updatePassword(UserAccount account, String currentPassword, String newPassword) {
        if (!cryptoService.matchesPassword(currentPassword, account.getPasswordHash(), account.getPasswordSalt())) {
            addAudit(account, "Troca de senha autenticada", "FALHA", "Senha atual incorreta.");
            throw new IllegalArgumentException("A senha atual nao confere.");
        }

        CryptoService.PasswordHash passwordHash = cryptoService.createPasswordHash(newPassword);
        account.setPasswordHash(passwordHash.hash());
        account.setPasswordSalt(passwordHash.salt());
        addAudit(account, "Troca de senha autenticada", "SUCESSO", "Credencial alterada pelo titular autenticado.");
        persistProtectedState();
    }

    public synchronized void updateAccessLevel(UserAccount account, AccessLevel accessLevel) {
        account.setAccessLevel(accessLevel);
        addAudit(account, "Nivel de acesso atualizado", "SUCESSO", "Novo nivel: " + accessLevel);
        persistProtectedState();
    }

    public synchronized void signConsent(UserAccount account) {
        account.setConsentSigned(true);
        account.setConsentVersion(consentVersion);
        account.setConsentPurpose(consentPurpose);
        account.setConsentSignedAt(LocalDateTime.now());
        account.setConsentRevokedAt(null);
        addAudit(account, "Consentimento LGPD", "SUCESSO", "Consentimento registrado com finalidade explicita.");
        persistProtectedState();
    }

    public synchronized void revokeConsent(UserAccount account) {
        account.setConsentSigned(false);
        account.setConsentRevokedAt(LocalDateTime.now());
        addAudit(account, "Revogacao de consentimento", "SUCESSO", "Titular revogou o consentimento anteriormente concedido.");
        persistProtectedState();
    }

    public synchronized ResponseEntity<byte[]> exportUserData(UserAccount account) {
        Map<String, Object> exportMap = buildPersonalDataMap(account);
        byte[] jsonBytes = toPrettyJson(exportMap).getBytes(StandardCharsets.UTF_8);
        protectedStorageService.storeEncryptedExport("export-" + sanitizeFilePart(account.getEmail()) + ".enc", exportMap);
        addAudit(account, "Exportacao de dados", "SUCESSO", "Titular exportou os dados pessoais em JSON.");
        persistProtectedState();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename("dados-" + sanitizeFilePart(account.getEmail()) + ".json")
                .build());
        return ResponseEntity.ok().headers(headers).body(jsonBytes);
    }

    public synchronized void deleteUser(UserAccount account) {
        usersByEmail.remove(account.getEmail().toLowerCase());
        addAudit(account, "Exclusao de dados pessoais", "SUCESSO", "Conta removida mediante solicitacao do titular.");
        persistProtectedState();
    }

    public synchronized void registerMedication(UserAccount actor,
                                                String medicationName,
                                                String dose,
                                                String frequency,
                                                LocalDateTime scheduledAt) {
        if (medicationName == null || medicationName.isBlank()
                || dose == null || dose.isBlank()
                || frequency == null || frequency.isBlank()
                || scheduledAt == null) {
            throw new IllegalArgumentException("Preencha nome do medicamento, dose, frequencia e data com horario.");
        }

        UserAccount targetPatient = resolveMedicationTarget(actor);
        MedicationEntry entry = new MedicationEntry(
                medicationName.trim(),
                dose.trim(),
                frequency.trim(),
                scheduledAt,
                actor.getEmail()
        );
        targetPatient.getMedications().add(entry);

        String detail = actor.getRole() == UserRole.CUIDADOR
                ? "Medicamento registrado para o paciente vinculado " + targetPatient.getEmail() + "."
                : "Medicamento registrado para o proprio paciente.";
        addAudit(actor, "Registro de medicamento", "SUCESSO", detail);
        persistProtectedState();
    }

    public List<AuditEntryView> buildAuditView() {
        return auditEntries.stream()
                .sorted(Comparator.comparing(AuditEntry::timestamp).reversed())
                .map(entry -> new AuditEntryView(
                        FORMATTER.format(entry.timestamp()),
                        entry.userEmail(),
                        entry.action(),
                        entry.result(),
                        entry.detail(),
                        abbreviate(entry.integrityHash())
                ))
                .toList();
    }

    public List<CollectedDataView> buildCollectedDataView(UserAccount account) {
        List<CollectedDataView> data = new ArrayList<>();
        data.add(new CollectedDataView("Nome completo", account.getName(), "Identificar o titular e personalizar o painel."));
        data.add(new CollectedDataView("E-mail", account.getEmail(), "Realizar login, 2FA, notificacoes e recuperacao de senha."));
        data.add(new CollectedDataView("CPF", account.getCpf(), "Identificacao civil minima do titular para cadastro."));
        data.add(new CollectedDataView("Idade", String.valueOf(account.getAge()), "Apoiar regras de cuidado e classificacao do perfil."));
        data.add(new CollectedDataView("Perfil de acesso", account.getRole().name(), "Aplicar regras de autorizacao entre paciente, cuidador e administrador."));
        data.add(new CollectedDataView("Nivel de acesso", account.getAccessLevel().name(), "Definir permissao de leitura ou edicao."));
        data.add(new CollectedDataView("Vinculo de cuidado", account.getLinkedPatientEmail() != null ? account.getLinkedPatientEmail() : "Nao aplicavel", "Associar um cuidador ao paciente acompanhado."));
        data.add(new CollectedDataView("Medicamentos registrados", String.valueOf(account.getMedications().size()), "Registrar nome, dose, frequencia e horario do tratamento informado."));
        data.add(new CollectedDataView("Consentimento", account.isConsentSigned() ? "Assinado" : "Nao assinado", "Registrar base legal e finalidade do tratamento."));
        data.add(new CollectedDataView("Metadados de seguranca", "Dispositivos, tentativas e logs", "Detectar fraude, forca bruta e auditar operacoes."));
        return data;
    }

    public Map<String, String> buildSecurityControlsSummary() {
        Map<String, String> controls = new LinkedHashMap<>();
        controls.put("Hash de senha", "PBKDF2WithHmacSHA256 com salt unico por usuario.");
        controls.put("2FA", "Codigo temporario de 6 digitos valido por " + twoFactorExpirationMinutes + " minutos.");
        controls.put("Forca bruta", "Bloqueio apos " + maxAttempts + " falhas por " + lockMinutes + " minutos.");
        controls.put("Recuperacao", "Token seguro, temporario e invalidado apos uso.");
        controls.put("Criptografia em repouso", "Snapshots e exportacoes protegidos com AES/GCM.");
        controls.put("Logs", "Auditoria com hash encadeado para detectar alteracoes.");
        return controls;
    }

    public Optional<UserAccount> findByEmail(String email) {
        return Optional.ofNullable(usersByEmail.get(normalizeEmail(email)));
    }

    public Collection<UserAccount> getAllUsers() {
        return usersByEmail.values();
    }

    public List<String> describeProtectedAssets() {
        return protectedStorageService.describeProtectedAssets();
    }

    public List<MedicationView> buildMedicationView(UserAccount actor) {
        UserAccount targetPatient = resolveMedicationTargetOrNull(actor);
        if (targetPatient == null) {
            return List.of();
        }
        return targetPatient.getMedications().stream()
                .sorted(Comparator.comparing(MedicationEntry::getScheduledAt).reversed())
                .map(entry -> new MedicationView(
                        entry.getMedicationName(),
                        entry.getDose(),
                        entry.getFrequency(),
                        FORMATTER.format(entry.getScheduledAt()),
                        entry.getRegisteredByEmail(),
                        FORMATTER.format(entry.getCreatedAt())
                ))
                .toList();
    }

    private void registerFailedAttempt(UserAccount account) {
        int attempts = account.getFailedLoginAttempts() + 1;
        account.setFailedLoginAttempts(attempts);
        if (attempts >= maxAttempts) {
            account.setLockedUntil(LocalDateTime.now().plusMinutes(lockMinutes));
            account.setFailedLoginAttempts(0);
        }
    }

    private void clearTwoFactor(UserAccount account) {
        account.setCurrentTwoFactorHash(null);
        account.setCurrentTwoFactorExpiresAt(null);
    }

    private void clearPasswordReset(UserAccount account) {
        account.setPasswordResetTokenHash(null);
        account.setPasswordResetExpiresAt(null);
    }

    private UserAccount resolveMedicationTarget(UserAccount actor) {
        UserAccount targetPatient = resolveMedicationTargetOrNull(actor);
        if (targetPatient == null) {
            throw new IllegalArgumentException("Apenas paciente ou cuidador vinculado podem registrar medicamentos.");
        }
        return targetPatient;
    }

    private UserAccount resolveMedicationTargetOrNull(UserAccount actor) {
        if (actor.getRole() == UserRole.PACIENTE) {
            return actor;
        }
        if (actor.getRole() == UserRole.CUIDADOR && actor.getLinkedPatientEmail() != null) {
            return usersByEmail.get(actor.getLinkedPatientEmail().toLowerCase());
        }
        return null;
    }

    private UserAccount findPatientByInviteToken(String caregiverInviteToken) {
        String tokenDigest = cryptoService.digest(caregiverInviteToken.trim());
        return usersByEmail.values().stream()
                .filter(user -> user.getRole() == UserRole.PACIENTE)
                .filter(user -> user.getCaregiverInviteTokenHash() != null)
                .filter(user -> user.getCaregiverInviteTokenExpiresAt() != null)
                .filter(user -> !LocalDateTime.now().isAfter(user.getCaregiverInviteTokenExpiresAt()))
                .filter(user -> MessageDigestFacade.equals(user.getCaregiverInviteTokenHash(), tokenDigest))
                .findFirst()
                .orElse(null);
    }

    private String createCaregiverInviteToken(UserAccount patientAccount) {
        String token = cryptoService.generateSecureToken();
        patientAccount.setCaregiverInviteTokenHash(cryptoService.digest(token));
        patientAccount.setCaregiverInviteTokenExpiresAt(LocalDateTime.now().plusDays(CAREGIVER_INVITE_EXPIRATION_DAYS));
        addAudit(patientAccount, "Token de vinculacao gerado", "SUCESSO",
                "Token para vinculacao de cuidador valido ate " + FORMATTER.format(patientAccount.getCaregiverInviteTokenExpiresAt()) + ".");
        return token;
    }

    private void invalidateCaregiverInvite(String patientEmail) {
        UserAccount patient = usersByEmail.get(patientEmail);
        if (patient == null) {
            return;
        }
        patient.setCaregiverInviteTokenHash(null);
        patient.setCaregiverInviteTokenExpiresAt(null);
        addAudit(patient, "Token de vinculacao invalidado", "SUCESSO",
                "Token de vinculacao consumido por um cuidador.");
    }

    private void addAudit(UserAccount account, String action, String result, String detail) {
        addAudit(account.getId(), account.getEmail(), action, result, detail);
    }

    private void addAudit(String userId, String userEmail, String action, String result, String detail) {
        LocalDateTime now = LocalDateTime.now();
        String material = now + "|" + userId + "|" + userEmail + "|" + action + "|" + result + "|" + detail + "|" + lastAuditHash;
        String integrityHash = cryptoService.digest(material);
        auditEntries.add(new AuditEntry(now, userId, userEmail, action, result, detail, lastAuditHash, integrityHash));
        lastAuditHash = integrityHash;
    }

    private String normalizeEmail(String email) {
        return email == null ? "" : email.trim().toLowerCase();
    }

    private String normalizeCpf(String cpf) {
        return cpf == null ? "" : cpf.replaceAll("\\D", "");
    }

    private void persistProtectedState() {
        protectedStorageService.storeEncryptedUserSnapshot(usersByEmail.values());
        protectedStorageService.storeEncryptedAuditSnapshot(auditEntries);
    }

    private Map<String, Object> buildPersonalDataMap(UserAccount account) {
        Map<String, Object> exportMap = new LinkedHashMap<>();
        exportMap.put("id", account.getId());
        exportMap.put("name", account.getName());
        exportMap.put("email", account.getEmail());
        exportMap.put("cpf", account.getCpf());
        exportMap.put("age", account.getAge());
        exportMap.put("role", account.getRole().name());
        exportMap.put("accessLevel", account.getAccessLevel().name());
        exportMap.put("linkedPatientEmail", account.getLinkedPatientEmail());
        exportMap.put("medications", account.getMedications());
        exportMap.put("consentSigned", account.isConsentSigned());
        exportMap.put("consentVersion", account.getConsentVersion());
        exportMap.put("consentPurpose", account.getConsentPurpose());
        exportMap.put("consentSignedAt", account.getConsentSignedAt());
        exportMap.put("consentRevokedAt", account.getConsentRevokedAt());
        exportMap.put("createdAt", account.getCreatedAt());
        exportMap.put("knownDevices", account.getKnownDevices().size());
        exportMap.put("auditEntries", auditEntries.stream()
                .filter(entry -> entry.userId().equals(account.getId()))
                .toList());
        return exportMap;
    }

    private String toPrettyJson(Object payload) {
        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(payload);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Falha ao serializar exportacao de dados.", exception);
        }
    }

    private String abbreviate(String value) {
        return value.length() <= 12 ? value : value.substring(0, 12) + "...";
    }

    private String sanitizeFilePart(String value) {
        return value.replaceAll("[^a-zA-Z0-9.-]", "_");
    }

    public record LoginChallenge(String twoFactorCode, String expiresAt) {
    }

    public record PasswordResetView(String token, String expiresAt) {
    }

    public record RegistrationResult(String errorMessage, String caregiverInviteToken) {

        public static RegistrationResult error(String errorMessage) {
            return new RegistrationResult(errorMessage, null);
        }

        public static RegistrationResult success(String caregiverInviteToken) {
            return new RegistrationResult(null, caregiverInviteToken);
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

    public record MedicationView(
            String medicationName,
            String dose,
            String frequency,
            String scheduledAt,
            String registeredByEmail,
            String createdAt
    ) {
    }

    private static final class MessageDigestFacade {

        private MessageDigestFacade() {
        }

        private static boolean equals(String left, String right) {
            return java.security.MessageDigest.isEqual(
                    left.getBytes(StandardCharsets.UTF_8),
                    right.getBytes(StandardCharsets.UTF_8)
            );
        }
    }
}
