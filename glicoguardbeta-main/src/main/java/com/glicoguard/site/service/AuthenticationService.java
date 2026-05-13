package com.glicoguard.site.service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.Period;
import java.util.Optional;

import com.glicoguard.site.model.AccessLevel;
import com.glicoguard.site.model.UserAccount;
import com.glicoguard.site.model.UserRole;
import com.glicoguard.site.repository.UserStore;
import com.glicoguard.site.util.FormatSupport;
import com.glicoguard.site.util.SecuritySupport;

final class AuthenticationService {

    private static final int CAREGIVER_INVITE_EXPIRATION_DAYS = 7;

    private final UserStore store;
    private final CryptoService cryptoService;
    private final EmailService emailService;
    private final int maxAttempts;
    private final int lockMinutes;
    private final int twoFactorExpirationMinutes;
    private final int resetExpirationMinutes;

    AuthenticationService(UserStore store,
                          CryptoService cryptoService,
                          EmailService emailService,
                          int maxAttempts,
                          int lockMinutes,
                          int twoFactorExpirationMinutes,
                          int resetExpirationMinutes) {
        this.store = store;
        this.cryptoService = cryptoService;
        this.emailService = emailService;
        this.maxAttempts = maxAttempts;
        this.lockMinutes = lockMinutes;
        this.twoFactorExpirationMinutes = twoFactorExpirationMinutes;
        this.resetExpirationMinutes = resetExpirationMinutes;
    }

    AuthService.RegistrationResult register(String name,
                                            String email,
                                            String cpf,
                                            LocalDate birthDate,
                                            String password,
                                            UserRole role,
                                            AccessLevel accessLevel,
                                            String caregiverInviteToken) {
        String normalizedEmail = SecuritySupport.normalizeEmail(email);
        if (store.containsEmail(normalizedEmail)) {
            return AuthService.RegistrationResult.error("Ja existe um usuario com este e-mail.");
        }

        String normalizedCpf = SecuritySupport.normalizeCpf(cpf);
        if (normalizedCpf.length() != 11) {
            return AuthService.RegistrationResult.error("Informe um CPF com 11 digitos.");
        }
        if (birthDate == null || birthDate.isAfter(LocalDate.now())) {
            return AuthService.RegistrationResult.error("Informe uma data de nascimento valida.");
        }
        int age = Period.between(birthDate, LocalDate.now()).getYears();
        if (age < 0 || age > 120) {
            return AuthService.RegistrationResult.error("Informe uma data de nascimento valida.");
        }
        if (store.allUsers().stream().anyMatch(user -> user.getCpf().equals(normalizedCpf))) {
            return AuthService.RegistrationResult.error("Ja existe um usuario com este CPF.");
        }

        String caregiverLink = null;
        if (role == UserRole.CUIDADOR) {
            if (caregiverInviteToken == null || caregiverInviteToken.isBlank()) {
                return AuthService.RegistrationResult.error("Para cuidador, informe o codigo de vinculacao do paciente.");
            }
            UserAccount patient = findPatientByInviteToken(caregiverInviteToken);
            if (patient == null) {
                return AuthService.RegistrationResult.error("Codigo de vinculacao invalido ou expirado.");
            }
            caregiverLink = patient.getEmail();
        }

        CryptoService.PasswordHash passwordHash = cryptoService.createPasswordHash(password);
        UserAccount account = new UserAccount(
                name.trim(),
                normalizedEmail,
                normalizedCpf,
                birthDate,
                role,
                accessLevel,
                caregiverLink,
                passwordHash.hash(),
                passwordHash.salt()
        );
        store.saveUser(account);

        if (role == UserRole.PACIENTE) {
            createCaregiverInviteToken(account);
        }
        if (role == UserRole.CUIDADOR) {
            invalidateCaregiverInvite(caregiverLink);
        }

        String detail = role == UserRole.CUIDADOR
                ? "Conta criada com sucesso e vinculada ao paciente " + caregiverLink + "."
                : "Conta criada com sucesso.";
        store.addAudit(account, "Cadastro realizado", "SUCESSO", detail);
        store.persist();
        return AuthService.RegistrationResult.success();
    }

    AuthService.LoginChallenge startPrimaryAuthentication(String email, String password, String deviceFingerprint, String sourceIp) {
        String normalizedEmail = SecuritySupport.normalizeEmail(email);
        UserAccount account = store.getByEmail(normalizedEmail);
        if (account == null) {
            store.addAudit("desconhecido", normalizedEmail, "Login primario", "FALHA", "Usuario inexistente. Origem: " + sourceIp);
            throw new IllegalArgumentException("E-mail ou senha invalidos.");
        }

        if (account.getLockedUntil() != null && LocalDateTime.now().isBefore(account.getLockedUntil())) {
            store.addAudit(account, "Login primario", "FALHA", "Conta temporariamente bloqueada por tentativas sucessivas.");
            throw new IllegalArgumentException("Conta temporariamente bloqueada ate " + FormatSupport.formatDateTime(account.getLockedUntil()) + ".");
        }

        if (!cryptoService.matchesPassword(password, account.getPasswordHash(), account.getPasswordSalt())) {
            registerFailedAttempt(account);
            store.addAudit(account, "Login primario", "FALHA", "Senha incorreta. Origem: " + sourceIp);
            store.persist();
            throw new IllegalArgumentException("E-mail ou senha invalidos.");
        }

        account.setFailedLoginAttempts(0);
        account.setLockedUntil(null);
        String twoFactorCode = cryptoService.generateShortCode(6);
        account.setCurrentTwoFactorHash(cryptoService.digest(twoFactorCode));
        account.setCurrentTwoFactorExpiresAt(LocalDateTime.now().plusMinutes(twoFactorExpirationMinutes));
        emailService.sendEmail(
                account.getEmail(),
                "GlicoGuard - Codigo de verificacao",
                "Seu codigo de verificacao em dois fatores e: " + twoFactorCode
                        + System.lineSeparator()
                        + "Validade: " + FormatSupport.formatDateTime(account.getCurrentTwoFactorExpiresAt())
        );
        store.addAudit(account, "2FA gerado", "SUCESSO", "Codigo de 6 caracteres enviado por e-mail. Origem: " + sourceIp);
        store.persist();
        return new AuthService.LoginChallenge(FormatSupport.formatDateTime(account.getCurrentTwoFactorExpiresAt()));
    }

    Optional<UserAccount> completeTwoFactorAuthentication(String email, String twoFactorCode, String deviceFingerprint, String sourceIp) {
        String normalizedEmail = SecuritySupport.normalizeEmail(email);
        UserAccount account = store.getByEmail(normalizedEmail);
        if (account == null) {
            store.addAudit("desconhecido", normalizedEmail, "2FA", "FALHA", "Usuario inexistente. Origem: " + sourceIp);
            return Optional.empty();
        }

        if (account.getCurrentTwoFactorHash() == null || account.getCurrentTwoFactorExpiresAt() == null) {
            store.addAudit(account, "2FA", "FALHA", "Nenhum desafio 2FA ativo.");
            return Optional.empty();
        }

        if (LocalDateTime.now().isAfter(account.getCurrentTwoFactorExpiresAt())) {
            clearTwoFactor(account);
            store.addAudit(account, "2FA", "FALHA", "Codigo expirado.");
            store.persist();
            return Optional.empty();
        }

        String providedDigest = cryptoService.digest(twoFactorCode.trim().toUpperCase());
        if (!SecuritySupport.constantTimeEquals(account.getCurrentTwoFactorHash(), providedDigest)) {
            store.addAudit(account, "2FA", "FALHA", "Codigo incorreto.");
            store.persist();
            return Optional.empty();
        }

        clearTwoFactor(account);
        if (account.getKnownDevices().add(deviceFingerprint)) {
            store.addAudit(account, "Novo dispositivo detectado", "SUCESSO",
                    "Um alerta seria enviado ao e-mail " + account.getEmail() + ". Origem: " + sourceIp);
        }
        store.addAudit(account, "Login concluido", "SUCESSO", "Autenticacao primaria e 2FA concluidos.");
        store.persist();
        return Optional.of(account);
    }

    AuthService.PasswordResetView createPasswordReset(String email) {
        String normalizedEmail = SecuritySupport.normalizeEmail(email);
        UserAccount account = store.getByEmail(normalizedEmail);
        if (account == null) {
            store.addAudit("desconhecido", normalizedEmail, "Recuperacao de senha", "FALHA", "Solicitacao para usuario inexistente.");
            throw new IllegalArgumentException("Nao existe usuario cadastrado com este e-mail.");
        }

        String token = cryptoService.generateSecureToken();
        account.setPasswordResetTokenHash(cryptoService.digest(token));
        account.setPasswordResetExpiresAt(LocalDateTime.now().plusMinutes(resetExpirationMinutes));
        emailService.sendEmail(
                account.getEmail(),
                "GlicoGuard - Token de recuperacao de senha",
                "Seu token para redefinir a senha e: " + token
                        + System.lineSeparator()
                        + "Validade: " + FormatSupport.formatDateTime(account.getPasswordResetExpiresAt())
        );
        store.addAudit(account, "Recuperacao de senha", "SUCESSO", "Token criptograficamente seguro gerado para redefinicao da senha.");
        store.persist();
        return new AuthService.PasswordResetView(token, FormatSupport.formatDateTime(account.getPasswordResetExpiresAt()));
    }

    void resetPassword(String email, String token, String newPassword) {
        String normalizedEmail = SecuritySupport.normalizeEmail(email);
        UserAccount account = store.getByEmail(normalizedEmail);
        if (account == null) {
            store.addAudit("desconhecido", normalizedEmail, "Redefinicao de senha", "FALHA", "Usuario nao encontrado.");
            throw new IllegalArgumentException("Usuario nao encontrado.");
        }

        if (account.getPasswordResetTokenHash() == null || account.getPasswordResetExpiresAt() == null) {
            store.addAudit(account, "Redefinicao de senha", "FALHA", "Nenhum token de recuperacao foi solicitado.");
            throw new IllegalArgumentException("Solicite um token de recuperacao antes de redefinir a senha.");
        }

        if (LocalDateTime.now().isAfter(account.getPasswordResetExpiresAt())) {
            clearPasswordReset(account);
            store.addAudit(account, "Redefinicao de senha", "FALHA", "Token expirado.");
            store.persist();
            throw new IllegalArgumentException("O token expirou. Solicite uma nova recuperacao.");
        }

        if (!SecuritySupport.constantTimeEquals(account.getPasswordResetTokenHash(), cryptoService.digest(token.trim()))) {
            store.addAudit(account, "Redefinicao de senha", "FALHA", "Token invalido.");
            store.persist();
            throw new IllegalArgumentException("Token de recuperacao invalido.");
        }

        CryptoService.PasswordHash passwordHash = cryptoService.createPasswordHash(newPassword);
        account.setPasswordHash(passwordHash.hash());
        account.setPasswordSalt(passwordHash.salt());
        clearPasswordReset(account);
        store.addAudit(account, "Redefinicao de senha", "SUCESSO", "Senha alterada com token temporario.");
        store.persist();
    }

    void updatePassword(UserAccount account, String currentPassword, String newPassword) {
        if (!cryptoService.matchesPassword(currentPassword, account.getPasswordHash(), account.getPasswordSalt())) {
            store.addAudit(account, "Troca de senha autenticada", "FALHA", "Senha atual incorreta.");
            throw new IllegalArgumentException("A senha atual nao confere.");
        }

        CryptoService.PasswordHash passwordHash = cryptoService.createPasswordHash(newPassword);
        account.setPasswordHash(passwordHash.hash());
        account.setPasswordSalt(passwordHash.salt());
        store.addAudit(account, "Troca de senha autenticada", "SUCESSO", "Credencial alterada pelo titular autenticado.");
        store.persist();
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

    private UserAccount findPatientByInviteToken(String caregiverInviteToken) {
        String tokenDigest = cryptoService.digest(caregiverInviteToken.trim().toUpperCase());
        return store.allUsers().stream()
                .filter(user -> user.getRole() == UserRole.PACIENTE)
                .filter(user -> user.getCaregiverInviteTokenHash() != null)
                .filter(user -> user.getCaregiverInviteTokenExpiresAt() != null)
                .filter(user -> !LocalDateTime.now().isAfter(user.getCaregiverInviteTokenExpiresAt()))
                .filter(user -> SecuritySupport.constantTimeEquals(user.getCaregiverInviteTokenHash(), tokenDigest))
                .findFirst()
                .orElse(null);
    }

    private void createCaregiverInviteToken(UserAccount patientAccount) {
        String code = cryptoService.generateShortCode(6);
        patientAccount.setCaregiverInviteTokenHash(cryptoService.digest(code));
        patientAccount.setCaregiverInviteTokenExpiresAt(LocalDateTime.now().plusDays(CAREGIVER_INVITE_EXPIRATION_DAYS));
        emailService.sendEmail(
                patientAccount.getEmail(),
                "GlicoGuard - Codigo para vincular cuidador",
                "Seu codigo para vincular um cuidador e: " + code
                        + System.lineSeparator()
                        + "Validade: " + FormatSupport.formatDateTime(patientAccount.getCaregiverInviteTokenExpiresAt())
        );
        store.addAudit(patientAccount, "Codigo de vinculacao gerado", "SUCESSO",
                "Codigo de 6 caracteres enviado por e-mail para vinculacao de cuidador ate "
                        + FormatSupport.formatDateTime(patientAccount.getCaregiverInviteTokenExpiresAt()) + ".");
    }

    private void invalidateCaregiverInvite(String patientEmail) {
        UserAccount patient = store.getByEmail(patientEmail.toLowerCase());
        if (patient == null) {
            return;
        }
        patient.setCaregiverInviteTokenHash(null);
        patient.setCaregiverInviteTokenExpiresAt(null);
        store.addAudit(patient, "Codigo de vinculacao invalidado", "SUCESSO", "Codigo de vinculacao consumido por um cuidador.");
    }
}
