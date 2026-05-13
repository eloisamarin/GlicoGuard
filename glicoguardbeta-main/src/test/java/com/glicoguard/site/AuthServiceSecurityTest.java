package com.glicoguard.site;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import com.glicoguard.site.model.AccessLevel;
import com.glicoguard.site.model.UserAccount;
import com.glicoguard.site.model.UserRole;
import com.glicoguard.site.service.AuthService;
import com.glicoguard.site.service.CryptoService;
import com.glicoguard.site.service.EmailService;
import com.glicoguard.site.service.ProtectedStorageService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AuthServiceSecurityTest {

    private AuthService authService;
    private CryptoService cryptoService;
    private EmailService emailService;

    @BeforeEach
    void setUp() {
        cryptoService = new CryptoService(120000, 256);
        ProtectedStorageService storageService = new ProtectedStorageService(cryptoService);
        emailService = new EmailService();
        authService = new AuthService(
                cryptoService,
                storageService,
                emailService,
                5,
                15,
                5,
                10,
                "2026.1",
                "Tratamento de dados de autenticacao, saude e seguranca para operacao do GlicoGuard"
        );
    }

    @Test
    void shouldGenerateDifferentSaltAndHashForDistinctUsers() {
        authService.register("Alice", "alice@glicoguard.com", "12345678901", LocalDate.of(1998, 3, 10), "SenhaSegura123", UserRole.PACIENTE, AccessLevel.EDICAO, null);
        authService.register("Bruno", "bruno@glicoguard.com", "12345678902", LocalDate.of(1990, 8, 22), "SenhaSegura123", UserRole.PACIENTE, AccessLevel.EDICAO, null);

        UserAccount alice = authService.findByEmail("alice@glicoguard.com").orElseThrow();
        UserAccount bruno = authService.findByEmail("bruno@glicoguard.com").orElseThrow();

        assertNotEquals(alice.getPasswordSalt(), bruno.getPasswordSalt());
        assertNotEquals(alice.getPasswordHash(), bruno.getPasswordHash());
        assertTrue(cryptoService.matchesPassword("SenhaSegura123", alice.getPasswordHash(), alice.getPasswordSalt()));
    }

    @Test
    void shouldRequireTwoFactorAfterPrimaryAuthentication() {
        authService.register("Carla", "carla@glicoguard.com", "12345678903", LocalDate.of(1984, 5, 12), "SenhaSegura123", UserRole.PACIENTE, AccessLevel.EDICAO, null);

        authService.startPrimaryAuthentication(
                "carla@glicoguard.com",
                "SenhaSegura123",
                "browser-a",
                "127.0.0.1"
        );

        String code = extractLatestCodeFromEmail("carla@glicoguard.com", "Codigo de verificacao");

        Optional<UserAccount> wrongCode = authService.completeTwoFactorAuthentication(
                "carla@glicoguard.com",
                "AAAAAA",
                "browser-a",
                "127.0.0.1"
        );
        assertTrue(wrongCode.isEmpty());

        Optional<UserAccount> validCode = authService.completeTwoFactorAuthentication(
                "carla@glicoguard.com",
                code,
                "browser-a",
                "127.0.0.1"
        );
        assertTrue(validCode.isPresent());
        assertEquals(6, code.length());
    }

    @Test
    void shouldLockAccountAfterRepeatedFailedAttempts() {
        authService.register("Diego", "diego@glicoguard.com", "12345678904", LocalDate.of(1993, 9, 14), "SenhaSegura123", UserRole.PACIENTE, AccessLevel.EDICAO, null);

        for (int i = 0; i < 5; i++) {
            assertThrows(IllegalArgumentException.class, () ->
                    authService.startPrimaryAuthentication("diego@glicoguard.com", "senha-errada", "browser-b", "127.0.0.1"));
        }

        IllegalArgumentException blocked = assertThrows(IllegalArgumentException.class, () ->
                authService.startPrimaryAuthentication("diego@glicoguard.com", "SenhaSegura123", "browser-b", "127.0.0.1"));

        assertTrue(blocked.getMessage().contains("bloqueada"));
    }

    @Test
    void shouldInvalidateRecoveryTokenAfterSuccessfulUse() {
        authService.register("Eva", "eva@glicoguard.com", "12345678905", LocalDate.of(2000, 2, 20), "SenhaSegura123", UserRole.PACIENTE, AccessLevel.EDICAO, null);

        AuthService.PasswordResetView resetView = authService.createPasswordReset("eva@glicoguard.com");
        String emailedToken = extractLatestCodeFromEmail("eva@glicoguard.com", "Token de recuperacao");
        assertEquals(resetView.token(), emailedToken);
        authService.resetPassword("eva@glicoguard.com", resetView.token(), "NovaSenha123");

        IllegalArgumentException reuseError = assertThrows(IllegalArgumentException.class, () ->
                authService.resetPassword("eva@glicoguard.com", resetView.token(), "OutraSenha123"));

        assertTrue(reuseError.getMessage().contains("Solicite um token"));

        authService.startPrimaryAuthentication(
                "eva@glicoguard.com",
                "NovaSenha123",
                "browser-c",
                "127.0.0.1"
        );
        String code = extractLatestCodeFromEmail("eva@glicoguard.com", "Codigo de verificacao");
        Optional<UserAccount> authenticated = authService.completeTwoFactorAuthentication(
                "eva@glicoguard.com",
                code,
                "browser-c",
                "127.0.0.1"
        );
        assertTrue(authenticated.isPresent());
    }

    @Test
    void shouldDeleteUserDataUponOwnerRequest() {
        authService.register("Fabio", "fabio@glicoguard.com", "12345678906", LocalDate.of(1988, 7, 1), "SenhaSegura123", UserRole.PACIENTE, AccessLevel.EDICAO, null);
        UserAccount account = authService.findByEmail("fabio@glicoguard.com").orElseThrow();

        authService.deleteUser(account);

        assertEquals(Optional.empty(), authService.findByEmail("fabio@glicoguard.com"));
        assertFalse(authService.getAllUsers().stream().anyMatch(user -> user.getEmail().equals("fabio@glicoguard.com")));
    }

    @Test
    void shouldLinkCaregiverToPatientUsingSixCharacterInviteCode() {
        authService.register(
                "Paciente",
                "paciente@glicoguard.com",
                "12345678907",
                LocalDate.of(1971, 10, 15),
                "SenhaSegura123",
                UserRole.PACIENTE,
                AccessLevel.EDICAO,
                null
        );

        String inviteCode = extractLatestCodeFromEmail("paciente@glicoguard.com", "Codigo para vincular cuidador");

        AuthService.RegistrationResult caregiverRegistration = authService.register(
                "Cuidadora",
                "cuidadora@glicoguard.com",
                "12345678908",
                LocalDate.of(1978, 6, 3),
                "SenhaSegura123",
                UserRole.CUIDADOR,
                AccessLevel.SOMENTE_LEITURA,
                inviteCode
        );

        assertEquals(null, caregiverRegistration.errorMessage());
        assertEquals(6, inviteCode.length());
        UserAccount caregiver = authService.findByEmail("cuidadora@glicoguard.com").orElseThrow();
        UserAccount patient = authService.findByEmail("paciente@glicoguard.com").orElseThrow();
        assertEquals("paciente@glicoguard.com", caregiver.getLinkedPatientEmail());
        assertEquals(null, patient.getCaregiverInviteTokenHash());
        assertEquals(null, patient.getCaregiverInviteTokenExpiresAt());
    }

    @Test
    void shouldRejectReusedCaregiverInviteToken() {
        authService.register(
                "Paciente Reuso",
                "paciente.reuso@glicoguard.com",
                "12345678909",
                LocalDate.of(1975, 4, 9),
                "SenhaSegura123",
                UserRole.PACIENTE,
                AccessLevel.EDICAO,
                null
        );

        String inviteCode = extractLatestCodeFromEmail("paciente.reuso@glicoguard.com", "Codigo para vincular cuidador");

        authService.register(
                "Cuidador 1",
                "cuidador1@glicoguard.com",
                "12345678910",
                LocalDate.of(1986, 8, 8),
                "SenhaSegura123",
                UserRole.CUIDADOR,
                AccessLevel.SOMENTE_LEITURA,
                inviteCode
        );

        AuthService.RegistrationResult reusedTokenAttempt = authService.register(
                "Cuidador 2",
                "cuidador2@glicoguard.com",
                "12345678911",
                LocalDate.of(1985, 5, 8),
                "SenhaSegura123",
                UserRole.CUIDADOR,
                AccessLevel.SOMENTE_LEITURA,
                inviteCode
        );

        assertEquals("Codigo de vinculacao invalido ou expirado.", reusedTokenAttempt.errorMessage());
    }

    @Test
    void shouldAllowPatientToRegisterOwnMedication() {
        authService.register("Helena", "helena@glicoguard.com", "12345678912", LocalDate.of(1992, 12, 12), "SenhaSegura123", UserRole.PACIENTE, AccessLevel.EDICAO, null);
        UserAccount patient = authService.findByEmail("helena@glicoguard.com").orElseThrow();

        authService.registerMedication(
                patient,
                "Insulina",
                "12 UI",
                "2 vezes ao dia",
                LocalDateTime.of(2026, 4, 28, 8, 30)
        );

        assertEquals(1, patient.getMedications().size());
        assertEquals("Insulina", patient.getMedications().get(0).getMedicationName());
        assertEquals("helena@glicoguard.com", patient.getMedications().get(0).getRegisteredByEmail());
    }

    @Test
    void shouldAllowLinkedCaregiverToRegisterMedicationForPatient() {
        authService.register(
                "Paciente Medicacao",
                "paciente.medicacao@glicoguard.com",
                "12345678913",
                LocalDate.of(1964, 1, 30),
                "SenhaSegura123",
                UserRole.PACIENTE,
                AccessLevel.EDICAO,
                null
        );
        String inviteCode = extractLatestCodeFromEmail("paciente.medicacao@glicoguard.com", "Codigo para vincular cuidador");
        authService.register(
                "Cuidadora Medicacao",
                "cuidadora.medicacao@glicoguard.com",
                "12345678914",
                LocalDate.of(1981, 3, 14),
                "SenhaSegura123",
                UserRole.CUIDADOR,
                AccessLevel.SOMENTE_LEITURA,
                inviteCode
        );

        UserAccount caregiver = authService.findByEmail("cuidadora.medicacao@glicoguard.com").orElseThrow();
        UserAccount patient = authService.findByEmail("paciente.medicacao@glicoguard.com").orElseThrow();

        authService.registerMedication(
                caregiver,
                "Metformina",
                "850 mg",
                "1 vez apos o jantar",
                LocalDateTime.of(2026, 4, 28, 19, 0)
        );

        assertEquals(1, patient.getMedications().size());
        assertEquals("Metformina", patient.getMedications().get(0).getMedicationName());
        assertEquals("cuidadora.medicacao@glicoguard.com", patient.getMedications().get(0).getRegisteredByEmail());
    }

    @Test
    void shouldRejectMedicationRegistrationForUnauthorizedUser() {
        UserAccount admin = authService.findByEmail("admin@glicoguard.com").orElseThrow();

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class, () ->
                authService.registerMedication(
                        admin,
                        "Losartana",
                        "50 mg",
                        "1 vez ao dia",
                        LocalDateTime.of(2026, 4, 28, 9, 0)
                ));

        assertEquals("Apenas paciente ou cuidador vinculado podem registrar medicamentos.", error.getMessage());
    }

    @Test
    void shouldShowAllLogsOnlyForAdministrator() {
        authService.register("Iris", "iris@glicoguard.com", "12345678916", LocalDate.of(1991, 11, 5), "SenhaSegura123", UserRole.PACIENTE, AccessLevel.EDICAO, null);
        UserAccount admin = authService.findByEmail("admin@glicoguard.com").orElseThrow();
        UserAccount iris = authService.findByEmail("iris@glicoguard.com").orElseThrow();

        List<AuthService.AuditEntryView> adminView = authService.buildAuditView(admin);
        List<AuthService.AuditEntryView> irisView = authService.buildAuditView(iris);

        assertTrue(adminView.size() > irisView.size());
        assertTrue(irisView.stream().allMatch(entry -> entry.userEmail().equals("iris@glicoguard.com")));
    }

    @Test
    void shouldAllowAdministratorToBlockAndUnblockUser() {
        authService.register("Joao", "joao@glicoguard.com", "12345678917", LocalDate.of(1994, 4, 12), "SenhaSegura123", UserRole.PACIENTE, AccessLevel.EDICAO, null);
        UserAccount admin = authService.findByEmail("admin@glicoguard.com").orElseThrow();

        authService.blockUserByAdministrator(admin, "joao@glicoguard.com");

        IllegalArgumentException blocked = assertThrows(IllegalArgumentException.class, () ->
                authService.startPrimaryAuthentication("joao@glicoguard.com", "SenhaSegura123", "browser-z", "127.0.0.1"));
        assertTrue(blocked.getMessage().contains("bloqueada"));

        authService.unblockUserByAdministrator(admin, "joao@glicoguard.com");
        authService.startPrimaryAuthentication("joao@glicoguard.com", "SenhaSegura123", "browser-z", "127.0.0.1");
    }

    private String extractLatestCodeFromEmail(String email, String subjectFragment) {
        return emailService.buildEmailView().stream()
                .filter(view -> view.to().equalsIgnoreCase(email))
                .filter(view -> view.subject().contains(subjectFragment))
                .findFirst()
                .map(view -> view.body().lines().findFirst().orElseThrow())
                .map(line -> line.substring(line.lastIndexOf(' ') + 1))
                .orElseThrow();
    }
}
