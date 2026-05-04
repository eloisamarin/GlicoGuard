package com.glicoguard.site;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.LocalDateTime;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AuthServiceSecurityTest {

    private AuthService authService;
    private CryptoService cryptoService;

    @BeforeEach
    void setUp() {
        cryptoService = new CryptoService(120000, 256);
        ProtectedStorageService storageService = new ProtectedStorageService(cryptoService);
        authService = new AuthService(
                cryptoService,
                storageService,
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
        authService.register("Alice", "alice@glicoguard.com", "12345678901", 28, "SenhaSegura123", UserRole.PACIENTE, AccessLevel.EDICAO, null);
        authService.register("Bruno", "bruno@glicoguard.com", "12345678902", 35, "SenhaSegura123", UserRole.PACIENTE, AccessLevel.EDICAO, null);

        UserAccount alice = authService.findByEmail("alice@glicoguard.com").orElseThrow();
        UserAccount bruno = authService.findByEmail("bruno@glicoguard.com").orElseThrow();

        assertNotEquals(alice.getPasswordSalt(), bruno.getPasswordSalt());
        assertNotEquals(alice.getPasswordHash(), bruno.getPasswordHash());
        assertTrue(cryptoService.matchesPassword("SenhaSegura123", alice.getPasswordHash(), alice.getPasswordSalt()));
    }

    @Test
    void shouldRequireTwoFactorAfterPrimaryAuthentication() {
        authService.register("Carla", "carla@glicoguard.com", "12345678903", 42, "SenhaSegura123", UserRole.PACIENTE, AccessLevel.EDICAO, null);

        AuthService.LoginChallenge challenge = authService.startPrimaryAuthentication(
                "carla@glicoguard.com",
                "SenhaSegura123",
                "browser-a",
                "127.0.0.1"
        );

        Optional<UserAccount> wrongCode = authService.completeTwoFactorAuthentication(
                "carla@glicoguard.com",
                "000000",
                "browser-a",
                "127.0.0.1"
        );
        assertTrue(wrongCode.isEmpty());

        Optional<UserAccount> validCode = authService.completeTwoFactorAuthentication(
                "carla@glicoguard.com",
                challenge.twoFactorCode(),
                "browser-a",
                "127.0.0.1"
        );
        assertTrue(validCode.isPresent());
    }

    @Test
    void shouldLockAccountAfterRepeatedFailedAttempts() {
        authService.register("Diego", "diego@glicoguard.com", "12345678904", 31, "SenhaSegura123", UserRole.PACIENTE, AccessLevel.EDICAO, null);

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
        authService.register("Eva", "eva@glicoguard.com", "12345678905", 26, "SenhaSegura123", UserRole.PACIENTE, AccessLevel.EDICAO, null);

        AuthService.PasswordResetView resetView = authService.createPasswordReset("eva@glicoguard.com");
        authService.resetPassword("eva@glicoguard.com", resetView.token(), "NovaSenha123");

        IllegalArgumentException reuseError = assertThrows(IllegalArgumentException.class, () ->
                authService.resetPassword("eva@glicoguard.com", resetView.token(), "OutraSenha123"));

        assertTrue(reuseError.getMessage().contains("Solicite um token"));

        AuthService.LoginChallenge challenge = authService.startPrimaryAuthentication(
                "eva@glicoguard.com",
                "NovaSenha123",
                "browser-c",
                "127.0.0.1"
        );
        Optional<UserAccount> authenticated = authService.completeTwoFactorAuthentication(
                "eva@glicoguard.com",
                challenge.twoFactorCode(),
                "browser-c",
                "127.0.0.1"
        );
        assertTrue(authenticated.isPresent());
    }

    @Test
    void shouldDeleteUserDataUponOwnerRequest() {
        authService.register("Fabio", "fabio@glicoguard.com", "12345678906", 38, "SenhaSegura123", UserRole.PACIENTE, AccessLevel.EDICAO, null);
        UserAccount account = authService.findByEmail("fabio@glicoguard.com").orElseThrow();

        authService.deleteUser(account);

        assertEquals(Optional.empty(), authService.findByEmail("fabio@glicoguard.com"));
        assertFalse(authService.getAllUsers().stream().anyMatch(user -> user.getEmail().equals("fabio@glicoguard.com")));
    }

    @Test
    void shouldLinkCaregiverToPatientUsingInviteToken() {
        AuthService.RegistrationResult patientRegistration = authService.register(
                "Paciente",
                "paciente@glicoguard.com",
                "12345678907",
                54,
                "SenhaSegura123",
                UserRole.PACIENTE,
                AccessLevel.EDICAO,
                null
        );

        assertEquals(null, patientRegistration.errorMessage());
        assertTrue(patientRegistration.caregiverInviteToken() != null && !patientRegistration.caregiverInviteToken().isBlank());

        AuthService.RegistrationResult caregiverRegistration = authService.register(
                "Cuidadora",
                "cuidadora@glicoguard.com",
                "12345678908",
                47,
                "SenhaSegura123",
                UserRole.CUIDADOR,
                AccessLevel.SOMENTE_LEITURA,
                patientRegistration.caregiverInviteToken()
        );

        assertEquals(null, caregiverRegistration.errorMessage());
        UserAccount caregiver = authService.findByEmail("cuidadora@glicoguard.com").orElseThrow();
        UserAccount patient = authService.findByEmail("paciente@glicoguard.com").orElseThrow();
        assertEquals("paciente@glicoguard.com", caregiver.getLinkedPatientEmail());
        assertEquals(null, patient.getCaregiverInviteTokenHash());
        assertEquals(null, patient.getCaregiverInviteTokenExpiresAt());
    }

    @Test
    void shouldRejectReusedCaregiverInviteToken() {
        AuthService.RegistrationResult patientRegistration = authService.register(
                "Paciente Reuso",
                "paciente.reuso@glicoguard.com",
                "12345678909",
                51,
                "SenhaSegura123",
                UserRole.PACIENTE,
                AccessLevel.EDICAO,
                null
        );

        authService.register(
                "Cuidador 1",
                "cuidador1@glicoguard.com",
                "12345678910",
                39,
                "SenhaSegura123",
                UserRole.CUIDADOR,
                AccessLevel.SOMENTE_LEITURA,
                patientRegistration.caregiverInviteToken()
        );

        AuthService.RegistrationResult reusedTokenAttempt = authService.register(
                "Cuidador 2",
                "cuidador2@glicoguard.com",
                "12345678911",
                40,
                "SenhaSegura123",
                UserRole.CUIDADOR,
                AccessLevel.SOMENTE_LEITURA,
                patientRegistration.caregiverInviteToken()
        );

        assertEquals("Token de vinculacao invalido ou expirado.", reusedTokenAttempt.errorMessage());
    }

    @Test
    void shouldAllowPatientToRegisterOwnMedication() {
        authService.register("Helena", "helena@glicoguard.com", "12345678912", 33, "SenhaSegura123", UserRole.PACIENTE, AccessLevel.EDICAO, null);
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
        AuthService.RegistrationResult patientRegistration = authService.register(
                "Paciente Medicacao",
                "paciente.medicacao@glicoguard.com",
                "12345678913",
                62,
                "SenhaSegura123",
                UserRole.PACIENTE,
                AccessLevel.EDICAO,
                null
        );
        authService.register(
                "Cuidadora Medicacao",
                "cuidadora.medicacao@glicoguard.com",
                "12345678914",
                44,
                "SenhaSegura123",
                UserRole.CUIDADOR,
                AccessLevel.SOMENTE_LEITURA,
                patientRegistration.caregiverInviteToken()
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
        authService.register(
                "Cuidador Solto",
                "cuidador.solto@glicoguard.com",
                "12345678915",
                37,
                "SenhaSegura123",
                UserRole.PACIENTE,
                AccessLevel.EDICAO,
                null
        );
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
}
