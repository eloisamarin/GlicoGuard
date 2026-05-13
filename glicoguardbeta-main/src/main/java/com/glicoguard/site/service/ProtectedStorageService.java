package com.glicoguard.site.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.List;

import com.glicoguard.site.model.AuditEntry;
import com.glicoguard.site.model.UserAccount;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.stereotype.Service;

@SuppressWarnings("unused")
@Service
public class ProtectedStorageService {

   
    @SuppressWarnings("unused")
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");

    private final CryptoService cryptoService;
    private final ObjectMapper objectMapper;
    private final Path protectedDirectory;

    public ProtectedStorageService(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        this.protectedDirectory = Path.of("data", "protected");
    }

    public void storeEncryptedUserSnapshot(Collection<UserAccount> users) {
        List<UserSnapshot> snapshots = users.stream()
                .map(user -> new UserSnapshot(
                        user.getId(),
                        user.getName(),
                        user.getEmail(),
                        user.getCpf(),
                        user.getBirthDate(),
                        user.getRole().name(),
                        user.getAccessLevel().name(),
                        user.getLinkedPatientEmail(),
                        user.getConsentVersion(),
                        user.getConsentPurpose(),
                        user.getConsentSignedAt(),
                        user.getConsentRevokedAt(),
                        user.getCreatedAt()
                ))
                .toList();
        writeEncryptedFile("users.enc", snapshots);
    }

    public void storeEncryptedAuditSnapshot(List<AuditEntry> entries) {
        writeEncryptedFile("audit.enc", entries);
    }

    public void storeEncryptedExport(String filename, Object payload) {
        writeEncryptedFile(filename, payload);
    }

    private void writeEncryptedFile(String filename, Object payload) {
        try {
            Files.createDirectories(protectedDirectory);
            byte[] json = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(payload);
            byte[] encrypted = cryptoService.encrypt(json);
            Files.write(protectedDirectory.resolve(filename), encrypted);
        } catch (IOException exception) {
            throw new IllegalStateException("Falha ao armazenar dados protegidos.", exception);
        }
    }

    public List<String> describeProtectedAssets() {
        return List.of(
                "data/protected/users.enc - snapshot cifrado com AES/GCM dos dados cadastrais",
                "data/protected/audit.enc - trilha de auditoria cifrada e encadeada por hash",
                "data/protected/export-<usuario>.enc - exportacao protegida dos dados do titular"
        );
    }

    public record UserSnapshot(
            String id,
            String name,
            String email,
            String cpf,
            java.time.LocalDate birthDate,
            String role,
            String accessLevel,
            String linkedPatientEmail,
            String consentVersion,
            String consentPurpose,
            java.time.LocalDateTime consentSignedAt,
            java.time.LocalDateTime consentRevokedAt,
            java.time.LocalDateTime createdAt
    ) {
    }
}
