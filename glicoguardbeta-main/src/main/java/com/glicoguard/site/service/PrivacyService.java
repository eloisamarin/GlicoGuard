package com.glicoguard.site.service;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.glicoguard.site.model.UserAccount;
import com.glicoguard.site.model.UserRole;
import com.glicoguard.site.repository.UserStore;
import com.glicoguard.site.util.FormatSupport;
import com.glicoguard.site.util.SecuritySupport;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

final class PrivacyService {

    private final UserStore store;
    private final ProtectedStorageService protectedStorageService;
    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
    private final String consentVersion;
    private final String consentPurpose;

    PrivacyService(UserStore store,
                   ProtectedStorageService protectedStorageService,
                   String consentVersion,
                   String consentPurpose) {
        this.store = store;
        this.protectedStorageService = protectedStorageService;
        this.consentVersion = consentVersion;
        this.consentPurpose = consentPurpose;
    }

    void signConsent(UserAccount account) {
        account.setConsentSigned(true);
        account.setConsentVersion(consentVersion);
        account.setConsentPurpose(consentPurpose);
        account.setConsentSignedAt(LocalDateTime.now());
        account.setConsentRevokedAt(null);
        store.addAudit(account, "Consentimento LGPD", "SUCESSO", "Consentimento registrado com finalidade explicita.");
        store.persist();
    }

    void revokeConsent(UserAccount account) {
        account.setConsentSigned(false);
        account.setConsentRevokedAt(LocalDateTime.now());
        store.addAudit(account, "Revogacao de consentimento", "SUCESSO", "Titular revogou o consentimento anteriormente concedido.");
        store.persist();
    }

    ResponseEntity<byte[]> exportUserData(UserAccount account) {
        Map<String, Object> exportMap = buildPersonalDataMap(account);
        byte[] jsonBytes = toPrettyJson(exportMap).getBytes(StandardCharsets.UTF_8);
        protectedStorageService.storeEncryptedExport("export-" + SecuritySupport.sanitizeFilePart(account.getEmail()) + ".enc", exportMap);
        store.addAudit(account, "Exportacao de dados", "SUCESSO", "Titular exportou os dados pessoais em JSON.");
        store.persist();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename("dados-" + SecuritySupport.sanitizeFilePart(account.getEmail()) + ".json")
                .build());
        return ResponseEntity.ok().headers(headers).body(jsonBytes);
    }

    List<AuthService.CollectedDataView> buildCollectedDataView(UserAccount account) {
        List<AuthService.CollectedDataView> data = new ArrayList<>();
        data.add(new AuthService.CollectedDataView("Nome completo", account.getName(), "Identificar o titular e personalizar o painel."));
        data.add(new AuthService.CollectedDataView("E-mail", account.getEmail(), "Realizar login, 2FA, notificacoes e recuperacao de senha."));
        data.add(new AuthService.CollectedDataView("CPF", account.getCpf(), "Identificacao civil minima do titular para cadastro."));
        data.add(new AuthService.CollectedDataView("Data de nascimento", FormatSupport.formatDate(account.getBirthDate()), "Apoiar identificacao do perfil de cuidado e dados cadastrais."));
        data.add(new AuthService.CollectedDataView("Perfil de acesso", account.getRole().name(), "Aplicar regras de autorizacao entre paciente, cuidador e administrador."));
        data.add(new AuthService.CollectedDataView("Nivel de acesso", account.getAccessLevel().name(), "Definir permissao de leitura ou edicao."));
        data.add(new AuthService.CollectedDataView("Vinculo de cuidado", account.getLinkedPatientEmail() != null ? account.getLinkedPatientEmail() : "Nao aplicavel", "Associar um cuidador ao paciente acompanhado."));
        data.add(new AuthService.CollectedDataView("Medicamentos registrados", String.valueOf(account.getMedications().size()), "Registrar nome, dose, frequencia e horario do tratamento informado."));
        data.add(new AuthService.CollectedDataView("Consentimento", account.isConsentSigned() ? "Assinado" : "Nao assinado", "Registrar base legal e finalidade do tratamento."));
        data.add(new AuthService.CollectedDataView("Metadados de seguranca", "Dispositivos, tentativas e logs", "Detectar fraude, forca bruta e auditar operacoes."));
        return data;
    }

    List<AuthService.PrivacyExplanationView> buildPrivacyExplanations(UserAccount account) {
        List<AuthService.PrivacyExplanationView> explanations = new ArrayList<>();
        explanations.add(new AuthService.PrivacyExplanationView(
                "Por que pedimos seus dados cadastrais",
                "Nome, CPF, data de nascimento e e-mail sao os dados minimos para identificar o titular da conta, evitar duplicidade de cadastro e manter um perfil correto de paciente, cuidador ou administrador.",
                "O codigo valida e armazena essas informacoes no momento do cadastro e usa esses campos para autenticacao, vinculacao de cuidador e exportacao dos dados."
        ));
        explanations.add(new AuthService.PrivacyExplanationView(
                "Por que usamos dados de seguranca",
                "O sistema precisa proteger a conta contra acessos indevidos. Por isso ele registra tentativas de login, bloqueios temporarios, codigos 2FA, recuperacao de senha e dispositivos conhecidos.",
                "No codigo, a senha nunca fica em texto puro. Ela e protegida com hash PBKDF2 e salt unico. Os eventos de seguranca sao registrados em logs de auditoria com hash encadeado."
        ));
        explanations.add(new AuthService.PrivacyExplanationView(
                "Por que usamos dados de cuidado e medicacao",
                "Medicamentos, doses, frequencias e horarios permitem acompanhar o tratamento do paciente e dar suporte ao cuidador vinculado.",
                "O codigo permite que o paciente gerencie seus proprios registros e que o cuidador vinculado registre informacoes somente para o paciente associado."
        ));
        explanations.add(new AuthService.PrivacyExplanationView(
                "Como a LGPD e atendida",
                "O titular consegue consultar os dados coletados, entender a finalidade, exportar as informacoes, revogar o consentimento e pedir exclusao da conta.",
                "Esses fluxos existem no proprio sistema por meio das rotas de privacidade, exportacao e exclusao de dados, com registro de auditoria para evidenciar cada acao."
        ));
        if (account.getRole() == UserRole.CUIDADOR) {
            explanations.add(new AuthService.PrivacyExplanationView(
                    "Por que existe o vinculo com o paciente",
                    "O vinculo e necessario para limitar o cuidado a uma pessoa especifica e impedir acesso indevido a outros pacientes.",
                    "O codigo exige um token temporario para conectar cuidador e paciente e remove esse token depois do uso."
            ));
        }
        return explanations;
    }

    List<String> buildDataSubjectRights() {
        return List.of(
                "Consultar quais dados pessoais foram coletados e para qual finalidade.",
                "Exportar uma copia estruturada dos seus dados diretamente pelo sistema.",
                "Revogar o consentimento registrado quando desejar.",
                "Solicitar a exclusao da conta e dos dados pessoais armazenados.",
                "Saber quais controles de seguranca protegem sua conta e seus registros."
        );
    }

    AuthService.ConsentDocumentView buildConsentDocumentView(UserAccount account) {
        String status = account.isConsentSigned() ? "Concordou com os termos" : "Ainda nao concordou ou revogou os termos";
        String signedAt = account.getConsentSignedAt() != null
                ? FormatSupport.formatDateTime(account.getConsentSignedAt())
                : "Nao registrado";
        String revokedAt = account.getConsentRevokedAt() != null
                ? FormatSupport.formatDateTime(account.getConsentRevokedAt())
                : "Nao revogado";
        String statement = "Eu, " + account.getName()
                + ", titular da conta vinculada ao e-mail " + account.getEmail()
                + ", declaro que li e compreendi o tratamento dos meus dados pessoais no GlicoGuard. "
                + "Estou ciente de que os dados coletados sao usados para autenticacao, seguranca da conta, "
                + "registro de medicamentos, vinculacao entre paciente e cuidador e atendimento aos direitos previstos na LGPD.";
        return new AuthService.ConsentDocumentView(
                "Termo de Privacidade e Consentimento LGPD",
                consentVersion,
                consentPurpose,
                status,
                signedAt,
                revokedAt,
                statement
        );
    }

    List<String> describeProtectedAssets() {
        return protectedStorageService.describeProtectedAssets();
    }

    private Map<String, Object> buildPersonalDataMap(UserAccount account) {
        Map<String, Object> exportMap = new LinkedHashMap<>();
        exportMap.put("id", account.getId());
        exportMap.put("name", account.getName());
        exportMap.put("email", account.getEmail());
        exportMap.put("cpf", account.getCpf());
        exportMap.put("birthDate", account.getBirthDate());
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
        exportMap.put("auditEntries", store.auditEntries().stream()
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
}
