package com.glicoguard.site.service;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.glicoguard.site.model.AccessLevel;
import com.glicoguard.site.model.AuditEntry;
import com.glicoguard.site.model.UserAccount;
import com.glicoguard.site.model.UserRole;
import com.glicoguard.site.repository.UserStore;
import com.glicoguard.site.util.FormatSupport;
import com.glicoguard.site.util.SecuritySupport;

final class AdministrationService {

    private final UserStore store;

    AdministrationService(UserStore store) {
        this.store = store;
    }

    void updateEmail(UserAccount account, String newEmail) {
        String normalizedEmail = SecuritySupport.normalizeEmail(newEmail);
        if (!account.getEmail().equalsIgnoreCase(normalizedEmail) && store.containsEmail(normalizedEmail)) {
            throw new IllegalArgumentException("Este e-mail ja esta em uso.");
        }

        store.removeByEmail(account.getEmail().toLowerCase());
        String previousEmail = account.getEmail();
        account.setEmail(normalizedEmail);
        store.saveUser(account);
        updateReferencesForEmailChange(previousEmail, normalizedEmail);
        store.addAudit(account, "E-mail atualizado", "SUCESSO", "Novo e-mail cadastrado: " + normalizedEmail);
        store.persist();
    }

    void updateAccessLevel(UserAccount account, AccessLevel accessLevel) {
        account.setAccessLevel(accessLevel);
        store.addAudit(account, "Nivel de acesso atualizado", "SUCESSO", "Novo nivel: " + accessLevel);
        store.persist();
    }

    void deleteUser(UserAccount account) {
        store.removeByEmail(account.getEmail().toLowerCase());
        clearLinkedPatientReferences(account.getEmail());
        store.addAudit(account, "Exclusao de dados pessoais", "SUCESSO", "Conta removida mediante solicitacao do titular.");
        store.persist();
    }

    void deleteUserByAdministrator(UserAccount administrator, String targetEmail) {
        UserAccount target = store.getByEmail(SecuritySupport.normalizeEmail(targetEmail));
        if (target == null) {
            throw new IllegalArgumentException("Usuario nao encontrado para exclusao.");
        }

        store.removeByEmail(target.getEmail().toLowerCase());
        clearLinkedPatientReferences(target.getEmail());
        store.addAudit(administrator, "Exclusao administrativa", "SUCESSO", "Conta " + target.getEmail() + " removida pelo administrador.");
        store.addAudit(target, "Conta removida por administrador", "SUCESSO", "Exclusao realizada por " + administrator.getEmail() + ".");
        store.persist();
    }

    void blockUserByAdministrator(UserAccount administrator, String targetEmail) {
        UserAccount target = store.getByEmail(SecuritySupport.normalizeEmail(targetEmail));
        if (target == null) {
            throw new IllegalArgumentException("Usuario nao encontrado para bloqueio.");
        }
        target.setLockedUntil(LocalDateTime.now().plusYears(100));
        target.setFailedLoginAttempts(0);
        store.addAudit(administrator, "Bloqueio administrativo", "SUCESSO", "Conta " + target.getEmail() + " bloqueada manualmente.");
        store.addAudit(target, "Conta bloqueada por administrador", "SUCESSO", "Bloqueio realizado por " + administrator.getEmail() + ".");
        store.persist();
    }

    void unblockUserByAdministrator(UserAccount administrator, String targetEmail) {
        UserAccount target = store.getByEmail(SecuritySupport.normalizeEmail(targetEmail));
        if (target == null) {
            throw new IllegalArgumentException("Usuario nao encontrado para desbloqueio.");
        }
        target.setLockedUntil(null);
        target.setFailedLoginAttempts(0);
        store.addAudit(administrator, "Desbloqueio administrativo", "SUCESSO", "Conta " + target.getEmail() + " desbloqueada manualmente.");
        store.addAudit(target, "Conta desbloqueada por administrador", "SUCESSO", "Desbloqueio realizado por " + administrator.getEmail() + ".");
        store.persist();
    }

    Optional<UserAccount> findByEmail(String email) {
        return store.findByEmail(SecuritySupport.normalizeEmail(email));
    }

    Collection<UserAccount> getAllUsers() {
        return store.allUsers();
    }

    List<AuthService.UserSummaryView> buildUserSummaryView() {
        return store.allUsers().stream()
                .sorted(Comparator.comparing(UserAccount::getEmail))
                .map(user -> new AuthService.UserSummaryView(
                        user.getName(),
                        user.getEmail(),
                        user.getRole().name(),
                        user.getLinkedPatientEmail() != null ? user.getLinkedPatientEmail() : "Nao aplicavel",
                        describeUserStatus(user)
                ))
                .toList();
    }

    Map<String, String> buildAdministratorSummary() {
        Map<String, String> summary = new LinkedHashMap<>();
        long totalUsers = store.allUsers().size();
        long patients = store.allUsers().stream().filter(user -> user.getRole() == UserRole.PACIENTE).count();
        long caregivers = store.allUsers().stream().filter(user -> user.getRole() == UserRole.CUIDADOR).count();
        long administrators = store.allUsers().stream().filter(user -> user.getRole() == UserRole.ADMINISTRADOR).count();
        long blocked = store.allUsers().stream().filter(this::isUserBlocked).count();
        summary.put("Total de contas", String.valueOf(totalUsers));
        summary.put("Pacientes", String.valueOf(patients));
        summary.put("Cuidadores", String.valueOf(caregivers));
        summary.put("Administradores", String.valueOf(administrators));
        summary.put("Contas bloqueadas", String.valueOf(blocked));
        return summary;
    }

    List<AuthService.AuditEntryView> buildAuditView(UserAccount account) {
        return store.auditEntries().stream()
                .filter(entry -> account.getRole() == UserRole.ADMINISTRADOR || entry.userEmail().equalsIgnoreCase(account.getEmail()))
                .sorted(Comparator.comparing(AuditEntry::timestamp).reversed())
                .map(entry -> new AuthService.AuditEntryView(
                        FormatSupport.formatDateTime(entry.timestamp()),
                        entry.userEmail(),
                        entry.action(),
                        entry.result(),
                        entry.detail(),
                        abbreviate(entry.integrityHash())
                ))
                .toList();
    }

    private void clearLinkedPatientReferences(String targetEmail) {
        store.allUsers().forEach(user -> {
            if (targetEmail.equalsIgnoreCase(user.getLinkedPatientEmail())) {
                user.setLinkedPatientEmail(null);
            }
        });
    }

    private void updateReferencesForEmailChange(String previousEmail, String newEmail) {
        store.allUsers().forEach(user -> {
            if (previousEmail.equalsIgnoreCase(user.getLinkedPatientEmail())) {
                user.setLinkedPatientEmail(newEmail);
            }
        });
    }

    private String describeUserStatus(UserAccount user) {
        return isUserBlocked(user) ? "Bloqueado" : "Ativo";
    }

    private boolean isUserBlocked(UserAccount user) {
        return user.getLockedUntil() != null && LocalDateTime.now().isBefore(user.getLockedUntil());
    }

    private String abbreviate(String value) {
        return value.length() <= 12 ? value : value.substring(0, 12) + "...";
    }
}
