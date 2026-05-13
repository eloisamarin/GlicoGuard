package com.glicoguard.site.service;

import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.List;

import com.glicoguard.site.model.MedicationEntry;
import com.glicoguard.site.model.UserAccount;
import com.glicoguard.site.model.UserRole;
import com.glicoguard.site.repository.UserStore;
import com.glicoguard.site.util.FormatSupport;

final class MedicationService {

    private final UserStore store;

    MedicationService(UserStore store) {
        this.store = store;
    }

    void registerMedication(UserAccount actor,
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
        store.addAudit(actor, "Registro de medicamento", "SUCESSO", detail);
        store.persist();
    }

    List<AuthService.MedicationView> buildMedicationView(UserAccount actor) {
        UserAccount targetPatient = resolveMedicationTargetOrNull(actor);
        if (targetPatient == null) {
            return List.of();
        }
        return targetPatient.getMedications().stream()
                .sorted(Comparator.comparing(MedicationEntry::getScheduledAt).reversed())
                .map(entry -> new AuthService.MedicationView(
                        entry.getMedicationName(),
                        entry.getDose(),
                        entry.getFrequency(),
                        FormatSupport.formatDateTime(entry.getScheduledAt()),
                        entry.getRegisteredByEmail(),
                        FormatSupport.formatDateTime(entry.getCreatedAt())
                ))
                .toList();
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
            return store.getByEmail(actor.getLinkedPatientEmail().toLowerCase());
        }
        return null;
    }
}
