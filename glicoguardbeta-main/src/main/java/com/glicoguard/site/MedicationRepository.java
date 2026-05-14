package com.glicoguard.site;

import org.springframework.data.jpa.repository.JpaRepository;

public interface MedicationRepository
        extends JpaRepository<EncryptedMedicationEntity, Long> {
}