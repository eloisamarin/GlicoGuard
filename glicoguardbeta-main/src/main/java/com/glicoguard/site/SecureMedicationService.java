package com.glicoguard.site;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class SecureMedicationService {

    private final MedicationRepository repository;
    private final CryptoService cryptoService;

    public SecureMedicationService(
            MedicationRepository repository,
            CryptoService cryptoService
    ) {
        this.repository = repository;
        this.cryptoService = cryptoService;
    }

    public void saveMedication(MedicationEntry entry) {

        EncryptedMedicationEntity entity = new EncryptedMedicationEntity();

        entity.setMedicationName(
                cryptoService.encrypt(
                        entry.getMedicationName()
                                .getBytes(StandardCharsets.UTF_8)
                )
        );

        entity.setDose(
                cryptoService.encrypt(
                        entry.getDose()
                                .getBytes(StandardCharsets.UTF_8)
                )
        );

        entity.setFrequency(
                cryptoService.encrypt(
                        entry.getFrequency()
                                .getBytes(StandardCharsets.UTF_8)
                )
        );

        entity.setRegisteredByEmail(
                cryptoService.encrypt(
                        entry.getRegisteredByEmail()
                                .getBytes(StandardCharsets.UTF_8)
                )
        );

        entity.setScheduledAt(entry.getScheduledAt());
        entity.setCreatedAt(LocalDateTime.now());

        repository.save(entity);
    }

    public List<MedicationEntry> findAll() {

        return repository.findAll()
                .stream()
                .map(entity -> new MedicationEntry(
                        decrypt(entity.getMedicationName()),
                        decrypt(entity.getDose()),
                        decrypt(entity.getFrequency()),
                        entity.getScheduledAt(),
                        decrypt(entity.getRegisteredByEmail())
                ))
                .collect(Collectors.toList());
    }

    private String decrypt(byte[] encrypted) {
        return new String(
                cryptoService.decrypt(encrypted),
                StandardCharsets.UTF_8
        );
    }
}