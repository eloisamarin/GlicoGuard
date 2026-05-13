package com.glicoguard.site.service;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class CryptoService {

    private static final int SALT_BYTES = 16;
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final String CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    private final SecureRandom secureRandom = new SecureRandom();
    private final int iterations;
    private final int keyLength;
    private final String masterKeySource;

    public CryptoService(@Value("${glicoguard.security.pbkdf2.iterations}") int iterations,
                         @Value("${glicoguard.security.pbkdf2.key-length}") int keyLength) {
        this.iterations = iterations;
        this.keyLength = keyLength;
        this.masterKeySource = System.getenv().getOrDefault(
                "GLICOGUARD_AES_KEY",
                "glicoguard-demo-master-key-2026-change-me"
        );
    }

    public PasswordHash createPasswordHash(String password) {
        String salt = generateSalt();
        return new PasswordHash(hashPassword(password, salt), salt);
    }

    public boolean matchesPassword(String password, String expectedHash, String salt) {
        String calculated = hashPassword(password, salt);
        return MessageDigest.isEqual(
                calculated.getBytes(StandardCharsets.UTF_8),
                expectedHash.getBytes(StandardCharsets.UTF_8)
        );
    }

    public String generateTwoFactorCode() {
        return generateShortCode(6);
    }

    public String generateSecureToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public String generateShortCode(int length) {
        StringBuilder builder = new StringBuilder(length);
        for (int index = 0; index < length; index++) {
            int alphabetIndex = secureRandom.nextInt(CODE_ALPHABET.length());
            builder.append(CODE_ALPHABET.charAt(alphabetIndex));
        }
        return builder.toString();
    }

    public String digest(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Falha ao gerar resumo criptografico.", exception);
        }
    }

    public byte[] encrypt(byte[] plainBytes) {
        try {
            byte[] iv = new byte[GCM_IV_BYTES];
            secureRandom.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(getAesKey(), "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] encrypted = cipher.doFinal(plainBytes);
            ByteBuffer buffer = ByteBuffer.allocate(iv.length + encrypted.length);
            buffer.put(iv);
            buffer.put(encrypted);
            return buffer.array();
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Falha ao criptografar dados.", exception);
        }
    }

    private String generateSalt() {
        byte[] salt = new byte[SALT_BYTES];
        secureRandom.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    private String hashPassword(String password, String salt) {
        try {
            byte[] saltBytes = Base64.getDecoder().decode(salt);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, iterations, keyLength);
            byte[] hash = factory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Falha ao aplicar PBKDF2.", exception);
        }
    }

    private byte[] getAesKey() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(masterKeySource.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Falha ao derivar a chave AES.", exception);
        }
    }

    public record PasswordHash(String hash, String salt) {
    }
}
