package com.glicoguard.site.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import com.glicoguard.site.model.EmailNotification;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private static final DateTimeFormatter FILE_STAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
    private static final DateTimeFormatter VIEW_STAMP = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");

    private final List<EmailNotification> notifications = new ArrayList<>();
    private final Path outboxDirectory = Path.of("sent-emails");
    private final JavaMailSender mailSender;
    private final boolean mailEnabled;
    private final String fromAddress;
    private final boolean requireRealDelivery;

    @Autowired
    public EmailService(ObjectProvider<JavaMailSender> mailSenderProvider,
                        @Value("${glicoguard.mail.enabled:false}") boolean mailEnabled,
                        @Value("${glicoguard.mail.from:no-reply@glicoguard.local}") String fromAddress,
                        @Value("${glicoguard.mail.require-real-delivery:true}") boolean requireRealDelivery) {
        this(mailSenderProvider.getIfAvailable(), mailEnabled, fromAddress, requireRealDelivery);
    }

    public EmailService() {
        this((JavaMailSender) null, false, "no-reply@glicoguard.local", false);
    }

    EmailService(JavaMailSender mailSender, boolean mailEnabled, String fromAddress, boolean requireRealDelivery) {
        this.mailSender = mailSender;
        this.mailEnabled = mailEnabled;
        this.fromAddress = fromAddress;
        this.requireRealDelivery = requireRealDelivery;
    }

    public synchronized void sendEmail(String to, String subject, String body) {
        EmailNotification notification = new EmailNotification(to, subject, body);
        notifications.add(notification);

        if (canSendRealEmail()) {
            try {
                SimpleMailMessage message = new SimpleMailMessage();
                message.setFrom(fromAddress);
                message.setTo(to);
                message.setSubject(subject);
                message.setText(body);
                mailSender.send(message);
                persistEmail(notification, "ENVIADO_POR_SMTP");
                return;
            } catch (MailException exception) {
                persistEmail(notification, "FALHA_SMTP");
                throw new IllegalStateException("Falha ao enviar e-mail por SMTP. Verifique usuario, senha de app e configuracao do Gmail.", exception);
            }
        }

        if (requireRealDelivery) {
            persistEmail(notification, "FALHA_CONFIGURACAO_SMTP");
            throw new IllegalStateException("O envio real de e-mail esta obrigatório, mas o SMTP nao foi inicializado corretamente.");
        }

        persistEmail(notification, "SIMULADO_CAIXA_LOCAL");
    }

    public synchronized List<EmailView> buildEmailView() {
        return notifications.stream()
                .sorted(Comparator.comparing(EmailNotification::getSentAt).reversed())
                .map(notification -> new EmailView(
                        notification.getTo(),
                        notification.getSubject(),
                        notification.getBody(),
                        VIEW_STAMP.format(notification.getSentAt())
                ))
                .toList();
    }

    public boolean isRealEmailEnabled() {
        return canSendRealEmail();
    }

    private boolean canSendRealEmail() {
        return mailEnabled && mailSender != null && fromAddress != null && !fromAddress.isBlank();
    }

    private void persistEmail(EmailNotification notification, String deliveryMode) {
        try {
            Files.createDirectories(outboxDirectory);
            String filename = FILE_STAMP.format(notification.getSentAt())
                    + "-" + sanitizeFilePart(notification.getTo()) + ".txt";
            String content = "Modo: " + deliveryMode + System.lineSeparator()
                    + "Remetente: " + fromAddress + System.lineSeparator()
                    + "Para: " + notification.getTo() + System.lineSeparator()
                    + "Assunto: " + notification.getSubject() + System.lineSeparator()
                    + "Enviado em: " + VIEW_STAMP.format(notification.getSentAt()) + System.lineSeparator()
                    + System.lineSeparator()
                    + notification.getBody();
            Files.writeString(
                    outboxDirectory.resolve(filename),
                    content,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING
            );
        } catch (IOException exception) {
            throw new IllegalStateException("Falha ao registrar e-mail enviado.", exception);
        }
    }

    private String sanitizeFilePart(String value) {
        return value.replaceAll("[^a-zA-Z0-9.-]", "_");
    }

    public record EmailView(String to, String subject, String body, String sentAt) {
    }
}
