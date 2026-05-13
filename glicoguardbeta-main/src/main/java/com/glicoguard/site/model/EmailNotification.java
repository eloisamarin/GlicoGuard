package com.glicoguard.site.model;

import java.time.LocalDateTime;

public class EmailNotification {

    private final String to;
    private final String subject;
    private final String body;
    private final LocalDateTime sentAt;

    public EmailNotification(String to, String subject, String body) {
        this.to = to;
        this.subject = subject;
        this.body = body;
        this.sentAt = LocalDateTime.now();
    }

    public String getTo() {
        return to;
    }

    public String getSubject() {
        return subject;
    }

    public String getBody() {
        return body;
    }

    public LocalDateTime getSentAt() {
        return sentAt;
    }
}
