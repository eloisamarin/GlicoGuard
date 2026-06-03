# GlicoGuard: Aplicação Web para Apoio ao Cuidado Glicêmico

## Resumo Científico

**Objetivo:** desenvolver um protótipo de aplicação web voltado ao apoio do cuidado glicêmico, com ênfase na segurança da informação, privacidade e conformidade com a Lei Geral de Proteção de Dados Pessoais. **Método:** trata-se do desenvolvimento de um sistema web em Java 21 com Spring Boot 3.4.4, estruturado em arquitetura em camadas, contemplando Controller, Service, Model, Repository e Config. O projeto foi desenvolvido a partir da análise de requisitos relacionados à autenticação, gestão de usuários, proteção de dados pessoais, controle de medicamentos e acompanhamento por cuidadores autorizados. Foram consideradas como principais variáveis os mecanismos de autenticação, autorização, confidencialidade, integridade, rastreabilidade, consentimento e tratamento de dados sensíveis. **Resultados:** o protótipo implementou cadastro de usuários, autenticação em duas etapas por e-mail, senhas protegidas por PBKDF2WithHmacSHA256 com salt individual, recuperação de senha por token temporário, bloqueio por tentativas inválidas, cookies de sessão com HttpOnly e SameSite=Strict, criptografia AES/GCM para dados protegidos, trilha de auditoria com hash encadeado e funcionalidades de consentimento, exportação e solicitação de exclusão de dados. **Conclusão:** o GlicoGuard demonstra a viabilidade de integrar recursos de saúde digital, governança de usuários e controles de segurança em uma aplicação web educacional, oferecendo uma base técnica segura para evolução futura, especialmente em sistemas que tratam dados pessoais e informações sensíveis relacionadas à saúde.

## Palavras-chave

Segurança da Informação; Proteção de Dados; LGPD; Autenticação Multifator; Aplicação Web.

---
# GlicoGuard: Web Application to Support Glycemic Care

## Abstract

**Objective:** to develop a web application prototype designed to support glycemic care, with emphasis on information security, privacy, and compliance with the Brazilian General Data Protection Law. **Method:** this is a development of a Java 21 web system using Spring Boot 3.4.4, organized through a layered architecture composed of Controller, Service, Model, Repository, and Config components. The project was developed from the analysis of requirements related to authentication, user management, personal data protection, medication control, and monitoring by authorized caregivers. The main variables considered were authentication, authorization, confidentiality, integrity, traceability, consent, and sensitive data processing mechanisms. **Results:** the prototype implemented user registration, e-mail-based two-factor authentication, password protection using PBKDF2WithHmacSHA256 with individual salt, password recovery through temporary tokens, temporary blocking after invalid login attempts, session cookies with HttpOnly and SameSite=Strict attributes, AES/GCM encryption for protected data, an audit trail with chained hashes, and features for consent management, data export, and data deletion requests. **Conclusion:** GlicoGuard demonstrates the feasibility of integrating digital health resources, user governance, and security controls into an educational web application, providing a secure technical foundation for future development, especially in systems that process personal data and sensitive health-related information.

## Keywords

Information Security; Data Protection; General Data Protection Law; Multifactor Authentication; Web Application.
