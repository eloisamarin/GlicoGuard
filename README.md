# GlicoGuard

Sistema web em Java para apoio ao gerenciamento de contas, autenticação, consentimento LGPD, privacidade e registros básicos relacionados ao cuidado glicêmico.

O projeto atual está organizado como uma aplicação Spring Boot com telas Thymeleaf, persistência local protegida por criptografia e trilha de auditoria encadeada por hash.

---

# O que é a ferramenta

O GlicoGuard é uma plataforma educacional/protótipo para demonstrar recursos de segurança, governança de usuários e tratamento de dados pessoais em um contexto de saúde.

## Principais capacidades

- Cadastro de pacientes, cuidadores e administradores.
- Login com senha e segundo fator por código temporário.
- Recuperação de senha por token temporário.
- Controle de tentativas de login e bloqueio temporário.
- Vínculo entre paciente e cuidador por código de convite.
- Registro de medicamentos por paciente ou cuidador autorizado.
- Área de privacidade com consentimento, revogação, exportação e solicitação de exclusão de dados.
- Painel administrativo com usuários, auditoria, bloqueio, desbloqueio e exclusão de contas.

---

# Fluxo do sistema

## Autenticação

1. O usuário informa e-mail e senha.
2. A senha é validada com hash PBKDF2 e salt individual.
3. Se a senha estiver correta, o sistema gera um código 2FA de 6 caracteres.
4. O código é enviado por e-mail ou registrado localmente em `sent-emails/`, conforme configuração.
5. O usuário informa o código dentro do prazo de expiração.
6. A sessão é criada somente após a validação do segundo fator.

### Regras de segurança aplicadas

- Bloqueio temporário após tentativas sucessivas de senha inválida.
- Token de recuperação de senha temporário e invalidado após uso.
- Cookie de sessão com `HttpOnly` e `SameSite=Strict`.
- Opção de exigir HTTPS por configuração.
- Auditoria das operações relevantes.

---

# Regras de negócio

- Paciente pode criar conta pública e receber código para vincular cuidador.
- Cuidador só é vinculado a paciente quando informa código de convite válido.
- Administrador é criado apenas por outro administrador.
- Administrador pode bloquear, desbloquear e excluir contas.
- Usuário comum não exclui mais seus dados diretamente: ele solicita a exclusão, e a execução fica pendente para o administrador geral.
- Administrador visualiza auditoria global; usuários comuns visualizam apenas seus próprios eventos.
- Medicamentos podem ser registrados por paciente ou cuidador vinculado.

---

# O que tem no repositório

## Estrutura principal

```text
.
├── README.md
├── glicoguardbeta-main/
│   ├── pom.xml
│   ├── src/main/java/com/glicoguard/site/
│   │   ├── config/
│   │   ├── controller/
│   │   ├── database/
│   │   ├── model/
│   │   ├── repository/
│   │   ├── service/
│   │   └── util/
│   ├── src/main/resources/
│   │   ├── application.properties
│   │   ├── static/css/style.css
│   │   └── templates/
│   └── src/test/java/com/glicoguard/site/
├── GlicoGuard/
│   └── copia/versao anterior do projeto com artefatos locais
├── data/
│   └── dados protegidos locais gerados em execucao
└── sent-emails/
    └── e-mails simulados/registrados localmente
```

O módulo recomendado para desenvolvimento e execução é `glicoguardbeta-main/`.

---

# Núcleo do sistema

## Arquivos principais

- `GlicoGuardApplication.java`: ponto de entrada Spring Boot.
- `WebController.java`: rotas web, páginas e ações de formulário.
- `AuthService.java`: fachada de autenticação, administração, privacidade e medicamentos.
- `AuthenticationService.java`: cadastro, login, 2FA e recuperação de senha.
- `AdministrationService.java`: gerenciamento de contas, bloqueio, desbloqueio, exclusão administrativa e solicitação de exclusão.
- `PrivacyService.java`: consentimento, direitos do titular, exportação e explicações LGPD.
- `MedicationService.java`: regras para registro de medicamentos.
- `CryptoService.java`: hash de senha, digest e criptografia.
- `ProtectedStorageService.java`: snapshots cifrados em `data/protected/`.
- `UserStore.java` e `InMemoryDatabase.java`: armazenamento em memória com persistência protegida por snapshot.
- `SecurityWebFilter.java`: cabeçalhos e controles básicos de segurança HTTP.

---

# Correção de bugs recentes

## Alteração mais recente no fluxo de exclusão

Antes, o usuário comum conseguia excluir a própria conta diretamente pela área de privacidade.

Agora:

- O usuário apenas solicita a exclusão dos dados.
- A conta recebe status de exclusão solicitada, com data/hora.
- O painel administrativo exibe a solicitação.
- Somente o administrador geral executa a exclusão definitiva pela ação administrativa.

## Outros pontos cobertos por testes

- Hash e salt diferentes por usuário.
- Login com segundo fator.
- Bloqueio por tentativas inválidas.
- Recuperação de senha com token de uso único.
- Vínculo paciente/cuidador por código.
- Autorização para registro de medicamentos.
- Auditoria global restrita ao administrador.

---

# Como configurar

## Pré-requisitos

- Java 21
- Maven 3.8 ou superior
- Porta 8080 livre, ou ajuste de `server.port`

## Configurações

As configurações ficam em:

```text
glicoguardbeta-main/src/main/resources/application.properties
```

## Para desenvolvimento sem envio real de e-mail

```powershell
$env:GLICOGUARD_MAIL_ENABLED="false"
$env:GLICOGUARD_MAIL_REQUIRE_REAL_DELIVERY="false"
```

Nesse modo, os e-mails podem ser consultados localmente em `sent-emails/` e pela tela de auditoria/comunicações do administrador.

## Configurações relevantes

```properties
server.port=8080
server.servlet.session.timeout=15m
glicoguard.security.pbkdf2.iterations=120000
glicoguard.security.login.max-attempts=5
glicoguard.security.login.lock-minutes=15
glicoguard.security.two-factor.expiration-minutes=5
glicoguard.security.reset.expiration-minutes=10
glicoguard.security.require-https=false
```

Em produção, defina:

```properties
glicoguard.security.require-https=true
```

---

# Documentação técnica

## Escopo

O escopo do projeto é demonstrar uma aplicação web com:

- Autenticação forte para contas de pacientes, cuidadores e administradores.
- Governança básica de contas.
- Registro de consentimento e direitos do titular.
- Tratamento de dados pessoais e dados sensíveis em um domínio de saúde.
- Auditoria de operações relevantes.
- Persistência local cifrada para snapshots e exportações.

---

# Stack

- Java 21
- Spring Boot 3.4.4
- Spring Web MVC
- Thymeleaf
- Spring Mail
- Maven
- JUnit 5 / Spring Boot Test
- Jackson para serialização
- PBKDF2WithHmacSHA256 para senha
- AES/GCM para criptografia dos arquivos protegidos

---

# LGPD e Trataemnto de Dados

O GlicoGuard foi desenvolvido considerando os princípios da Lei Geral de Proteção de Dados Pessoais — LGPD (Lei nº 13.709/2018), com foco na proteção, transparência e segurança dos dados dos usuários.

Dentre os dados que o sistema poderá coletar estão:

## Dados pessoais

- Nome
- E-mail
- CPF
- Data de nascimento
- Perfil de acesso
- Vínculo entre paciente e cuidador
- Logs de autenticação, recuperação de senha e administração

## Dados sensíveis ou de maior criticidade

- Informações relacionadas à saúde, como medicamentos cadastrados.
- Relacionamento de cuidado entre paciente e cuidador.
- Dados de segurança da conta, como hash de senha, salt, tokens temporários e códigos 2FA.

Esses dados serão utilizados exclusivamente para o funcionamento da aplicação.

Para consultar o documento completo sobre quais dados são coletados, como são utilizados e como são protegidos, acesse:

---

# Como instalar e rodar

## Entre no módulo principal

```bash
cd glicoguardbeta-main
```

## Instale dependências e rode os testes

```bash
mvn test
```

## Inicie a aplicação

```bash
mvn spring-boot:run
```

## Acesse

```text
http://localhost:8080
```

## Conta administrativa inicial para ambiente local

```text
E-mail: admin@glicoguard.com
Senha: admin123
```

Depois do login primário, consulte o código 2FA enviado por e-mail ou registrado localmente, dependendo da configuração.

## Para gerar o pacote

```bash
mvn clean package
```

## Para executar o JAR

```bash
java -jar target/glicoguard-site-1.0.0.jar
```
