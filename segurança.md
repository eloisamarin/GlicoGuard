# Aviso de Privacidade e Tratamento de Dados — GlicoGuard

O GlicoGuard trata dados pessoais conforme a **Lei Geral de Proteção de Dados Pessoais — LGPD, Lei nº 13.709/2018**, adotando medidas de segurança para proteger as informações dos usuários contra acessos não autorizados, uso indevido, alteração, perda ou exposição indevida.


## 1. LGPD
O sistema implementa recursos voltados aos princípios da LGPD:

- **Finalidade:** os dados são usados para fins específicos e informados ao usuário.
- **Necessidade:** são coletados apenas dados necessários para funcionamento do sistema.
- **Transparência:** o usuário pode visualizar quais dados são coletados e para qual finalidade.
- **Segurança:** o sistema aplica controles técnicos para proteger as informações.
- **Prevenção:** são usados mecanismos para reduzir riscos de acesso indevido.
- **Responsabilização:** ações importantes são registradas em trilha de auditoria.

---

## 2. Dados coletados pelo sistema

A tabela abaixo apresenta os dados identificados no código do projeto e a finalidade de uso de cada um.

| Dado coletado | Onde aparece no sistema/código | Finalidade |
|---|---|---|
| Nome completo | Cadastro de usuário e painel do usuário | Identificar o titular da conta e personalizar o acesso ao sistema. |
| E-mail | Cadastro, login, 2FA, recuperação de senha e notificações | Permitir autenticação, envio de código de verificação, recuperação de senha e comunicação com o usuário. |
| CPF | Cadastro do usuário | Identificar o usuário e evitar duplicidade de cadastro. |
| Data de nascimento | Cadastro do usuário | Complementar a identificação do perfil do usuário. |
| Senha | Cadastro, login e alteração de senha | Permitir acesso seguro à conta. A senha será armazenada em hash. |
| Hash da senha e salt | Serviço de autenticação e criptografia | Validar a senha de forma segura sem guardar a senha original. |
| Perfil do usuário | Paciente, cuidador ou administrador | Controlar permissões e regras de acesso dentro do sistema. |
| Nível de acesso | Somente leitura ou edição | Definir se o usuário pode apenas visualizar dados ou também alterá-los. |
| E-mail do paciente vinculado | Cadastro de cuidador e vínculo paciente/cuidador | Permitir que um cuidador acompanhe apenas o paciente autorizado. |
| Token de convite do cuidador | Vinculação entre paciente e cuidador | Confirmar o vínculo entre paciente e cuidador por meio de token temporário. |
| Medicamento registrado | Tela/serviço de medicações | Registrar os medicamentos informados pelo paciente ou cuidador. |
| Dose do medicamento | Tela/serviço de medicações | Registrar a dose do medicamento informado. |
| Frequência do medicamento | Tela/serviço de medicações | Registrar a frequência de uso do medicamento. |
| Data e horário agendado do medicamento | Tela/serviço de medicações | Organizar o controle de horários de medicação. |
| E-mail de quem registrou o medicamento | Registro de medicações | Identificar se o registro foi feito pelo paciente ou cuidador vinculado. |
| Data de criação da conta | Modelo de usuário | Registrar quando a conta foi criada. |
| Consentimento LGPD | Tela/serviço de privacidade | Registrar se o usuário aceitou o tratamento de dados e qual versão do termo foi aceita. |
| Data de aceite do consentimento | Tela/serviço de privacidade | Guardar evidência do momento em que o usuário consentiu. |
| Data de revogação do consentimento | Tela/serviço de privacidade | Guardar evidência caso o usuário revogue o consentimento. |
| Dispositivos conhecidos | Serviço de autenticação | Identificar novos acessos e reforçar a segurança da conta. |
| Tentativas de login | Serviço de autenticação | Detectar tentativas indevidas e aplicar bloqueio temporário. |
| Data de bloqueio da conta | Serviço de autenticação/administração | Controlar bloqueios por falhas de login ou ação administrativa. |
| Código de 2FA em formato protegido | Serviço de autenticação | Validar a autenticação em duas etapas sem armazenar o código em texto puro. |
| Token de recuperação de senha em formato protegido | Serviço de autenticação | Permitir redefinição de senha com token temporário. |
| Logs de auditoria | Serviço de auditoria/administração | Registrar ações relevantes para segurança, rastreabilidade e conformidade. |
| IP de origem do acesso | Registro de auditoria no login | Apoiar a identificação de acessos e tentativas suspeitas. |

---

## 3. Utilização dos dados

### 3.1 Cadastro de usuário

Durante o cadastro, o sistema coleta:

- nome completo;
- e-mail;
- CPF;
- data de nascimento;
- senha;
- perfil do usuário;
- nível de acesso;
- token de vínculo, quando o usuário for cuidador.

Esses dados são usados para criar a conta, validar identidade mínima, evitar duplicidade de cadastro e definir as permissões do usuário.

---

### 3.2 Login e autenticação

No login, o sistema utiliza:

- e-mail;
- senha;
- hash da senha;
- salt;
- tentativas de login;
- bloqueio temporário;
- código de verificação em duas etapas;
- IP de origem;
- dispositivo utilizado.

A autenticação possui verificação em duas etapas por e-mail. Após a validação da senha, o sistema gera um código temporário de 6 caracteres e envia ao e-mail cadastrado.

---

### 3.3 Recuperação de senha

Na recuperação de senha, o sistema utiliza:

- e-mail;
- token temporário de recuperação;
- hash do token;
- data de expiração do token.

O token é temporário e será invalidado após o uso ou após a expiração.

---

### 3.4 Vínculo entre paciente e cuidador

Quando um cuidador é cadastrado, o sistema utiliza:

- e-mail do paciente vinculado;
- token temporário de convite;
- perfil do usuário;
- nível de acesso.

Esse vínculo limita o acesso do cuidador apenas ao paciente autorizado, evitando acesso indevido a outros usuários.

---

### 3.5 Registro de medicamentos

Para controle de medicação, o sistema utiliza:

- nome do medicamento;
- dose;
- frequência;
- data e horário agendado;
- e-mail de quem registrou;
- data de criação do registro.

Esses dados permitem organizar as medicações do paciente e identificar se o registro foi feito pelo próprio paciente ou por um cuidador vinculado.

---

### 3.6 Área de privacidade

Na área de privacidade, o sistema permite que o usuário consulte informações sobre:

- dados coletados;
- finalidade do tratamento;
- termo de consentimento;
- versão do consentimento;
- data de aceite;
- data de revogação;
- exportação dos dados;
- exclusão da conta.

Essa área reforça a transparência exigida pela LGPD.

---

### 3.7 Auditoria e segurança

O sistema registra logs de auditoria contendo:

- data e hora do evento;
- usuário relacionado;
- e-mail do usuário;
- ação realizada;
- resultado da ação;
- detalhes do evento;
- hash anterior;
- hash de integridade.

Esses registros são usados para rastrear eventos importantes, como login, falhas de autenticação, geração de 2FA, recuperação de senha, alteração de e-mail, exclusão de conta e ações administrativas.

---

## 4. Como os dados são tratados

Os dados são tratados para as seguintes finalidades:

1. **Autenticação e segurança da conta**  
   Utilização de e-mail, senha, 2FA, tokens, tentativas de login e dispositivos conhecidos.

2. **Gestão do perfil do usuário**  
   Utilização de nome, CPF, data de nascimento, perfil e nível de acesso.

3. **Controle de medicações**  
   Utilização de medicamento, dose, frequência, horário e responsável pelo registro.

4. **Vínculo entre paciente e cuidador**  
   Utilização do e-mail do paciente e token temporário para autorizar acompanhamento.

5. **Cumprimento da LGPD**  
   Registro de consentimento, revogação, exportação e exclusão de dados.

6. **Auditoria e prevenção contra fraudes**  
   Registro de ações relevantes para segurança, rastreabilidade e investigação de incidentes.

---

## 5. Medidas de segurança adotadas


| Controle de segurança | Aplicação no sistema |
|---|---|
| Hash de senha com PBKDF2 | A senha é protegida com hash criptográfico e salt único por usuário. |
| Salt individual | Cada usuário possui salt próprio para proteger a senha. |
| 2FA por e-mail | Código temporário de verificação enviado ao e-mail cadastrado. |
| Expiração do código 2FA | O código de verificação possui tempo limitado de validade. |
| Recuperação de senha com token temporário | O token de redefinição expira e será invalidado após uso. |
| Bloqueio por tentativas inválidas | A conta pode ser bloqueada temporariamente após falhas sucessivas. |
| Criptografia AES/GCM | Arquivos protegidos e exportações são armazenados de forma cifrada. |
| Auditoria com hash encadeado | Logs possuem hash de integridade para rastreabilidade. |
| Controle de sessão | Sessão com tempo limite e cookie HTTP-only. |
| Controle de acesso por perfil | Paciente, cuidador e administrador possuem permissões diferentes. |
| Restrição de cuidador vinculado | Cuidador só acessa informações do paciente associado. |

---

## 6. Armazenamento dos dados

### 6.1 Arquivos protegidos

O sistema possui armazenamento criptografado.

### 6.2 Banco de dados

O projeto também possui configuração para uso de banco PostgreSQL. 
A entidade de medicamentos possui campos criptografados para:

- nome do medicamento;
- dose;
- frequência;
- e-mail de quem registrou.

---

## 7. Compartilhamento de dados

Os dados serão utilizados internamente pelo próprio sistema para:

- autenticar o usuário;
- enviar e-mails de 2FA;
- enviar token de recuperação de senha;
- permitir acesso do cuidador vinculado;
- permitir administração do sistema;
- registrar eventos de auditoria;
- cumprir solicitações do titular.

---

## 8. Direitos do titular dos dados

O usuário possui direitos previstos na LGPD e o sistema já contempla algumas funcionalidades relacionadas a esses direitos.

O titular pode:

- consultar quais dados foram coletados;
- entender a finalidade de uso de cada dado;
- exportar uma cópia estruturada dos seus dados;
- revogar o consentimento;
- solicitar exclusão da conta e dos dados pessoais;
- obter informações sobre os controles de segurança aplicados;
- solicitar atualização de dados, como e-mail e senha.

---

## 9. Consentimento

O sistema registra o consentimento do usuário com:

- status do consentimento;
- versão do termo;
- finalidade do tratamento;
- data de aceite;
- data de revogação.

Ao aceitar o termo, o usuário declara estar ciente de que seus dados serão usados para autenticação, segurança da conta, registro de medicamentos, vínculo entre paciente e cuidador e atendimento aos direitos previstos na LGPD.

---

## 10. Exclusão de dados

O sistema possui funcionalidade para exclusão de conta e dados pessoais.

Quando a exclusão é solicitada, o sistema remove a conta do usuário e registra o evento em logs. Caso o usuário esteja vinculado a outro perfil, como cuidador ou paciente, as referências de vínculo também serão atualizadas para evitar inconsistências.

---

## 11. Exportação de dados

O sistema permite exportar os dados do titular em formato estruturado, incluindo:

- identificação do usuário;
- dados cadastrais;
- perfil e nível de acesso;
- vínculo com paciente, quando houver;
- medicamentos registrados;
- consentimento;
- data de criação da conta;
- quantidade de dispositivos conhecidos;
- registros de auditoria relacionados ao usuário.

A exportação também é armazenada de forma protegida em arquivo cifrado.

---

## 12. Retenção dos dados

Os dados devem ser mantidos apenas pelo tempo necessário para cumprir as finalidades informadas ao usuário, incluindo:

- manutenção da conta;
- autenticação;
- segurança;
- auditoria;
- controle de medicamentos;
- cumprimento de obrigações legais ou regulatórias.

Quando os dados não forem mais necessários ou quando o titular solicitar exclusão, os dados serão removidos, exceto em caso de obrigação legal que justifique a retenção.
