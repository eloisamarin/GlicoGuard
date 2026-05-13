package com.glicoguard.site.controller;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Optional;

import com.glicoguard.site.model.AccessLevel;
import com.glicoguard.site.model.UserAccount;
import com.glicoguard.site.model.UserRole;
import com.glicoguard.site.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class WebController {

    private static final String SESSION_EMAIL = "loggedUserEmail";
    private static final String PENDING_2FA_EMAIL = "pendingTwoFactorEmail";

    private final AuthService authService;

    public WebController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/")
    public String home(HttpSession session, Model model) {
        Optional<UserAccount> loggedUser = getLoggedUser(session);
        if (loggedUser.isPresent()) {
            if (loggedUser.get().getRole() == UserRole.ADMINISTRADOR) {
                fillAdministratorDashboard(model, loggedUser.get());
                return "admin-dashboard";
            }
            fillDashboard(model, loggedUser.get());
            return "dashboard";
        }
        return "index";
    }

    @GetMapping("/cadastro")
    public String publicRegisterPage(Model model) {
        fillPublicRegistrationPage(model);
        return "cadastro";
    }

    @GetMapping("/admin/cadastro")
    public String administratorRegisterPage(HttpSession session, Model model) {
        Optional<UserAccount> loggedUser = getLoggedUser(session);
        if (loggedUser.isEmpty() || loggedUser.get().getRole() != UserRole.ADMINISTRADOR) {
            return "redirect:/";
        }

        fillAdministratorRegistrationPage(model);
        return "cadastro";
    }

    @GetMapping("/2fa")
    public String twoFactorPage(HttpSession session) {
        if (session.getAttribute(PENDING_2FA_EMAIL) == null) {
            return "redirect:/";
        }
        return "two-factor";
    }

    @GetMapping("/recuperar-senha")
    public String passwordRecoveryPage(HttpSession session) {
        if (getLoggedUser(session).isPresent()) {
            return "redirect:/";
        }
        return "recuperar-senha";
    }

    @GetMapping("/privacidade")
    public String privacyPage(HttpSession session, Model model) {
        Optional<UserAccount> loggedUser = getLoggedUser(session);
        if (loggedUser.isEmpty()) {
            return "redirect:/";
        }

        model.addAttribute("user", loggedUser.get());
        model.addAttribute("collectedData", authService.buildCollectedDataView(loggedUser.get()));
        model.addAttribute("privacyExplanations", authService.buildPrivacyExplanations(loggedUser.get()));
        model.addAttribute("dataSubjectRights", authService.buildDataSubjectRights());
        model.addAttribute("consentDocument", authService.buildConsentDocumentView(loggedUser.get()));
        model.addAttribute("protectedAssets", authService.describeProtectedAssets());
        return "privacidade";
    }

    @GetMapping("/medicacoes")
    public String medicationsPage(HttpSession session, Model model) {
        Optional<UserAccount> loggedUser = getLoggedUser(session);
        if (loggedUser.isEmpty()) {
            return "redirect:/";
        }
        if (!canManageMedications(loggedUser.get())) {
            return "redirect:/";
        }

        model.addAttribute("user", loggedUser.get());
        model.addAttribute("medications", authService.buildMedicationView(loggedUser.get()));
        model.addAttribute("linkedPatientLabel",
                loggedUser.get().getLinkedPatientEmail() != null ? loggedUser.get().getLinkedPatientEmail() : "Nao aplicavel");
        return "medicacoes";
    }

    @GetMapping("/auditoria")
    public String auditPage(HttpSession session, Model model, RedirectAttributes redirectAttributes) {
        Optional<UserAccount> loggedUser = getLoggedUser(session);
        if (loggedUser.isEmpty()) {
            return "redirect:/";
        }
        if (loggedUser.get().getRole() != UserRole.ADMINISTRADOR) {
            redirectAttributes.addFlashAttribute("error", "Apenas o administrador pode visualizar os logs globais.");
            return "redirect:/";
        }

        model.addAttribute("user", loggedUser.get());
        model.addAttribute("auditEntries", authService.buildAuditView(loggedUser.get()));
        model.addAttribute("emailEntries", authService.buildEmailView());
        return "auditoria";
    }

    @PostMapping("/admin/usuarios/bloquear")
    public String blockUserAsAdministrator(@RequestParam String userEmail,
                                           HttpSession session,
                                           RedirectAttributes redirectAttributes) {
        Optional<UserAccount> loggedUser = getLoggedUser(session);
        if (loggedUser.isEmpty() || loggedUser.get().getRole() != UserRole.ADMINISTRADOR) {
            return "redirect:/";
        }

        try {
            authService.blockUserByAdministrator(loggedUser.get(), userEmail);
            redirectAttributes.addFlashAttribute("success", "Conta bloqueada pelo administrador.");
        } catch (IllegalArgumentException exception) {
            redirectAttributes.addFlashAttribute("error", exception.getMessage());
        }
        return "redirect:/";
    }

    @PostMapping("/admin/usuarios/desbloquear")
    public String unblockUserAsAdministrator(@RequestParam String userEmail,
                                             HttpSession session,
                                             RedirectAttributes redirectAttributes) {
        Optional<UserAccount> loggedUser = getLoggedUser(session);
        if (loggedUser.isEmpty() || loggedUser.get().getRole() != UserRole.ADMINISTRADOR) {
            return "redirect:/";
        }

        try {
            authService.unblockUserByAdministrator(loggedUser.get(), userEmail);
            redirectAttributes.addFlashAttribute("success", "Conta desbloqueada pelo administrador.");
        } catch (IllegalArgumentException exception) {
            redirectAttributes.addFlashAttribute("error", exception.getMessage());
        }
        return "redirect:/";
    }

    @PostMapping("/cadastro")
    public String register(@RequestParam String name,
                           @RequestParam String email,
                           @RequestParam String cpf,
                           @RequestParam String birthDate,
                           @RequestParam String password,
                           @RequestParam String confirmPassword,
                           @RequestParam UserRole role,
                           @RequestParam AccessLevel accessLevel,
                           @RequestParam(required = false) String caregiverInviteToken,
                           RedirectAttributes redirectAttributes) {
        if (name.isBlank() || email.isBlank() || cpf.isBlank() || birthDate.isBlank() || password.length() < 8) {
            redirectAttributes.addFlashAttribute("error", "Preencha nome, CPF, data de nascimento, e-mail e uma senha com pelo menos 8 caracteres.");
            return "redirect:/cadastro";
        }
        if (role == UserRole.ADMINISTRADOR) {
            redirectAttributes.addFlashAttribute("error", "Use o painel do administrador para criar contas administradoras.");
            return "redirect:/cadastro";
        }

        if (!password.equals(confirmPassword)) {
            redirectAttributes.addFlashAttribute("error", "A confirmacao de senha nao confere.");
            return "redirect:/cadastro";
        }

        LocalDate parsedBirthDate;
        try {
            parsedBirthDate = LocalDate.parse(birthDate);
        } catch (RuntimeException exception) {
            redirectAttributes.addFlashAttribute("error", "Informe uma data de nascimento valida.");
            return "redirect:/cadastro";
        }

        try {
            AuthService.RegistrationResult result = authService.register(
                    name,
                    email,
                    cpf,
                    parsedBirthDate,
                    password,
                    role,
                    accessLevel,
                    caregiverInviteToken
            );
            if (result.hasError()) {
                redirectAttributes.addFlashAttribute("error", result.errorMessage());
                return "redirect:/cadastro";
            }

            if (role == UserRole.PACIENTE) {
                redirectAttributes.addFlashAttribute("success", "Cadastro realizado com sucesso. O codigo para vincular cuidador foi enviado para o e-mail cadastrado.");
            } else {
                redirectAttributes.addFlashAttribute("success", "Cadastro realizado com sucesso. Agora faca login.");
            }
            return "redirect:/";
        } catch (IllegalStateException exception) {
            redirectAttributes.addFlashAttribute("error", exception.getMessage());
            return "redirect:/cadastro";
        }
    }

    @PostMapping("/admin/cadastro")
    public String registerAdministrator(@RequestParam String name,
                                        @RequestParam String email,
                                        @RequestParam String cpf,
                                        @RequestParam String birthDate,
                                        @RequestParam String password,
                                        @RequestParam String confirmPassword,
                                        @RequestParam AccessLevel accessLevel,
                                        HttpSession session,
                                        RedirectAttributes redirectAttributes) {
        Optional<UserAccount> loggedUser = getLoggedUser(session);
        if (loggedUser.isEmpty() || loggedUser.get().getRole() != UserRole.ADMINISTRADOR) {
            return "redirect:/";
        }

        if (name.isBlank() || email.isBlank() || cpf.isBlank() || birthDate.isBlank() || password.length() < 8) {
            redirectAttributes.addFlashAttribute("error", "Preencha nome, CPF, data de nascimento, e-mail e uma senha com pelo menos 8 caracteres.");
            return "redirect:/admin/cadastro";
        }

        if (!password.equals(confirmPassword)) {
            redirectAttributes.addFlashAttribute("error", "A confirmacao de senha nao confere.");
            return "redirect:/admin/cadastro";
        }

        LocalDate parsedBirthDate;
        try {
            parsedBirthDate = LocalDate.parse(birthDate);
        } catch (RuntimeException exception) {
            redirectAttributes.addFlashAttribute("error", "Informe uma data de nascimento valida.");
            return "redirect:/admin/cadastro";
        }

        try {
            AuthService.RegistrationResult result = authService.register(
                    name,
                    email,
                    cpf,
                    parsedBirthDate,
                    password,
                    UserRole.ADMINISTRADOR,
                    accessLevel,
                    null
            );
            if (result.hasError()) {
                redirectAttributes.addFlashAttribute("error", result.errorMessage());
                return "redirect:/admin/cadastro";
            }
        } catch (IllegalStateException exception) {
            redirectAttributes.addFlashAttribute("error", exception.getMessage());
            return "redirect:/admin/cadastro";
        }

        redirectAttributes.addFlashAttribute("success", "Conta administradora criada com sucesso.");
        return "redirect:/";
    }

    @PostMapping("/login")
    public String login(@RequestParam String email,
                        @RequestParam String password,
                        HttpServletRequest request,
                        HttpSession session,
                        RedirectAttributes redirectAttributes) {
        try {
            AuthService.LoginChallenge challenge = authService.startPrimaryAuthentication(
                    email,
                    password,
                    request.getHeader("User-Agent"),
                    getSourceIp(request)
            );
            session.setAttribute(PENDING_2FA_EMAIL, email.trim().toLowerCase());
            redirectAttributes.addFlashAttribute("success", "Senha validada. O codigo de verificacao foi enviado para o e-mail cadastrado e expira em " + challenge.expiresAt() + ".");
            return "redirect:/2fa";
        } catch (IllegalArgumentException exception) {
            redirectAttributes.addFlashAttribute("error", exception.getMessage());
            return "redirect:/";
        } catch (IllegalStateException exception) {
            redirectAttributes.addFlashAttribute("error", exception.getMessage());
            return "redirect:/";
        }
    }

    @PostMapping("/2fa")
    public String verifyTwoFactor(@RequestParam String code,
                                  HttpServletRequest request,
                                  HttpSession session,
                                  RedirectAttributes redirectAttributes) {
        Object pendingEmail = session.getAttribute(PENDING_2FA_EMAIL);
        if (pendingEmail == null) {
            redirectAttributes.addFlashAttribute("error", "Sessao 2FA inexistente. Faca login novamente.");
            return "redirect:/";
        }

        Optional<UserAccount> account = authService.completeTwoFactorAuthentication(
                pendingEmail.toString(),
                code,
                request.getHeader("User-Agent"),
                getSourceIp(request)
        );
        if (account.isEmpty()) {
            redirectAttributes.addFlashAttribute("error", "Codigo 2FA invalido ou expirado.");
            return "redirect:/2fa";
        }

        session.removeAttribute(PENDING_2FA_EMAIL);
        session.setAttribute(SESSION_EMAIL, account.get().getEmail());
        redirectAttributes.addFlashAttribute("success", "Login realizado com sucesso.");
        return "redirect:/";
    }

    @PostMapping("/recuperar-senha")
    public String requestPasswordReset(@RequestParam String email,
                                       RedirectAttributes redirectAttributes) {
        if (email.isBlank()) {
            redirectAttributes.addFlashAttribute("error", "Informe o e-mail para recuperar a senha.");
            return "redirect:/recuperar-senha";
        }

        try {
            AuthService.PasswordResetView resetView = authService.createPasswordReset(email);
            redirectAttributes.addFlashAttribute("success", "Token de recuperacao enviado para o e-mail cadastrado. Valido ate " + resetView.expiresAt() + ".");
        } catch (IllegalArgumentException exception) {
            redirectAttributes.addFlashAttribute("error", exception.getMessage());
        } catch (IllegalStateException exception) {
            redirectAttributes.addFlashAttribute("error", exception.getMessage());
        }

        return "redirect:/recuperar-senha";
    }

    @PostMapping("/redefinir-senha")
    public String resetPassword(@RequestParam String email,
                                @RequestParam String token,
                                @RequestParam String newPassword,
                                RedirectAttributes redirectAttributes) {
        if (email.isBlank() || token.isBlank() || newPassword.length() < 8) {
            redirectAttributes.addFlashAttribute("error",
                    "Preencha e-mail, token e uma nova senha com pelo menos 8 caracteres.");
            return "redirect:/recuperar-senha";
        }

        try {
            authService.resetPassword(email, token, newPassword);
            redirectAttributes.addFlashAttribute("success", "Senha redefinida com sucesso. Agora faca login.");
        } catch (IllegalArgumentException exception) {
            redirectAttributes.addFlashAttribute("error", exception.getMessage());
        }

        return "redirect:/recuperar-senha";
    }

    @PostMapping("/credenciais/email")
    public String updateEmail(@RequestParam String newEmail,
                              HttpSession session,
                              RedirectAttributes redirectAttributes) {
        Optional<UserAccount> loggedUser = getLoggedUser(session);
        if (loggedUser.isEmpty()) {
            return "redirect:/";
        }

        try {
            authService.updateEmail(loggedUser.get(), newEmail);
            session.setAttribute(SESSION_EMAIL, loggedUser.get().getEmail());
            redirectAttributes.addFlashAttribute("success", "E-mail atualizado.");
        } catch (IllegalArgumentException exception) {
            redirectAttributes.addFlashAttribute("error", exception.getMessage());
        }
        return "redirect:/";
    }

    @PostMapping("/credenciais/senha")
    public String updatePassword(@RequestParam String currentPassword,
                                 @RequestParam String newPassword,
                                 HttpSession session,
                                 RedirectAttributes redirectAttributes) {
        Optional<UserAccount> loggedUser = getLoggedUser(session);
        if (loggedUser.isEmpty()) {
            return "redirect:/";
        }

        if (newPassword.length() < 8) {
            redirectAttributes.addFlashAttribute("error", "A nova senha precisa ter pelo menos 8 caracteres.");
            return "redirect:/";
        }

        try {
            authService.updatePassword(loggedUser.get(), currentPassword, newPassword);
            redirectAttributes.addFlashAttribute("success", "Senha alterada com sucesso.");
        } catch (IllegalArgumentException exception) {
            redirectAttributes.addFlashAttribute("error", exception.getMessage());
        }
        return "redirect:/";
    }

    @PostMapping("/credenciais/acesso")
    public String updateAccessLevel(@RequestParam AccessLevel accessLevel,
                                    HttpSession session,
                                    RedirectAttributes redirectAttributes) {
        Optional<UserAccount> loggedUser = getLoggedUser(session);
        if (loggedUser.isEmpty()) {
            return "redirect:/";
        }

        authService.updateAccessLevel(loggedUser.get(), accessLevel);
        redirectAttributes.addFlashAttribute("success", "Nivel de acesso atualizado.");
        return "redirect:/";
    }

    @PostMapping("/medicacoes")
    public String registerMedication(@RequestParam String medicationName,
                                     @RequestParam String dose,
                                     @RequestParam String frequency,
                                     @RequestParam String scheduledAt,
                                     HttpSession session,
                                     RedirectAttributes redirectAttributes) {
        Optional<UserAccount> loggedUser = getLoggedUser(session);
        if (loggedUser.isEmpty()) {
            return "redirect:/";
        }

        try {
            authService.registerMedication(
                    loggedUser.get(),
                    medicationName,
                    dose,
                    frequency,
                    LocalDateTime.parse(scheduledAt)
            );
            redirectAttributes.addFlashAttribute("success", "Medicamento registrado com sucesso.");
        } catch (IllegalArgumentException exception) {
            redirectAttributes.addFlashAttribute("error", exception.getMessage());
        }
        return "redirect:/medicacoes";
    }

    @PostMapping("/consentimento")
    public String signConsent(HttpSession session, RedirectAttributes redirectAttributes) {
        Optional<UserAccount> loggedUser = getLoggedUser(session);
        if (loggedUser.isEmpty()) {
            return "redirect:/";
        }

        authService.signConsent(loggedUser.get());
        redirectAttributes.addFlashAttribute("success", "Consentimento LGPD registrado.");
        return "redirect:/privacidade";
    }

    @PostMapping("/consentimento/revogar")
    public String revokeConsent(HttpSession session, RedirectAttributes redirectAttributes) {
        Optional<UserAccount> loggedUser = getLoggedUser(session);
        if (loggedUser.isEmpty()) {
            return "redirect:/";
        }

        authService.revokeConsent(loggedUser.get());
        redirectAttributes.addFlashAttribute("success", "Consentimento revogado.");
        return "redirect:/privacidade";
    }

    @GetMapping("/dados/exportar")
    public ResponseEntity<byte[]> exportData(HttpSession session) {
        Optional<UserAccount> loggedUser = getLoggedUser(session);
        if (loggedUser.isEmpty()) {
            return ResponseEntity.status(401).build();
        }
        return authService.exportUserData(loggedUser.get());
    }

    @PostMapping("/dados/excluir")
    public String deleteAccount(HttpSession session, RedirectAttributes redirectAttributes) {
        Optional<UserAccount> loggedUser = getLoggedUser(session);
        if (loggedUser.isEmpty()) {
            return "redirect:/";
        }

        authService.deleteUser(loggedUser.get());
        session.invalidate();
        redirectAttributes.addFlashAttribute("success", "Dados pessoais excluidos do sistema.");
        return "redirect:/";
    }

    @PostMapping("/logout")
    public String logout(HttpSession session, RedirectAttributes redirectAttributes) {
        session.invalidate();
        redirectAttributes.addFlashAttribute("success", "Sessao encerrada.");
        return "redirect:/";
    }

    @PostMapping("/admin/usuarios/excluir")
    public String deleteUserAsAdministrator(@RequestParam String userEmail,
                                            HttpSession session,
                                            RedirectAttributes redirectAttributes) {
        Optional<UserAccount> loggedUser = getLoggedUser(session);
        if (loggedUser.isEmpty() || loggedUser.get().getRole() != UserRole.ADMINISTRADOR) {
            return "redirect:/";
        }

        try {
            authService.deleteUserByAdministrator(loggedUser.get(), userEmail);
            if (loggedUser.get().getEmail().equalsIgnoreCase(userEmail)) {
                session.invalidate();
                redirectAttributes.addFlashAttribute("success", "Conta administradora excluida com sucesso.");
                return "redirect:/";
            }
            redirectAttributes.addFlashAttribute("success", "Conta excluida pelo administrador.");
        } catch (IllegalArgumentException exception) {
            redirectAttributes.addFlashAttribute("error", exception.getMessage());
        }
        return "redirect:/";
    }

    private Optional<UserAccount> getLoggedUser(HttpSession session) {
        Object email = session.getAttribute(SESSION_EMAIL);
        if (email == null) {
            return Optional.empty();
        }
        return authService.findByEmail(email.toString());
    }

    private boolean canManageMedications(UserAccount account) {
        return account.getRole() == UserRole.PACIENTE
                || (account.getRole() == UserRole.CUIDADOR && account.getLinkedPatientEmail() != null);
    }

    private void fillDashboard(Model model, UserAccount account) {
        model.addAttribute("user", account);
        model.addAttribute("accessLevels", AccessLevel.values());
        model.addAttribute("canManageMedications", canManageMedications(account));
        model.addAttribute("managedUsers", authService.buildUserSummaryView());
        model.addAttribute("securityControls", authService.buildSecurityControlsSummary());
        model.addAttribute("linkedPatientLabel",
                account.getLinkedPatientEmail() != null ? account.getLinkedPatientEmail() : "Nao aplicavel");
    }

    private void fillAdministratorDashboard(Model model, UserAccount account) {
        model.addAttribute("user", account);
        model.addAttribute("adminSummary", authService.buildAdministratorSummary());
        model.addAttribute("managedUsers", authService.buildUserSummaryView());
        model.addAttribute("recentAuditEntries", authService.buildAuditView(account).stream().limit(10).toList());
        model.addAttribute("emailEntries", authService.buildEmailView().stream().limit(10).toList());
    }

    private void fillPublicRegistrationPage(Model model) {
        model.addAttribute("roles", registrationRoles());
        model.addAttribute("accessLevels", AccessLevel.values());
        model.addAttribute("formAction", "/cadastro");
        model.addAttribute("pageEyebrow", "Cadastro de usuarios");
        model.addAttribute("pageTitle", "Criacao de conta");
        model.addAttribute("leadText", "Preencha os dados abaixo para criar uma conta de paciente ou cuidador na plataforma.");
        model.addAttribute("infoText", "Quando o perfil de paciente for criado, o codigo de vinculacao do cuidador sera enviado para o e-mail informado no cadastro.");
        model.addAttribute("showCaregiverToken", true);
        model.addAttribute("backHref", "/");
        model.addAttribute("backLabel", "Voltar ao login");
    }

    private void fillAdministratorRegistrationPage(Model model) {
        model.addAttribute("roles", new UserRole[] {UserRole.ADMINISTRADOR});
        model.addAttribute("accessLevels", AccessLevel.values());
        model.addAttribute("formAction", "/admin/cadastro");
        model.addAttribute("pageEyebrow", "Cadastro administrativo");
        model.addAttribute("pageTitle", "Criacao de administrador");
        model.addAttribute("leadText", "Esta area e restrita ao administrador atual para a criacao de novas contas com privilegios integrais de gestao.");
        model.addAttribute("infoText", "Utilize este fluxo apenas para usuarios de alta confianca, pois contas administrativas possuem acesso ampliado a auditoria, governanca e gerenciamento de usuarios.");
        model.addAttribute("showCaregiverToken", false);
        model.addAttribute("backHref", "/");
        model.addAttribute("backLabel", "Voltar ao painel");
    }

    private UserRole[] registrationRoles() {
        return new UserRole[] {UserRole.PACIENTE, UserRole.CUIDADOR};
    }

    private String getSourceIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
