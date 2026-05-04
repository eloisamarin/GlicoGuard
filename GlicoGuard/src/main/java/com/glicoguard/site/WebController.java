package com.glicoguard.site;

import java.time.LocalDateTime;
import java.util.Optional;

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
            fillDashboard(model, loggedUser.get());
            return "dashboard";
        }

        model.addAttribute("roles", UserRole.values());
        model.addAttribute("accessLevels", AccessLevel.values());
        return "index";
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
        model.addAttribute("protectedAssets", authService.describeProtectedAssets());
        return "privacidade";
    }

    @PostMapping("/cadastro")
    public String register(@RequestParam String name,
                           @RequestParam String email,
                           @RequestParam String cpf,
                           @RequestParam int age,
                           @RequestParam String password,
                           @RequestParam String confirmPassword,
                           @RequestParam UserRole role,
                           @RequestParam AccessLevel accessLevel,
                           @RequestParam(required = false) String caregiverInviteToken,
                           RedirectAttributes redirectAttributes) {
        if (name.isBlank() || email.isBlank() || cpf.isBlank() || password.length() < 8) {
            redirectAttributes.addFlashAttribute("error", "Preencha nome, CPF, e-mail e uma senha com pelo menos 8 caracteres.");
            return "redirect:/";
        }

        if (!password.equals(confirmPassword)) {
            redirectAttributes.addFlashAttribute("error", "A confirmacao de senha nao confere.");
            return "redirect:/";
        }

        AuthService.RegistrationResult result = authService.register(
                name,
                email,
                cpf,
                age,
                password,
                role,
                accessLevel,
                caregiverInviteToken
        );
        if (result.hasError()) {
            redirectAttributes.addFlashAttribute("error", result.errorMessage());
            return "redirect:/";
        }

        redirectAttributes.addFlashAttribute("success", "Cadastro realizado com sucesso. Agora faca login.");
        if (result.caregiverInviteToken() != null) {
            redirectAttributes.addFlashAttribute(
                    "caregiverInvitePreview",
                    "Token de vinculacao do paciente: " + result.caregiverInviteToken() + " (use no cadastro do cuidador)."
            );
        }
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
            redirectAttributes.addFlashAttribute("success", "Senha validada. Complete o segundo fator.");
            redirectAttributes.addFlashAttribute("twoFactorPreview",
                    "Codigo 2FA de demonstracao: " + challenge.twoFactorCode() + " (valido ate " + challenge.expiresAt() + ")");
            return "redirect:/2fa";
        } catch (IllegalArgumentException exception) {
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
            redirectAttributes.addFlashAttribute("success", "Token de recuperacao gerado com sucesso.");
            redirectAttributes.addFlashAttribute("resetCodePreview",
                    "Token temporario de demonstracao: " + resetView.token() + " (valido ate " + resetView.expiresAt() + ")");
        } catch (IllegalArgumentException exception) {
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

    @PostMapping("/medicamentos")
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
        return "redirect:/";
    }

    @PostMapping("/consentimento")
    public String signConsent(HttpSession session, RedirectAttributes redirectAttributes) {
        Optional<UserAccount> loggedUser = getLoggedUser(session);
        if (loggedUser.isEmpty()) {
            return "redirect:/";
        }

        authService.signConsent(loggedUser.get());
        redirectAttributes.addFlashAttribute("success", "Consentimento LGPD registrado.");
        return "redirect:/";
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

    private Optional<UserAccount> getLoggedUser(HttpSession session) {
        Object email = session.getAttribute(SESSION_EMAIL);
        if (email == null) {
            return Optional.empty();
        }
        return authService.findByEmail(email.toString());
    }

    private void fillDashboard(Model model, UserAccount account) {
        model.addAttribute("user", account);
        model.addAttribute("accessLevels", AccessLevel.values());
        model.addAttribute("auditEntries", authService.buildAuditView());
        model.addAttribute("medications", authService.buildMedicationView(account));
        model.addAttribute("securityControls", authService.buildSecurityControlsSummary());
        model.addAttribute("canManageMedications",
                account.getRole() == UserRole.PACIENTE
                        || (account.getRole() == UserRole.CUIDADOR && account.getLinkedPatientEmail() != null));
        model.addAttribute("linkedPatientLabel",
                account.getLinkedPatientEmail() != null ? account.getLinkedPatientEmail() : "Nao aplicavel");
    }

    private String getSourceIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
