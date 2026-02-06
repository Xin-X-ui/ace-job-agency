using System.ComponentModel.DataAnnotations;
using AceJobAgency.Data;
using AceJobAgency.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace AceJobAgency.Pages.Auth;

[AllowAnonymous]
public class LoginModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditLogger _auditLogger;
    private readonly IRecaptchaValidator _recaptchaValidator;
    private readonly RecaptchaOptions _recaptchaOptions;
    private readonly IPasswordPolicyService _passwordPolicyService;

    public LoginModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IAuditLogger auditLogger,
        IRecaptchaValidator recaptchaValidator,
        IOptions<RecaptchaOptions> recaptchaOptions,
        IPasswordPolicyService passwordPolicyService)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _auditLogger = auditLogger;
        _recaptchaValidator = recaptchaValidator;
        _recaptchaOptions = recaptchaOptions.Value;
        _passwordPolicyService = passwordPolicyService;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();
    public string RecaptchaSiteKey => _recaptchaOptions.SiteKey;
    public bool RecaptchaEnabled => !string.IsNullOrWhiteSpace(_recaptchaOptions.SiteKey) && !string.IsNullOrWhiteSpace(_recaptchaOptions.SecretKey);
    public string? NoticeMessage { get; private set; }

    public string ReturnUrl { get; set; } = "/";

    public class InputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Display(Name = "Remember me")]
        public bool RememberMe { get; set; }

        public string RecaptchaToken { get; set; } = string.Empty;
    }

    public IActionResult OnGet(string? returnUrl = null)
    {
        ReturnUrl = returnUrl ?? Url.Content("~/");
        if (User.Identity?.IsAuthenticated == true)
        {
            return LocalRedirect(ReturnUrl);
        }

        if (Request.Cookies.TryGetValue("auth_notice", out var noticeValue) && string.Equals(noticeValue, "concurrent", StringComparison.Ordinal))
        {
            NoticeMessage = "You were signed out because this account was logged in from another browser or device.";
            Response.Cookies.Delete("auth_notice");
        }

        return Page();
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        returnUrl ??= Url.Content("~/");
        ReturnUrl = returnUrl;

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var email = Input.Email.Trim();
        var user = await _userManager.FindByEmailAsync(email);
        var userId = user?.Id;

        if (RecaptchaEnabled)
        {
            var recaptchaResult = await _recaptchaValidator.ValidateAsync(Input.RecaptchaToken, "login");
            if (!recaptchaResult.IsSuccess)
            {
                await _auditLogger.LogAsync("RecaptchaFailed", userId, email, "Login blocked by reCAPTCHA validation.");
                ModelState.AddModelError(string.Empty, recaptchaResult.ErrorMessage ?? "reCAPTCHA validation failed.");
                return Page();
            }
        }

        if (user is null)
        {
            await _auditLogger.LogAsync("LoginFailed", null, email, "Invalid login attempt.");
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return Page();
        }

        var preCheck = await _signInManager.CheckPasswordSignInAsync(user, Input.Password, lockoutOnFailure: true);
        if (preCheck.IsLockedOut)
        {
            await _auditLogger.LogAsync("LoginLockedOut", userId, email, "Account locked after repeated failed login attempts.");
            ModelState.AddModelError(string.Empty, "This account is locked. Please try again later.");
            return Page();
        }

        if (!preCheck.Succeeded)
        {
            await _auditLogger.LogAsync("LoginFailed", userId, email, "Invalid login attempt.");
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return Page();
        }

        if (_passwordPolicyService.IsPasswordExpired(user))
        {
            await _auditLogger.LogAsync("PasswordExpired", user.Id, user.Email, "Login denied because password age exceeded maximum policy.");
            ModelState.AddModelError(string.Empty, "Your password has expired. Please reset your password.");
            return Page();
        }

        var result = await _signInManager.PasswordSignInAsync(email, Input.Password, Input.RememberMe, lockoutOnFailure: false);
        if (result.RequiresTwoFactor)
        {
            await _auditLogger.LogAsync("LoginRequires2fa", userId, email, "Password verified. Awaiting 2FA code.");
            return RedirectToPage("/Auth/LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
        }

        if (result.Succeeded)
        {
            var hadPreviousSession = !string.IsNullOrWhiteSpace(user.CurrentSessionId);
            user.CurrentSessionId = Guid.NewGuid().ToString("N");
            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                await _auditLogger.LogAsync("LoginFailed", userId, email, "Login succeeded but session issuance failed.");
                ModelState.AddModelError(string.Empty, "Unable to establish session. Please try again.");
                return Page();
            }

            await _signInManager.SignInAsync(user, isPersistent: Input.RememberMe);
            if (hadPreviousSession)
            {
                await _auditLogger.LogAsync("ConcurrentSessionReplaced", userId, email, "Existing session was replaced by a new login.");
            }

            await _auditLogger.LogAsync("LoginSuccess", userId, email, "User login succeeded.");
            return LocalRedirect(returnUrl);
        }

        await _auditLogger.LogAsync("LoginFailed", userId, email, "Login failed.");
        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
        return Page();
    }
}
