using System.ComponentModel.DataAnnotations;
using AceJobAgency.Data;
using AceJobAgency.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AceJobAgency.Pages.Auth;

[AllowAnonymous]
public class LoginWith2faModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditLogger _auditLogger;

    public LoginWith2faModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IAuditLogger auditLogger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _auditLogger = auditLogger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public bool RememberMe { get; set; }

    public string ReturnUrl { get; set; } = "/";

    public class InputModel
    {
        [Required]
        [StringLength(7, ErrorMessage = "Authenticator code must be 6 digits.", MinimumLength = 6)]
        [DataType(DataType.Text)]
        [Display(Name = "Authenticator code")]
        public string TwoFactorCode { get; set; } = string.Empty;

        [Display(Name = "Remember this device")]
        public bool RememberMachine { get; set; }
    }

    public async Task<IActionResult> OnGetAsync(bool rememberMe, string? returnUrl = null)
    {
        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user is null)
        {
            return RedirectToPage("/Auth/Login");
        }

        ReturnUrl = returnUrl ?? Url.Content("~/");
        RememberMe = rememberMe;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(bool rememberMe, string? returnUrl = null)
    {
        returnUrl ??= Url.Content("~/");
        ReturnUrl = returnUrl;
        RememberMe = rememberMe;

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user is null)
        {
            return RedirectToPage("/Auth/Login");
        }

        var authenticatorCode = Input.TwoFactorCode.Replace(" ", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal);

        var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, rememberMe, Input.RememberMachine);
        if (result.Succeeded)
        {
            var hadPreviousSession = !string.IsNullOrWhiteSpace(user.CurrentSessionId);
            user.CurrentSessionId = Guid.NewGuid().ToString("N");
            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                await _signInManager.SignOutAsync();
                await _auditLogger.LogAsync("Login2faFailed", user.Id, user.Email, "2FA succeeded but session issuance failed.");
                ModelState.AddModelError(string.Empty, "Unable to establish session. Please log in again.");
                return Page();
            }

            await _signInManager.SignInAsync(user, isPersistent: rememberMe);
            if (hadPreviousSession)
            {
                await _auditLogger.LogAsync("ConcurrentSessionReplaced", user.Id, user.Email, "Existing session was replaced by a new login after 2FA.");
            }

            await _auditLogger.LogAsync("Login2faSuccess", user.Id, user.Email, "2FA login succeeded.");
            return LocalRedirect(returnUrl);
        }

        if (result.IsLockedOut)
        {
            await _auditLogger.LogAsync("LoginLockedOut", user.Id, user.Email, "Account locked during 2FA flow.");
            ModelState.AddModelError(string.Empty, "This account is locked. Please try again later.");
            return Page();
        }

        await _auditLogger.LogAsync("Login2faFailed", user.Id, user.Email, "Invalid 2FA code.");
        ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
        return Page();
    }
}
