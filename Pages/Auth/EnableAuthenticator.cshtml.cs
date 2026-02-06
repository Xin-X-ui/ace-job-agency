using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Encodings.Web;
using AceJobAgency.Data;
using AceJobAgency.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AceJobAgency.Pages.Auth;

[Authorize]
public class EnableAuthenticatorModel : PageModel
{
    private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UrlEncoder _urlEncoder;
    private readonly IAuditLogger _auditLogger;

    public EnableAuthenticatorModel(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        UrlEncoder urlEncoder,
        IAuditLogger auditLogger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _urlEncoder = urlEncoder;
        _auditLogger = auditLogger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string SharedKey { get; private set; } = string.Empty;

    public string AuthenticatorUri { get; private set; } = string.Empty;

    public bool Is2faEnabled { get; private set; }

    public string StatusMessage { get; private set; } = string.Empty;

    public class InputModel
    {
        [Required]
        [StringLength(7, ErrorMessage = "Verification code must be 6 digits.", MinimumLength = 6)]
        [Display(Name = "Verification code")]
        public string VerificationCode { get; set; } = string.Empty;
    }

    public async Task<IActionResult> OnGetAsync()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return RedirectToPage("/Auth/Login");
        }

        await LoadSharedKeyAndQrCodeUriAsync(user);
        Is2faEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return RedirectToPage("/Auth/Login");
        }

        if (!ModelState.IsValid)
        {
            await LoadSharedKeyAndQrCodeUriAsync(user);
            Is2faEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            return Page();
        }

        var verificationCode = Input.VerificationCode.Replace(" ", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal);

        var isTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
            user,
            _userManager.Options.Tokens.AuthenticatorTokenProvider,
            verificationCode);

        if (!isTokenValid)
        {
            ModelState.AddModelError("Input.VerificationCode", "Verification code is invalid.");
            await _auditLogger.LogAsync("Enable2faFailed", user.Id, user.Email, "Authenticator verification code invalid.");
            await LoadSharedKeyAndQrCodeUriAsync(user);
            Is2faEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            return Page();
        }

        var set2faResult = await _userManager.SetTwoFactorEnabledAsync(user, true);
        if (!set2faResult.Succeeded)
        {
            foreach (var error in set2faResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            await _auditLogger.LogAsync("Enable2faFailed", user.Id, user.Email, "Could not enable 2FA.");
            await LoadSharedKeyAndQrCodeUriAsync(user);
            Is2faEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            return Page();
        }

        await _signInManager.RefreshSignInAsync(user);
        await _auditLogger.LogAsync("Enable2faSuccess", user.Id, user.Email, "Authenticator app 2FA enabled.");

        StatusMessage = "Authenticator app verified. Two-factor authentication is now enabled.";
        await LoadSharedKeyAndQrCodeUriAsync(user);
        Is2faEnabled = true;
        Input = new InputModel();
        return Page();
    }

    public async Task<IActionResult> OnPostDisableAsync()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return RedirectToPage("/Auth/Login");
        }

        var disableResult = await _userManager.SetTwoFactorEnabledAsync(user, false);
        if (!disableResult.Succeeded)
        {
            foreach (var error in disableResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
        else
        {
            await _signInManager.RefreshSignInAsync(user);
            await _auditLogger.LogAsync("Disable2faSuccess", user.Id, user.Email, "Authenticator app 2FA disabled.");
            StatusMessage = "Two-factor authentication has been disabled.";
        }

        await LoadSharedKeyAndQrCodeUriAsync(user);
        Is2faEnabled = false;
        Input = new InputModel();
        return Page();
    }

    public async Task<IActionResult> OnPostResetKeyAsync()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return RedirectToPage("/Auth/Login");
        }

        await _userManager.SetTwoFactorEnabledAsync(user, false);
        await _userManager.ResetAuthenticatorKeyAsync(user);
        await _signInManager.RefreshSignInAsync(user);
        await _auditLogger.LogAsync("Reset2faKey", user.Id, user.Email, "Authenticator key was reset.");

        StatusMessage = "Authenticator key reset. Configure your app again.";
        await LoadSharedKeyAndQrCodeUriAsync(user);
        Is2faEnabled = false;
        Input = new InputModel();
        return Page();
    }

    private async Task LoadSharedKeyAndQrCodeUriAsync(ApplicationUser user)
    {
        var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrWhiteSpace(unformattedKey))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        SharedKey = FormatKey(unformattedKey ?? string.Empty);
        var email = await _userManager.GetEmailAsync(user) ?? user.UserName ?? "user";
        AuthenticatorUri = GenerateQrCodeUri(email, unformattedKey ?? string.Empty);
    }

    private string GenerateQrCodeUri(string email, string unformattedKey)
    {
        return string.Format(
            AuthenticatorUriFormat,
            _urlEncoder.Encode("AceJobAgency"),
            _urlEncoder.Encode(email),
            unformattedKey);
    }

    private static string FormatKey(string unformattedKey)
    {
        var result = new StringBuilder();
        var currentPosition = 0;
        while (currentPosition + 4 < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition, 4)).Append(' ');
            currentPosition += 4;
        }

        if (currentPosition < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition));
        }

        return result.ToString().ToLowerInvariant();
    }
}
