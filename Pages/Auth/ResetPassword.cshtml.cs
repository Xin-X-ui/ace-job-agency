using System.ComponentModel.DataAnnotations;
using System.Text;
using AceJobAgency.Data;
using AceJobAgency.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;

namespace AceJobAgency.Pages.Auth;

[AllowAnonymous]
public class ResetPasswordModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditLogger _auditLogger;
    private readonly IPasswordPolicyService _passwordPolicyService;

    public ResetPasswordModel(
        UserManager<ApplicationUser> userManager,
        IAuditLogger auditLogger,
        IPasswordPolicyService passwordPolicyService)
    {
        _userManager = userManager;
        _auditLogger = auditLogger;
        _passwordPolicyService = passwordPolicyService;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string StatusMessage { get; private set; } = string.Empty;

    public class InputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string Token { get; set; } = string.Empty;

        [Required]
        [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters long.")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{12,}$", ErrorMessage = "Password must include lowercase, uppercase, number, and special character.")]
        [DataType(DataType.Password)]
        [Display(Name = "New password")]
        public string NewPassword { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(NewPassword), ErrorMessage = "The new password and confirmation password do not match.")]
        [Display(Name = "Confirm new password")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public IActionResult OnGet(string? email = null, string? token = null)
    {
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(token))
        {
            return RedirectToPage("/Auth/ForgotPassword");
        }

        Input = new InputModel
        {
            Email = email,
            Token = token
        };

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var email = Input.Email.Trim();
        var user = await _userManager.FindByEmailAsync(email);
        if (user is null)
        {
            StatusMessage = "If the account exists, password reset has been processed.";
            return Page();
        }
        var userId = user.Id;
        var userEmail = user.Email;

        var validation = await _passwordPolicyService.ValidateNewPasswordAsync(user, Input.NewPassword);
        if (!validation.IsValid)
        {
            ModelState.AddModelError(string.Empty, validation.ErrorMessage ?? "Password policy validation failed.");
            await _auditLogger.LogAsync("PasswordResetFailed", userId, userEmail, "Password reset blocked by password policy.");
            return Page();
        }

        string decodedToken;
        try
        {
            decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(Input.Token));
        }
        catch
        {
            ModelState.AddModelError(string.Empty, "Invalid reset token.");
            await _auditLogger.LogAsync("PasswordResetFailed", userId, userEmail, "Password reset failed due to invalid token.");
            return Page();
        }

        var result = await _userManager.ResetPasswordAsync(user, decodedToken, Input.NewPassword);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            await _auditLogger.LogAsync("PasswordResetFailed", userId, userEmail, "Password reset failed.");
            return Page();
        }

        user = await _userManager.FindByIdAsync(user.Id);
        if (user is not null)
        {
            await _passwordPolicyService.RecordPasswordHistoryAsync(user);
        }

        await _auditLogger.LogAsync("PasswordResetSuccess", userId, userEmail, "Password reset succeeded.");
        StatusMessage = "Password reset successful. You can now log in with your new password.";
        ModelState.Clear();
        Input = new InputModel();
        return Page();
    }
}
