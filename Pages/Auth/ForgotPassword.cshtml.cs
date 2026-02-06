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
public class ForgotPasswordModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditLogger _auditLogger;

    public ForgotPasswordModel(
        UserManager<ApplicationUser> userManager,
        IAuditLogger auditLogger)
    {
        _userManager = userManager;
        _auditLogger = auditLogger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public bool RequestSubmitted { get; private set; }

    public string? DemoResetLink { get; private set; }

    public class InputModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email address")]
        public string Email { get; set; } = string.Empty;
    }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        RequestSubmitted = true;
        var email = Input.Email.Trim();
        var user = await _userManager.FindByEmailAsync(email);

        if (user is not null)
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            DemoResetLink = Url.Page("/Auth/ResetPassword", pageHandler: null, values: new { email, token = encodedToken }, protocol: Request.Scheme);

            await _auditLogger.LogAsync("PasswordResetRequested", user.Id, user.Email, "Password reset link generated.");
        }
        else
        {
            await _auditLogger.LogAsync("PasswordResetRequestedUnknownEmail", null, email, "Password reset requested for non-existing email.");
        }

        return Page();
    }
}
