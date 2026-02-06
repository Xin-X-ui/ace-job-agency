using System.ComponentModel.DataAnnotations;
using System.Net;
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
    private readonly IEmailSender _emailSender;
    private readonly ILogger<ForgotPasswordModel> _logger;

    public ForgotPasswordModel(
        UserManager<ApplicationUser> userManager,
        IAuditLogger auditLogger,
        IEmailSender emailSender,
        ILogger<ForgotPasswordModel> logger)
    {
        _userManager = userManager;
        _auditLogger = auditLogger;
        _emailSender = emailSender;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public bool RequestSubmitted { get; private set; }

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

        var email = Input.Email.Trim();
        var user = await _userManager.FindByEmailAsync(email);

        if (user is not null)
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            var resetLink = Url.Page("/Auth/ResetPassword", pageHandler: null, values: new { email, token = encodedToken }, protocol: Request.Scheme);

            var htmlMessage = BuildResetEmailMessage(email, resetLink ?? string.Empty);
            try
            {
                await _emailSender.SendEmailAsync(email, "Reset your Ace Job Agency password", htmlMessage);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send password reset email.");
                ModelState.AddModelError(string.Empty, "Unable to send reset email. Please try again later.");
                return Page();
            }

            await _auditLogger.LogAsync("PasswordResetRequested", user.Id, user.Email, "Password reset link emailed.");
        }
        else
        {
            await _auditLogger.LogAsync("PasswordResetRequestedUnknownEmail", null, email, "Password reset requested for non-existing email.");
        }

        RequestSubmitted = true;
        return Page();
    }

    private static string BuildResetEmailMessage(string email, string resetLink)
    {
        var safeEmail = WebUtility.HtmlEncode(email);
        var safeLink = WebUtility.HtmlEncode(resetLink);

        return $"""
            <p>Hello,</p>
            <p>A password reset was requested for <strong>{safeEmail}</strong>.</p>
            <p><a href="{safeLink}">Click here to reset your password</a></p>
            <p>If you did not request this, you can ignore this email.</p>
            """;
    }
}
