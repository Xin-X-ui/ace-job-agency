using System.ComponentModel.DataAnnotations;
using AceJobAgency.Data;
using AceJobAgency.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AceJobAgency.Pages.Auth;

[Authorize]
public class ChangePasswordModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IAuditLogger _auditLogger;
    private readonly IPasswordPolicyService _passwordPolicyService;

    public ChangePasswordModel(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IAuditLogger auditLogger,
        IPasswordPolicyService passwordPolicyService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _auditLogger = auditLogger;
        _passwordPolicyService = passwordPolicyService;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string StatusMessage { get; private set; } = string.Empty;

    public class InputModel
    {
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Current password")]
        public string CurrentPassword { get; set; } = string.Empty;

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

    public IActionResult OnGet()
    {
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return RedirectToPage("/Auth/Login");
        }

        var validation = await _passwordPolicyService.ValidateNewPasswordAsync(user, Input.NewPassword);
        if (!validation.IsValid)
        {
            ModelState.AddModelError(string.Empty, validation.ErrorMessage ?? "Password policy validation failed.");
            await _auditLogger.LogAsync("ChangePasswordFailed", user.Id, user.Email, "Change password blocked by password policy.");
            return Page();
        }

        var result = await _userManager.ChangePasswordAsync(user, Input.CurrentPassword, Input.NewPassword);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            await _auditLogger.LogAsync("ChangePasswordFailed", user.Id, user.Email, "Change password failed.");
            return Page();
        }

        user = await _userManager.FindByIdAsync(user.Id);
        if (user is null)
        {
            return RedirectToPage("/Auth/Login");
        }

        await _passwordPolicyService.RecordPasswordHistoryAsync(user);
        await _signInManager.RefreshSignInAsync(user);
        await _auditLogger.LogAsync("ChangePasswordSuccess", user.Id, user.Email, "Password changed successfully.");

        StatusMessage = "Your password has been changed.";
        ModelState.Clear();
        Input = new InputModel();
        return Page();
    }
}
