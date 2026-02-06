using AceJobAgency.Data;
using AceJobAgency.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AceJobAgency.Pages.Auth;

[Authorize]
public class LogoutModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditLogger _auditLogger;

    public LogoutModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IAuditLogger auditLogger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _auditLogger = auditLogger;
    }

    public IActionResult OnGet()
    {
        return RedirectToPage("/Index");
    }

    public async Task<IActionResult> OnPost(string? returnUrl = null)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is not null)
        {
            user.CurrentSessionId = null;
            await _userManager.UpdateAsync(user);
        }

        await _auditLogger.LogAsync("Logout", user?.Id, user?.Email, "User logged out.");

        await _signInManager.SignOutAsync();

        if (!string.IsNullOrWhiteSpace(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            return LocalRedirect(returnUrl);
        }

        return RedirectToPage("/Auth/Login");
    }
}
