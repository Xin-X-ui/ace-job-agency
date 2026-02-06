using AceJobAgency.Data;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace AceJobAgency.Pages;

public class IndexModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _dbContext;
    private readonly IDataProtector _nricProtector;

    public IndexModel(
        UserManager<ApplicationUser> userManager,
        ApplicationDbContext dbContext,
        IDataProtectionProvider dataProtectionProvider)
    {
        _userManager = userManager;
        _dbContext = dbContext;
        _nricProtector = dataProtectionProvider.CreateProtector("AceJobAgency.Member.Nric.v1");
    }

    public bool IsAuthenticated { get; private set; }

    public string DisplayName { get; private set; } = "Member";

    public string Email { get; private set; } = string.Empty;

    public string Gender { get; private set; } = string.Empty;

    public DateTime DateOfBirth { get; private set; }

    public string MaskedNric { get; private set; } = "Hidden";

    public string WhoAmI { get; private set; } = string.Empty;

    public string ResumeName { get; private set; } = string.Empty;

    public DateTime? LastPasswordChangedAtUtc { get; private set; }

    public List<ActivityRow> RecentActivities { get; private set; } = [];

    public async Task OnGetAsync()
    {
        IsAuthenticated = User.Identity?.IsAuthenticated == true;
        if (!IsAuthenticated)
        {
            return;
        }

        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            IsAuthenticated = false;
            return;
        }

        DisplayName = $"{user.FirstName} {user.LastName}".Trim();
        if (string.IsNullOrWhiteSpace(DisplayName))
        {
            DisplayName = user.Email ?? user.UserName ?? "Member";
        }

        Email = user.Email ?? string.Empty;
        Gender = user.Gender;
        DateOfBirth = user.DateOfBirth;
        WhoAmI = user.WhoAmI;
        ResumeName = user.ResumeOriginalFileName;
        LastPasswordChangedAtUtc = user.LastPasswordChangedAtUtc;

        try
        {
            var decryptedNric = _nricProtector.Unprotect(user.EncryptedNric);
            MaskedNric = MaskNric(decryptedNric);
        }
        catch
        {
            MaskedNric = "Protected";
        }

        RecentActivities = await _dbContext.AuditLogs
            .Where(x => x.UserId == user.Id)
            .OrderByDescending(x => x.CreatedAtUtc)
            .Take(8)
            .Select(x => new ActivityRow
            {
                Action = x.EventType,
                Message = x.Message,
                Timestamp = x.CreatedAtUtc,
                IsSuccess = !x.EventType.Contains("Failed", StringComparison.OrdinalIgnoreCase) &&
                            !x.EventType.Contains("Locked", StringComparison.OrdinalIgnoreCase) &&
                            !x.EventType.Contains("Expired", StringComparison.OrdinalIgnoreCase)
            })
            .ToListAsync();
    }

    private static string MaskNric(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "Hidden";
        }

        if (value.Length <= 4)
        {
            return new string('*', value.Length);
        }

        return $"{value[0]}{new string('*', value.Length - 2)}{value[^1]}";
    }

    public sealed class ActivityRow
    {
        public string Action { get; set; } = string.Empty;

        public string Message { get; set; } = string.Empty;

        public DateTime Timestamp { get; set; }

        public bool IsSuccess { get; set; }
    }
}
