using AceJobAgency.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace AceJobAgency.Pages;

[Authorize]
public class SecurityLogsModel : PageModel
{
    private readonly ApplicationDbContext _dbContext;
    private readonly UserManager<ApplicationUser> _userManager;

    public SecurityLogsModel(ApplicationDbContext dbContext, UserManager<ApplicationUser> userManager)
    {
        _dbContext = dbContext;
        _userManager = userManager;
    }

    public List<LogRow> Logs { get; private set; } = [];

    public async Task OnGetAsync()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return;
        }

        Logs = await _dbContext.AuditLogs
            .Where(x => x.UserId == user.Id)
            .OrderByDescending(x => x.CreatedAtUtc)
            .Take(100)
            .Select(x => new LogRow
            {
                Timestamp = x.CreatedAtUtc,
                Action = x.EventType,
                Entity = string.IsNullOrWhiteSpace(x.Email) ? "(unknown)" : x.Email!,
                Message = x.Message,
                IpAddress = string.IsNullOrWhiteSpace(x.IpAddress) ? "-" : x.IpAddress!,
                IsSuccess = !x.EventType.Contains("Failed", StringComparison.OrdinalIgnoreCase) &&
                            !x.EventType.Contains("Locked", StringComparison.OrdinalIgnoreCase) &&
                            !x.EventType.Contains("Expired", StringComparison.OrdinalIgnoreCase)
            })
            .ToListAsync();
    }

    public sealed class LogRow
    {
        public DateTime Timestamp { get; set; }

        public string Action { get; set; } = string.Empty;

        public string Entity { get; set; } = string.Empty;

        public string Message { get; set; } = string.Empty;

        public string IpAddress { get; set; } = string.Empty;

        public bool IsSuccess { get; set; }
    }
}
