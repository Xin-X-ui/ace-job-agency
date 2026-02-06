using AceJobAgency.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AceJobAgency.Services;

public class PasswordPolicyService : IPasswordPolicyService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly IPasswordHasher<ApplicationUser> _passwordHasher;
    private readonly PasswordPolicyOptions _options;

    public PasswordPolicyService(
        ApplicationDbContext dbContext,
        IPasswordHasher<ApplicationUser> passwordHasher,
        IOptions<PasswordPolicyOptions> options)
    {
        _dbContext = dbContext;
        _passwordHasher = passwordHasher;
        _options = options.Value;
    }

    public async Task<(bool IsValid, string? ErrorMessage)> ValidateNewPasswordAsync(ApplicationUser user, string newPassword)
    {
        if (_options.MinimumPasswordAgeDays > 0 &&
            user.LastPasswordChangedAtUtc.HasValue &&
            user.LastPasswordChangedAtUtc.Value.AddDays(_options.MinimumPasswordAgeDays) > DateTime.UtcNow)
        {
            return (false, $"You can only change password after {_options.MinimumPasswordAgeDays} day(s).");
        }

        var historyCount = Math.Max(1, _options.PasswordHistoryCount);
        var recentHashes = await _dbContext.PasswordHistories
            .Where(x => x.UserId == user.Id)
            .OrderByDescending(x => x.ChangedAtUtc)
            .Take(historyCount)
            .Select(x => x.PasswordHash)
            .ToListAsync();

        foreach (var hash in recentHashes)
        {
            var result = _passwordHasher.VerifyHashedPassword(user, hash, newPassword);
            if (result != PasswordVerificationResult.Failed)
            {
                return (false, $"New password cannot match your last {historyCount} password(s).");
            }
        }

        return (true, null);
    }

    public bool IsPasswordExpired(ApplicationUser user)
    {
        if (_options.MaximumPasswordAgeDays <= 0 || !user.LastPasswordChangedAtUtc.HasValue)
        {
            return false;
        }

        return user.LastPasswordChangedAtUtc.Value.AddDays(_options.MaximumPasswordAgeDays) < DateTime.UtcNow;
    }

    public async Task RecordPasswordHistoryAsync(ApplicationUser user)
    {
        if (string.IsNullOrWhiteSpace(user.PasswordHash))
        {
            return;
        }

        var now = DateTime.UtcNow;
        user.LastPasswordChangedAtUtc = now;

        _dbContext.PasswordHistories.Add(new PasswordHistory
        {
            UserId = user.Id,
            PasswordHash = user.PasswordHash,
            ChangedAtUtc = now
        });

        await _dbContext.SaveChangesAsync();

        var keepCount = Math.Max(1, _options.PasswordHistoryCount);
        var oldRows = await _dbContext.PasswordHistories
            .Where(x => x.UserId == user.Id)
            .OrderByDescending(x => x.ChangedAtUtc)
            .Skip(keepCount)
            .ToListAsync();

        if (oldRows.Count > 0)
        {
            _dbContext.PasswordHistories.RemoveRange(oldRows);
            await _dbContext.SaveChangesAsync();
        }
    }
}
