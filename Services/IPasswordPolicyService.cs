using AceJobAgency.Data;

namespace AceJobAgency.Services;

public interface IPasswordPolicyService
{
    Task<(bool IsValid, string? ErrorMessage)> ValidateNewPasswordAsync(ApplicationUser user, string newPassword);

    bool IsPasswordExpired(ApplicationUser user);

    Task RecordPasswordHistoryAsync(ApplicationUser user);
}
