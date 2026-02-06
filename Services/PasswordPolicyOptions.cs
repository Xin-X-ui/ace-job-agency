namespace AceJobAgency.Services;

public class PasswordPolicyOptions
{
    public int MinimumPasswordAgeDays { get; set; } = 1;

    public int MaximumPasswordAgeDays { get; set; } = 90;

    public int PasswordHistoryCount { get; set; } = 2;
}
