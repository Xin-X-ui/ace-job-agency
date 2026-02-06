namespace AceJobAgency.Services;

public class RecaptchaOptions
{
    public string SiteKey { get; set; } = string.Empty;

    public string SecretKey { get; set; } = string.Empty;

    public decimal MinimumScore { get; set; } = 0.5m;
}
