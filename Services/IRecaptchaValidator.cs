namespace AceJobAgency.Services;

public interface IRecaptchaValidator
{
    Task<RecaptchaValidationResult> ValidateAsync(string token, string expectedAction, CancellationToken cancellationToken = default);
}
