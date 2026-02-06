namespace AceJobAgency.Services;

public sealed class RecaptchaValidationResult
{
    private RecaptchaValidationResult(bool isSuccess, string? errorMessage)
    {
        IsSuccess = isSuccess;
        ErrorMessage = errorMessage;
    }

    public bool IsSuccess { get; }

    public string? ErrorMessage { get; }

    public static RecaptchaValidationResult Success() => new(true, null);

    public static RecaptchaValidationResult Failed(string errorMessage) => new(false, errorMessage);
}
