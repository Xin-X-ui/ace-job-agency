using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;

namespace AceJobAgency.Services;

public class RecaptchaValidator : IRecaptchaValidator
{
    private const string VerifyEndpoint = "https://www.google.com/recaptcha/api/siteverify";

    private readonly HttpClient _httpClient;
    private readonly RecaptchaOptions _options;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<RecaptchaValidator> _logger;

    public RecaptchaValidator(
        HttpClient httpClient,
        IOptions<RecaptchaOptions> options,
        IHttpContextAccessor httpContextAccessor,
        ILogger<RecaptchaValidator> logger)
    {
        _httpClient = httpClient;
        _options = options.Value;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public async Task<RecaptchaValidationResult> ValidateAsync(string token, string expectedAction, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(_options.SecretKey))
        {
            return RecaptchaValidationResult.Failed("reCAPTCHA is not configured. Please set SecretKey.");
        }

        if (string.IsNullOrWhiteSpace(token))
        {
            return RecaptchaValidationResult.Failed("reCAPTCHA token is missing.");
        }

        var form = new Dictionary<string, string>
        {
            ["secret"] = _options.SecretKey,
            ["response"] = token
        };

        var remoteIp = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString();
        if (!string.IsNullOrWhiteSpace(remoteIp))
        {
            form["remoteip"] = remoteIp;
        }

        try
        {
            using var response = await _httpClient.PostAsync(VerifyEndpoint, new FormUrlEncodedContent(form), cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("reCAPTCHA verification failed with HTTP status {StatusCode}", response.StatusCode);
                return RecaptchaValidationResult.Failed("reCAPTCHA verification service is unavailable.");
            }

            var payload = await response.Content.ReadFromJsonAsync<RecaptchaApiResponse>(cancellationToken: cancellationToken);
            if (payload is null || !payload.Success)
            {
                _logger.LogWarning("reCAPTCHA rejected request. Errors: {Errors}", string.Join(",", payload?.ErrorCodes ?? []));
                return RecaptchaValidationResult.Failed("reCAPTCHA validation failed.");
            }

            if (!string.Equals(payload.Action, expectedAction, StringComparison.Ordinal))
            {
                return RecaptchaValidationResult.Failed("Invalid reCAPTCHA action.");
            }

            if (payload.Score < _options.MinimumScore)
            {
                return RecaptchaValidationResult.Failed("reCAPTCHA score too low.");
            }

            return RecaptchaValidationResult.Success();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "reCAPTCHA verification threw an exception");
            return RecaptchaValidationResult.Failed("reCAPTCHA verification failed.");
        }
    }

    private sealed class RecaptchaApiResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("score")]
        public decimal Score { get; set; }

        [JsonPropertyName("action")]
        public string Action { get; set; } = string.Empty;

        [JsonPropertyName("error-codes")]
        public string[] ErrorCodes { get; set; } = [];
    }
}
