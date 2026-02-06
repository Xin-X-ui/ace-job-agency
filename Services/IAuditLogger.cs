namespace AceJobAgency.Services;

public interface IAuditLogger
{
    Task LogAsync(string eventType, string? userId, string? email, string message);
}
