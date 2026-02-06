using AceJobAgency.Data;

namespace AceJobAgency.Services;

public class AuditLogger : IAuditLogger
{
    private readonly ApplicationDbContext _dbContext;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<AuditLogger> _logger;

    public AuditLogger(
        ApplicationDbContext dbContext,
        IHttpContextAccessor httpContextAccessor,
        ILogger<AuditLogger> logger)
    {
        _dbContext = dbContext;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public async Task LogAsync(string eventType, string? userId, string? email, string message)
    {
        try
        {
            var httpContext = _httpContextAccessor.HttpContext;
            var userAgent = httpContext?.Request.Headers.UserAgent.ToString();
            if (string.IsNullOrWhiteSpace(userAgent))
            {
                userAgent = null;
            }
            else if (userAgent.Length > 512)
            {
                userAgent = userAgent[..512];
            }

            _dbContext.AuditLogs.Add(new AuditLog
            {
                EventType = eventType,
                UserId = userId,
                Email = email,
                Message = message,
                IpAddress = httpContext?.Connection.RemoteIpAddress?.ToString(),
                UserAgent = userAgent,
                CreatedAtUtc = DateTime.UtcNow
            });

            await _dbContext.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to write audit log entry for event type {EventType}", eventType);
        }
    }
}
