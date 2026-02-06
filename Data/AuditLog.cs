using System.ComponentModel.DataAnnotations;

namespace AceJobAgency.Data;

public class AuditLog
{
    public long Id { get; set; }

    [Required]
    [MaxLength(50)]
    public string EventType { get; set; } = string.Empty;

    [MaxLength(450)]
    public string? UserId { get; set; }

    [MaxLength(256)]
    public string? Email { get; set; }

    [Required]
    [MaxLength(2000)]
    public string Message { get; set; } = string.Empty;

    [MaxLength(64)]
    public string? IpAddress { get; set; }

    [MaxLength(512)]
    public string? UserAgent { get; set; }

    public DateTime CreatedAtUtc { get; set; }
}
