using System.ComponentModel.DataAnnotations;

namespace AceJobAgency.Data;

public class PasswordHistory
{
    public long Id { get; set; }

    [Required]
    [MaxLength(450)]
    public string UserId { get; set; } = string.Empty;

    [Required]
    [MaxLength(1000)]
    public string PasswordHash { get; set; } = string.Empty;

    public DateTime ChangedAtUtc { get; set; }
}
