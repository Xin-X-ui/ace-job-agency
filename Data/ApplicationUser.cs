using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace AceJobAgency.Data;

public class ApplicationUser : IdentityUser
{
    [Required]
    [MaxLength(100)]
    public string FirstName { get; set; } = string.Empty;

    [Required]
    [MaxLength(100)]
    public string LastName { get; set; } = string.Empty;

    [Required]
    [MaxLength(20)]
    public string Gender { get; set; } = string.Empty;

    [Required]
    [MaxLength(512)]
    public string EncryptedNric { get; set; } = string.Empty;

    public DateTime DateOfBirth { get; set; }

    [Required]
    [MaxLength(2000)]
    public string WhoAmI { get; set; } = string.Empty;

    [Required]
    [MaxLength(255)]
    public string ResumeOriginalFileName { get; set; } = string.Empty;

    [Required]
    [MaxLength(255)]
    public string ResumeStoredFileName { get; set; } = string.Empty;

    [Required]
    [MaxLength(100)]
    public string ResumeContentType { get; set; } = string.Empty;

    public DateTime ResumeUploadedAtUtc { get; set; }

    [MaxLength(64)]
    public string? CurrentSessionId { get; set; }

    public DateTime? LastPasswordChangedAtUtc { get; set; }
}
