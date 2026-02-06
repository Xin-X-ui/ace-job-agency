using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AceJobAgency.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<PasswordHistory> PasswordHistories => Set<PasswordHistory>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<ApplicationUser>(entity =>
        {
            entity.HasIndex(u => u.NormalizedEmail)
                .HasDatabaseName("EmailIndex")
                .IsUnique()
                .HasFilter("[NormalizedEmail] IS NOT NULL");

            entity.Property(u => u.FirstName).HasMaxLength(100);
            entity.Property(u => u.LastName).HasMaxLength(100);
            entity.Property(u => u.Gender).HasMaxLength(20);
            entity.Property(u => u.EncryptedNric).HasMaxLength(512);
            entity.Property(u => u.WhoAmI).HasMaxLength(2000);
            entity.Property(u => u.ResumeOriginalFileName).HasMaxLength(255);
            entity.Property(u => u.ResumeStoredFileName).HasMaxLength(255);
            entity.Property(u => u.ResumeContentType).HasMaxLength(100);
            entity.Property(u => u.CurrentSessionId).HasMaxLength(64);
        });

        builder.Entity<AuditLog>(entity =>
        {
            entity.Property(x => x.EventType).HasMaxLength(50).IsRequired();
            entity.Property(x => x.UserId).HasMaxLength(450);
            entity.Property(x => x.Email).HasMaxLength(256);
            entity.Property(x => x.Message).HasMaxLength(2000).IsRequired();
            entity.Property(x => x.IpAddress).HasMaxLength(64);
            entity.Property(x => x.UserAgent).HasMaxLength(512);
            entity.HasIndex(x => x.CreatedAtUtc);
            entity.HasIndex(x => x.EventType);
        });

        builder.Entity<PasswordHistory>(entity =>
        {
            entity.Property(x => x.UserId).HasMaxLength(450).IsRequired();
            entity.Property(x => x.PasswordHash).HasMaxLength(1000).IsRequired();
            entity.HasIndex(x => new { x.UserId, x.ChangedAtUtc });
        });
    }
}
