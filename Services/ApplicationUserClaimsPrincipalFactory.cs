using System.Security.Claims;
using AceJobAgency.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AceJobAgency.Services;

public class ApplicationUserClaimsPrincipalFactory : UserClaimsPrincipalFactory<ApplicationUser>
{
    public const string SessionIdClaimType = "session_id";

    public ApplicationUserClaimsPrincipalFactory(
        UserManager<ApplicationUser> userManager,
        IOptions<IdentityOptions> optionsAccessor)
        : base(userManager, optionsAccessor)
    {
    }

    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(ApplicationUser user)
    {
        var identity = await base.GenerateClaimsAsync(user);

        if (!string.IsNullOrWhiteSpace(user.CurrentSessionId))
        {
            identity.AddClaim(new Claim(SessionIdClaimType, user.CurrentSessionId));
        }

        return identity;
    }
}
