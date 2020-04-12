using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace KeycloakAuthentication
{
    public static class KeycloakClaimTypes
    {
        public const string RealmRoles = "KeycloakRealmRoles";
        public const string ClientRoles = "KeycloakClientRoles";
    }
    public class KeycloakAuthorizeClaimAttribute : TypeFilterAttribute
    {
        public KeycloakAuthorizeClaimAttribute(string claimType, string claimValue) : base(typeof(ClaimRequirementFilter))
        {
            Arguments = new object[] {new Claim(claimType, claimValue) };
        }
    }

    public class ClaimRequirementFilter : IAuthorizationFilter
    {
        private readonly IEnumerable<Claim> _claims;

        public ClaimRequirementFilter(params Claim[] claims)
        {
            _claims = claims;
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var hasClaim = _claims.Any(
                claim => context.HttpContext.User.Claims.Any(
                    c => c.Type == claim.Type && claim.Value.Contains(c.Value))
            );
            if (!hasClaim)
            {
                context.Result = new ForbidResult();
            }
        }
    }
}