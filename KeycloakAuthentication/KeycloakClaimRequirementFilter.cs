using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace KeycloakAuthentication
{
    public class KeycloakClaimRequirementFilter : IAuthorizationFilter
    {
        private readonly IEnumerable<Claim> _claims;

        public KeycloakClaimRequirementFilter(params Claim[] claims)
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