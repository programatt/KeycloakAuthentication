using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;

namespace KeycloakAuthentication
{
    public class KeycloakAuthorizeClaimAttribute : TypeFilterAttribute
    {
        public KeycloakAuthorizeClaimAttribute(string claimType, string claimValue) : base(typeof(KeycloakClaimRequirementFilter))
        {
            Arguments = new object[] {new Claim(claimType, claimValue) };
        }
    }
}