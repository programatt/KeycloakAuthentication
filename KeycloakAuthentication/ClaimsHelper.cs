using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Newtonsoft.Json;

namespace KeycloakAuthentication
{
    public static class ClaimsHelper
    {
        /// <summary>
        /// Parse the JWT for specific claims that Keycloak Provides to Clients
        /// Example JWT with client of 'aspnetcore-test-app'
        /// {
        ///     ...
        ///     "realm_access": {
        ///         "roles":["offline_access","uma_authorization"]
        ///     },
        ///     "resource_access": {
        ///         "aspnetcore-test-app":{ "roles":["sop-admin"] },
        ///         "account":{ "roles":["manage-account","manage-account-links","view-profile"] }
        ///     } 
        /// }
        /// </summary>
        public static IEnumerable<Claim> ParseKeycloakClaims(JwtSecurityToken token, string clientId)
        {
            var realmAccess = token.Claims.Single(c => c.Type == "realm_access");
            var realmRoles = JsonConvert.DeserializeObject<KeycloakClaim>(realmAccess.Value);
            var resourceAccessClaim = token.Claims.Single(c => c.Type == "resource_access");
            var allClientRoles = JsonConvert.DeserializeObject<Dictionary<string, KeycloakClaim>>(resourceAccessClaim.Value);
            var clientRoles = "";
            if (allClientRoles.ContainsKey(clientId))
            {
                clientRoles = string.Join(",",allClientRoles[clientId].roles);
            }
            return new List<Claim>
            {
                new Claim("KeycloakRealmRoles", string.Join(",",realmRoles.roles)),
                new Claim("KeycloakClientRoles", clientRoles)
            };
        }
        
        /// <summary>
        /// Used for parsing the JWT
        /// </summary>
        internal sealed class KeycloakClaim
        {
            // ReSharper disable once InconsistentNaming
            // ReSharper disable once UnusedAutoPropertyAccessor.Global
            public IEnumerable<string> roles { get; set; }
        } 
    }
}