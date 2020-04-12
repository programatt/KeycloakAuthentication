using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using FluentAssertions;
using Xunit;

namespace KeycloakAuthentication.Tests
{
    // ReSharper disable once InconsistentNaming
    public class KeycloakExtensions_ParseKeycloakClaims
    {
        [Fact]
        public void ShouldParseRealmRolesFromJwtSecurityToken()
        {
            var expectedClaim = new Claim("KeycloakRealmRoles", "offline_access,uma_authorization");
            var token = new JwtSecurityToken(File.ReadAllText("EncodedKeycloakJwt"));
            var parsedClaims = ClaimsHelper.ParseKeycloakClaims(token, "doesnt-matter");
            parsedClaims.Should().ContainEquivalentOf(expectedClaim);
        }
        
        [Fact]
        public void ShouldParseClientRolesFromJwtSecurityToken()
        {
            var expectedClaim = new Claim("KeycloakClientRoles", "sop-admin");
            var token = new JwtSecurityToken(File.ReadAllText("EncodedKeycloakJwt"));
            const string clientId = "aspnetcore-test-app";
            var parsedClaims = ClaimsHelper.ParseKeycloakClaims(token, clientId);
            parsedClaims.Should().ContainEquivalentOf(expectedClaim);
        }
    }
}