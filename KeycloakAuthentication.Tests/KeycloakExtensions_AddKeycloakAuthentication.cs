using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace KeycloakAuthentication.Tests
{
    // ReSharper disable once InconsistentNaming
    public class KeycloakExtensions_AddKeycloakAuthentication
    {
        [Fact]
        public void ShouldNotThrowExceptionIfJwtAuthorityAndClientIdInConfiguration()
        {
             IConfiguration configuration = new ConfigurationBuilder()
                 .AddInMemoryCollection(new Dictionary<string, string>
                 {
                     {"Jwt:Authority", "https://test.keycloak.authority.url"},
                     {"Jwt:ClientId", "test-client-id"}
                 })
                 .Build();
             var serviceCollection = new ServiceCollection();
             var env = new Mock<IWebHostEnvironment>();
             serviceCollection.AddKeycloakAuthentication(configuration, env.Object);
        }
        
        [Fact]
        public void ShouldThrowArgumentExceptionIfJwtAuthorityMissingFromConfiguration()
        {
            IConfiguration configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string>
                {
                    {"Jwt:ClientId", "test-client-id"}
                })
                .Build();
            var serviceCollection = new ServiceCollection();
            var env = new Mock<IWebHostEnvironment>();

            Assert.Throws<ArgumentException>(() =>
                serviceCollection.AddKeycloakAuthentication(configuration, env.Object)
            );
        }
        
        [Fact]
        public void ShouldThrowArgumentExceptionIfJwtClientMissingFromConfiguration()
        {
            IConfiguration configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string>
                {
                    {"Jwt:Authority", "https://test.keycloak.authority.url"}
                })
                .Build();
            var serviceCollection = new ServiceCollection();
            var env = new Mock<IWebHostEnvironment>();

            Assert.Throws<ArgumentException>(() =>
                serviceCollection.AddKeycloakAuthentication(configuration, env.Object)
            );
        }

        
    }
}