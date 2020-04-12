using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace KeycloakAuthentication
{
    public static class KeycloakExtensions
    {
        /// <summary>
        /// Add Keycloak JWT Authentication to aspnet core application.
        /// Requires Jwt config value with
        /// Authority: &lt;url to keycloak auth&gt;
        /// ClientId: the keycloak client-id
        /// </summary>
        /// <param name="services"></param>
        /// <param name="configuration"></param>
        /// <param name="env"></param>
        public static void AddKeycloakAuthentication(this IServiceCollection services, IConfiguration configuration, IWebHostEnvironment env)
        {
            if (configuration.GetValue<string>("Jwt:Authority") == null)
            {
                throw new ArgumentException("Configuration Requires Key \"Jwt:Authority\"");
            }
            if (configuration.GetValue<string>("Jwt:ClientId") == null)
            {
                throw new ArgumentException("Configuration Requires Key \"Jwt:ClientId\"");
            }
            
            services.AddAuthentication(x =>
                {
                    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddJwtBearer(x =>
                {
                    x.SecurityTokenValidators.Add(new JwtSecurityTokenHandler { MapInboundClaims = false });
                    x.Authority = configuration["Jwt:Authority"];
                    x.Audience = "account";
                    x.RequireHttpsMetadata = !env.IsDevelopment();
                    x.Events = new JwtBearerEvents
                    {
                        OnAuthenticationFailed = c => c.OnKeycloakAuthenticationFailed(env),
                        OnTokenValidated = async ctx => await ctx.OnKeycloakTokenValidated(configuration)
                    };
                }); 
        }
        
        /// <summary>
        /// Dont Leak Data When Jwt Authentication Fails Unless in Development Mode
        /// </summary>
        private static Task OnKeycloakAuthenticationFailed(this AuthenticationFailedContext context, IWebHostEnvironment env)
        {
            context.NoResult();
            context.Response.StatusCode = 500;
            context.Response.ContentType = "text/plain";
            return context.Response.WriteAsync(env.IsDevelopment() 
                ? context.Exception.ToString()
                : "An error occured processing your authentication.");
        }
        
        /// <summary>
        /// Set The Claims for Keycloak Realm and Client Roles from the JWT
        /// </summary>
        // ReSharper disable once MemberCanBePrivate.Global
        private static Task OnKeycloakTokenValidated(this TokenValidatedContext context, IConfiguration configuration)
        {
            var claims = ClaimsHelper.ParseKeycloakClaims(
                context.SecurityToken as JwtSecurityToken,
                configuration["Jwt:ClientId"]
            );
            var appIdentity = new ClaimsIdentity(claims);
            context.Principal.AddIdentity(appIdentity);
            return Task.CompletedTask;
        }
    }
}