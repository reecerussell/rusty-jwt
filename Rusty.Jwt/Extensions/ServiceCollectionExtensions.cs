using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Rusty.Jwt.Keys;

namespace Rusty.Jwt;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Used to register the core services.
    /// </summary>
    public static IJwtServiceBuilder AddRustyJwt(this IServiceCollection services)
    {
        services.TryAddTransient<IKeyRing, KeyRing>();
        services.TryAddTransient<IJwtFactory, JwtFactory>();
        services.TryAddTransient<IJwtVerifier, JwtVerifier>();

        return new JwtServiceBuilder(services);
    }
}