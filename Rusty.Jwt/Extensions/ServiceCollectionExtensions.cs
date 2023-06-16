using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Rusty.Jwt.Caching;
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
        services.TryAddSingleton<ISystemClock, UtcSystemClock>();
        services.TryAddSingleton<ITokenCache, NoopTokenCache>();

        return new JwtServiceBuilder(services);
    }
}