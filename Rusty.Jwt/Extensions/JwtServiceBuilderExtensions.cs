using Microsoft.Extensions.DependencyInjection;
using Rusty.Jwt.Keys;

namespace Rusty.Jwt;

public static class JwtServiceBuilderExtensions
{
    /// <summary>
    /// Used to register a signing key.
    /// </summary>
    public static IJwtServiceBuilder AddSigningKey<T>(this IJwtServiceBuilder builder)
        where T : class, ISigningKey
    {
        return builder.AddSigningKey<T>(null, SigningKeyMode.SignAndVerify);
    }
    
    /// <summary>
    /// Used to register a signing key.
    /// </summary>
    public static IJwtServiceBuilder AddSigningKey<T>(this IJwtServiceBuilder builder, string name)
        where T : class, ISigningKey
    {
        return builder.AddSigningKey<T>(name, SigningKeyMode.SignAndVerify);
    }
    
    /// <summary>
    /// Used to register a signing key.
    /// </summary>
    public static IJwtServiceBuilder AddSigningKey<T>(this IJwtServiceBuilder builder, SigningKeyMode mode)
        where T : class, ISigningKey
    {
        return builder.AddSigningKey<T>(null, mode);
    }
    
    /// <summary>
    /// Used to register a signing key.
    /// </summary>
    public static IJwtServiceBuilder AddSigningKey<T>(this IJwtServiceBuilder builder, string? name, SigningKeyMode mode)
        where T : class, ISigningKey
    {
        builder.Services.AddTransient<T>();
        builder.Services.AddTransient<ISigningKeyDefinition>(_ =>
        {
            var key = _.GetRequiredService<T>();

            return new SigningKeyDefinition
            {
                Key = key,
                Mode = mode,
                Name = name
            };
        });

        return builder;
    }

    /// <summary>
    /// Used to register a HMAC signing key.
    /// </summary>
    public static IJwtServiceBuilder AddHmacSigningKey(this IJwtServiceBuilder builder, string key, HashAlgorithm hashAlgorithm,
        string? name, SigningKeyMode mode)
    {
        builder.Services.AddTransient(_ => new HmacSigningKey(key, hashAlgorithm));
        builder.Services.AddTransient<ISigningKeyDefinition>(_ =>
        {
            var signingKey = _.GetRequiredService<HmacSigningKey>();

            return new SigningKeyDefinition
            {
                Key = signingKey,
                Mode = mode,
                Name = name
            };
        });

        return builder;
    }
}