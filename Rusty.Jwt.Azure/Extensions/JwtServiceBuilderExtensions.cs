using Azure.Core;
using Azure.Identity;
using Microsoft.Extensions.DependencyInjection;
using Rusty.Jwt.Keys;

namespace Rusty.Jwt;

public static class JwtServiceBuilderExtensions
{
    public static IJwtServiceBuilder AddAzureKey(this IJwtServiceBuilder builder,
        string vaultUri,
        string keyName,
        string? name = null,
        TokenCredential? credentials = null,
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256,
        SigningKeyMode mode = SigningKeyMode.SignAndVerify)
    {
        builder.Services.AddTransient(_ =>
        {
            var credential = credentials ?? new DefaultAzureCredential();

            return new AzureSigningKey(vaultUri, keyName, credential, hashAlgorithm);
        });
        builder.Services.AddTransient<ISigningKeyDefinition>(_ =>
        {
            var signingKey = _.GetRequiredService<AzureSigningKey>();

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