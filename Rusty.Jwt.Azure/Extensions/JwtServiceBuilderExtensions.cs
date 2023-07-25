using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
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
        builder.Services.AddSingleton<KeyVaultKey>(_ =>
        {
            var credential = credentials ?? new DefaultAzureCredential();
            var keyVault = new KeyClient(new Uri(vaultUri), credential);
            var response = keyVault.GetKey(keyName)!; 
            return response.Value;
        });
        builder.Services.AddTransient(_ =>
        {
            var credential = credentials ?? new DefaultAzureCredential();
            var key = _.GetRequiredService<KeyVaultKey>();

            return new AzureSigningKey(key, credential, hashAlgorithm);
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