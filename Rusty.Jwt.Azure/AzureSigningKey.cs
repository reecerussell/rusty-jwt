using System.Security.Cryptography;
using System.Text;
using Azure.Core;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Rusty.Jwt.Keys;
using HashAlgorithm = Rusty.Jwt.Keys.HashAlgorithm;

namespace Rusty.Jwt;

public class AzureSigningKey : ISigningKey
{
    private readonly CryptographyClient _client;
    
    public string Id { get; }
    public HashAlgorithm HashAlgorithm { get; }
    public SigningKeyAlgorithm Algorithm { get; }

    public AzureSigningKey(KeyVaultKey key, TokenCredential credential, HashAlgorithm hashAlgorithm)
    {
        _client = new CryptographyClient(key.Id, credential);

        Id = GenerateKeyId(key.Id.ToString());
        HashAlgorithm = hashAlgorithm;
        Algorithm = GetAlgorithm(key.KeyType);
    }

    public async Task<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        var digest = CreateDigest(data);
        var result = await _client.SignAsync(GetSignatureAlgorithm(), digest, cancellationToken);
        return result.Signature;
    }
    
    public async Task<bool> VerifyAsync(byte[] data, byte[] signature, CancellationToken cancellationToken = default)
    {
        var digest = CreateDigest(data);
        var result = await _client.VerifyAsync(GetSignatureAlgorithm(), digest, signature, cancellationToken);
        return result.IsValid;
    }

    private static SigningKeyAlgorithm GetAlgorithm(KeyType type)
    {
        if (type == KeyType.Rsa)
        {
            return SigningKeyAlgorithm.Rsa;
        }

        if (type == KeyType.Ec)
        {
            return SigningKeyAlgorithm.EllipticCurve;
        }

        throw new InvalidOperationException($"The Azure Key type '{type.ToString()}' is not supported.");
    }

    private byte[] CreateDigest(byte[] data)
    {
        switch (HashAlgorithm)
        {
            case HashAlgorithm.SHA256:
                var sha256 = new SHA256Managed();
                return sha256.ComputeHash(data);
            case HashAlgorithm.SHA384:
                var sha384 = new SHA384Managed();
                return sha384.ComputeHash(data);
            case HashAlgorithm.SHA512:
                var sha512 = new SHA512Managed();
                return sha512.ComputeHash(data);
            default:
                throw new ArgumentOutOfRangeException(nameof(HashAlgorithm));
        }
    }

    private SignatureAlgorithm GetSignatureAlgorithm()
    {
        return Algorithm switch
        {
            SigningKeyAlgorithm.Rsa => HashAlgorithm switch
            {
                HashAlgorithm.SHA256 => SignatureAlgorithm.RS256,
                HashAlgorithm.SHA384 => SignatureAlgorithm.RS384,
                HashAlgorithm.SHA512 => SignatureAlgorithm.RS512
            },
            SigningKeyAlgorithm.EllipticCurve => HashAlgorithm switch
            {
                HashAlgorithm.SHA256 => SignatureAlgorithm.ES256,
                HashAlgorithm.SHA384 => SignatureAlgorithm.ES384,
                HashAlgorithm.SHA512 => SignatureAlgorithm.ES512
            }
        };
    }

    /// <summary>
    /// Used to generate an Id for the SigningKey by obscuring
    /// the Azure KeyVault Key Id.
    /// </summary>
    private string GenerateKeyId(string azureKeyId)
    {
        using var md5 = MD5.Create();
        var keyIdBytes = Encoding.UTF8.GetBytes(azureKeyId);
        var hash = md5.ComputeHash(keyIdBytes);
        return new Guid(hash[..16]).ToString();
    }
}