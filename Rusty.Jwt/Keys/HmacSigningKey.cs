using System.Security.Cryptography;
using System.Text;

namespace Rusty.Jwt.Keys;

/// <summary>
/// An <see cref="ISigningKey"/> used to sign and verify data using
/// a HMAC algorithm.
/// </summary>
public class HmacSigningKey : ISigningKey
{
    private readonly byte[] _key;

    public string Id => "3A221AFF-C802-4BA1-80C4-49BA2981D023";
    
    public HashAlgorithm HashAlgorithm { get; }

    public SigningKeyAlgorithm Algorithm => SigningKeyAlgorithm.Hmac;

    /// <summary>
    /// Initializes a new instance of <see cref="HmacSigningKey"/> with the
    /// given <paramref name="hashAlgorithm"/>.
    /// </summary>
    /// <param name="key">The key used to sign data with.</param>
    /// <param name="hashAlgorithm">The name fo the hash algorithm to use.</param>
    public HmacSigningKey(byte[] key, HashAlgorithm hashAlgorithm)
    {
        _key = key;

        HashAlgorithm = hashAlgorithm;
    }

    /// <summary>
    /// Initializes a new instance of <see cref="HmacSigningKey"/> with the
    /// given <paramref name="hashAlgorithm"/>.
    /// </summary>
    /// <param name="key">The key used to sign data with. This value is encoded as UTF-8.</param>
    /// <param name="hashAlgorithm">The name fo the hash algorithm to use.</param>
    public HmacSigningKey(string key, HashAlgorithm hashAlgorithm)
        : this(Encoding.UTF8.GetBytes(key), hashAlgorithm)
    {
    }
    
    public async Task<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        using var hmac = Create();
        await using var ms = new MemoryStream(data);
        return await hmac.ComputeHashAsync(ms, cancellationToken);
    }

    public async Task<bool> VerifyAsync(byte[] data, byte[] signature, CancellationToken cancellationToken = default)
    {
        var expected = await SignAsync(data, cancellationToken);

        return CryptographicOperations.FixedTimeEquals(signature, expected);
    }

    private HMAC Create() => HashAlgorithm switch
    {
        HashAlgorithm.SHA256 => new HMACSHA256(_key),
        HashAlgorithm.SHA384 => new HMACSHA384(_key),
        HashAlgorithm.SHA512 => new HMACSHA512(_key),
        _ => throw new ArgumentOutOfRangeException(nameof(HashAlgorithm))
    };
}