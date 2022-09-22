using Rusty.Jwt.Keys;

namespace Rusty.Jwt;

internal static class HashAlgorithmExtensions
{
    public static int GetHashSize(this HashAlgorithm hashAlgorithm)
    {
        return hashAlgorithm switch
        {
            HashAlgorithm.SHA256 => 256,
            HashAlgorithm.SHA384 => 384,
            HashAlgorithm.SHA512 => 512,
            _ => throw new ArgumentOutOfRangeException(nameof(hashAlgorithm))
        };
    }
}