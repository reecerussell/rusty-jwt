using Rusty.Jwt.Keys;

namespace Rusty.Jwt;

internal static class SigningAlgorithmExtensions
{
    public static string GetPrefix(this SigningKeyAlgorithm algorithm)
    {
        return algorithm switch
        {
            SigningKeyAlgorithm.Rsa => "RS",
            SigningKeyAlgorithm.EllipticCurve => "ES",
            SigningKeyAlgorithm.Hmac => "HS",
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
        };
    }
}