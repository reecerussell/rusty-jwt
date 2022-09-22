namespace Rusty.Jwt.Keys;

/// <summary>
/// Used to indicate what signing algorithm a <see cref="ISigningKey"/> is using.
/// </summary>
public enum SigningKeyAlgorithm
{
    Rsa,
    EllipticCurve,
    Hmac
}