namespace Rusty.Jwt.Keys;

/// <summary>
/// Used to determine how a <see cref="ISigningKey"/> is used.
/// </summary>
public enum SigningKeyMode
{
    /// <summary>
    /// Indicates that a <see cref="ISigningKey"/> can be used to
    /// both sign and verify data.
    /// </summary>
    SignAndVerify,
    
    /// <summary>
    /// Indicates that a <see cref="ISigningKey"/> can only be
    /// used to verify data.
    /// </summary>
    VerifyOnly
}