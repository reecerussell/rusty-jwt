namespace Rusty.Jwt;

public class JwtClaimTypes
{
    /// <summary>
    /// Gets the key for the Issuer claim.
    /// </summary>
    public const string Issuer = "iss";
    
    /// <summary>
    /// Gets the key for the Audience claim.
    /// </summary>
    public const string Audience = "aud";
    
    /// <summary>
    /// Gets the key for the Subject claim.
    /// </summary>
    public const string Subject = "sub";
    
    /// <summary>
    /// Gets the key for the Expiry claim.
    /// </summary>
    public const string Expiry = "exp";
    
    /// <summary>
    /// Gets the key for the NotBefore claim.
    /// </summary>
    public const string NotBefore = "nbf";
    
    /// <summary>
    /// Gets the key for the IssuedAt claim.
    /// </summary>
    public const string IssuedAt = "iat";
}