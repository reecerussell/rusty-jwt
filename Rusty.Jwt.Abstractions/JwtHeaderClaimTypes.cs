namespace Rusty.Jwt;

public class JwtHeaderClaimTypes
{
    /// <summary>
    /// Gets the key for the Id header value.
    /// </summary>
    public const string Id = "jti";

    /// <summary>
    /// Gets the key for the KeyId header value.
    /// </summary>
    public const string KeyId = "kid";

    /// <summary>
    /// Gets the key for the Algorithm header value.
    /// </summary>
    public const string Algorithm = "alg";
    
    /// <summary>
    /// Gets the key for the Type header value.
    /// </summary>
    public const string Type = "typ";
}