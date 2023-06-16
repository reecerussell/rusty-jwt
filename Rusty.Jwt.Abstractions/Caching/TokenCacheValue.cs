namespace Rusty.Jwt.Caching;

public record struct TokenCacheValue
{
    public bool Valid { get; set; }
    public DateTime Expiry { get; set; }
}