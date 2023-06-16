namespace Rusty.Jwt.Caching;

/// <summary>
/// Used to cache key token verification data, to ease the load on third-part APIs.
/// </summary>
public interface ITokenCache
{
    /// <summary>
    /// Used to retrieve a cached token value, containing the verification result.
    /// </summary>
    /// <param name="token">The token to fetch the result of.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>
    ///     Returns a cached token value containing the verification result.
    /// </returns>
    Task<TokenCacheValue?> GetAsync(string token, CancellationToken cancellationToken);
    
    /// <summary>
    /// Used to set a token value in the cache.
    /// </summary>
    /// <param name="token">The token to cache a value of.</param>
    /// <param name="value">The value to cache.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    Task SetAsync(string token, TokenCacheValue value, CancellationToken cancellationToken);
}