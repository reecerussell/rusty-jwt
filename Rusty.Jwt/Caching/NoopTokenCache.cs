namespace Rusty.Jwt.Caching;

public class NoopTokenCache : ITokenCache
{
    public Task<TokenCacheValue?> GetAsync(string token, CancellationToken cancellationToken)
    {
        return Task.FromResult<TokenCacheValue?>(null);
    }

    public Task SetAsync(string token, TokenCacheValue value, CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}