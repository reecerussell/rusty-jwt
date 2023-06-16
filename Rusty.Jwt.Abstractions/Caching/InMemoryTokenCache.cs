using System.Collections.Concurrent;

namespace Rusty.Jwt.Caching;

public class InMemoryTokenCache : ITokenCache
{
    private readonly ISystemClock _systemClock;
    private readonly ConcurrentDictionary<string, TokenCacheValue> _items;

    public InMemoryTokenCache(ISystemClock systemClock)
    {
        _systemClock = systemClock;
        _items = new ConcurrentDictionary<string, TokenCacheValue>();
    }
    
    public Task<TokenCacheValue?> GetAsync(string token, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        
        if (!_items.TryGetValue(token, out var result))
        {
            return Task.FromResult<TokenCacheValue?>(null);
        }

        if (result.Expiry < _systemClock.Now)
        {
            _ = _items.TryRemove(token, out _);
            
            return Task.FromResult<TokenCacheValue?>(null);
        }

        return Task.FromResult<TokenCacheValue?>(result);
    }

    public Task SetAsync(string token, TokenCacheValue value, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        
        _ = _items.TryAdd(token, value);
        
        return Task.CompletedTask;
    }
}