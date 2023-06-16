using System.Collections.Concurrent;
using System.Reflection;
using FluentAssertions;
using Moq;
using Rusty.Jwt.Caching;

namespace Rusty.Jwt.Tests.Caching;

public class InMemoryTokenCacheTests
{
    [Fact]
    public async Task GetAsync_WhereCacheHits_ReturnsResult()
    {
        var now = DateTime.UtcNow;
        var token = "320742304";
        var value = new TokenCacheValue
        {
            Valid = true,
            Expiry = now.AddMinutes(5)
        };
        var cancellationToken = new CancellationToken();

        var clock = new Mock<ISystemClock>();
        clock.SetupGet(x => x.Now).Returns(now);

        var cache = new InMemoryTokenCache(clock.Object);

        var items = new ConcurrentDictionary<string, TokenCacheValue>
        {
            [token] = value
        };
        typeof(InMemoryTokenCache).GetField("_items", BindingFlags.NonPublic | BindingFlags.Instance)!
            .SetValue(cache, items);

        var result = await cache.GetAsync(token, cancellationToken);
        result.Should().Be(value);
    }
    
    [Fact]
    public async Task GetAsync_WhereCacheMisses_ReturnsNull()
    {
        var now = DateTime.UtcNow;
        var token = "320742304";
        var cancellationToken = new CancellationToken();

        var clock = new Mock<ISystemClock>();
        clock.SetupGet(x => x.Now).Returns(now);

        var cache = new InMemoryTokenCache(clock.Object);

        var result = await cache.GetAsync(token, cancellationToken);
        result.Should().BeNull();
    }
    
    [Fact]
    public async Task GetAsync_WhereCacheHitsByValueHasExpired_ReturnsNull()
    {
        var now = DateTime.UtcNow;
        var token = "320742304";
        var value = new TokenCacheValue
        {
            Valid = true,
            Expiry = now.AddMinutes(-5)
        };
        var cancellationToken = new CancellationToken();

        var clock = new Mock<ISystemClock>();
        clock.SetupGet(x => x.Now).Returns(now);

        var cache = new InMemoryTokenCache(clock.Object);

        var items = new ConcurrentDictionary<string, TokenCacheValue>
        {
            [token] = value
        };
        typeof(InMemoryTokenCache).GetField("_items", BindingFlags.NonPublic | BindingFlags.Instance)!
            .SetValue(cache, items);

        var result = await cache.GetAsync(token, cancellationToken);
        result.Should().BeNull();
        
        // Item has been cleared from cache.
        items.Count.Should().Be(0);
    }
    
    [Fact]
    public async Task GetAsync_WhereCancellationHasBeenRequested_Throws()
    {
        var token = "320742304";
        var cancellationToken = new CancellationToken(true);

        var clock = new Mock<ISystemClock>();
        var cache = new InMemoryTokenCache(clock.Object);

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => cache.GetAsync(token, cancellationToken));
    }

    [Fact]
    public async Task SetAsync_GivenValidInput_SetsInCache()
    {
        var now = DateTime.UtcNow;
        var token = "320742304";
        var value = new TokenCacheValue
        {
            Valid = true,
            Expiry = now.AddMinutes(-5)
        };
        var cancellationToken = new CancellationToken();

        var clock = new Mock<ISystemClock>();
        var cache = new InMemoryTokenCache(clock.Object);

        await cache.SetAsync(token, value, cancellationToken);

        var items = (ConcurrentDictionary<string, TokenCacheValue>)typeof(InMemoryTokenCache)
            .GetField("_items", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(cache)!;

        items.Count.Should().Be(1);
        items[token].Should().Be(value);
    }
    
    [Fact]
    public async Task SetAsync_WhereCancellationHasBeenRequested_Throws()
    {
        var now = DateTime.UtcNow;
        var token = "320742304";
        var value = new TokenCacheValue
        {
            Valid = true,
            Expiry = now.AddMinutes(-5)
        };
        var cancellationToken = new CancellationToken(true);

        var clock = new Mock<ISystemClock>();
        var cache = new InMemoryTokenCache(clock.Object);

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => cache.SetAsync(token, value, cancellationToken));
    }
}