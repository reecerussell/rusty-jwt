using FluentAssertions;
using Rusty.Jwt.Caching;

namespace Rusty.Jwt.Tests.Caching;

public class NoopTokenCacheTests
{
    [Fact]
    public async Task GetAsync_GivenAnyInput_ReturnsNull()
    {
        var cache = new NoopTokenCache();
        var result = await cache.GetAsync("token", new CancellationToken());

        result.Should().BeNull();
    }

    [Fact]
    public void SetAsync_GivenAnyInput_ReturnsCompletedTask()
    {
        var cache = new NoopTokenCache();
        var task = cache.SetAsync("token", new TokenCacheValue(), new CancellationToken());

        task.IsCompleted.Should().BeTrue();
    }
}