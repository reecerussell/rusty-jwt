using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;

namespace Rusty.Jwt.Tests.Extensions;

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddSigningKey_GivenType_RegistersKey()
    {
        var collection = new ServiceCollection();
        var builder = collection.AddRustyJwt();
        builder.Should().NotBeNull();

        var services = collection.BuildServiceProvider();
        services.GetRequiredService<IJwtFactory>().Should().BeOfType<JwtFactory>();
        services.GetRequiredService<IKeyRing>().Should().BeOfType<KeyRing>();
    }
}