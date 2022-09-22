using Base64Extensions;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;

namespace Rusty.Jwt.Tests;

public class HmacEndToEndTests : IAsyncLifetime
{
    private IJwtFactory _factory;
    private IJwtVerifier _verifier;
    private Jwt _jwt;

    private const string ClaimName = "foo";
    private const string ClaimValue = "bar";
    private const int SecondsTtl = 3600;

    public async Task InitializeAsync()
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddRustyJwt()
            .AddHmacSigningKey("foo", HashAlgorithm.SHA256, "Key1", SigningKeyMode.SignAndVerify);

        var services = serviceCollection.BuildServiceProvider();

        _factory = services.GetRequiredService<IJwtFactory>();
        _verifier = services.GetRequiredService<IJwtVerifier>();

        _jwt = await _factory.CreateAsync(claims =>
        {
            claims[ClaimName] = ClaimValue;
            claims.Expiry = DateTimeOffset.UtcNow.AddSeconds(SecondsTtl);
        }, CancellationToken.None);
    }

    public Task DisposeAsync()
    {
        return Task.CompletedTask;
    }

    [Fact]
    public void ThenTheJwtShouldBeCorrect()
    {
        _jwt.Should().NotBeNull();
        _jwt.Id.Should().NotBeNullOrWhiteSpace();
        _jwt.Token.Should().NotBeNullOrWhiteSpace();
        _jwt.ExpiresIn.Should().BeCloseTo(SecondsTtl, 1);
    }

    [Fact]
    public void ThenTheTokenHeaderContainsTheCorrectValues()
    {
        var parts = _jwt.Token.Split('.');
        var values = JsonConvert.DeserializeObject<Dictionary<string, string>>(Base64Convert.Decode(parts[0]))!;
        values["typ"].Should().Be("jwt");
        values["jti"].Should().Be(_jwt.Id);
        values["kid"].Should().Be("3A221AFF-C802-4BA1-80C4-49BA2981D023");
        values["alg"].Should().Be("HS256");
    }
    
    [Fact]
    public void ThenTheTokenClaimsContainsTheCorrectValues()
    {
        var parts = _jwt.Token.Split('.');
        var values = JsonConvert.DeserializeObject<Dictionary<string, string>>(Base64Convert.Decode(parts[1]))!;
        values[ClaimName].Should().Be(ClaimValue);
        values["exp"].Should().NotBeNull();
    }

    [Fact]
    public async Task ThenTheTokenIsValid()
    {
        var values = await _verifier.VerifyAsync(_jwt.Token, CancellationToken.None);
        values[ClaimName].Should().Be(ClaimValue);
    }
}