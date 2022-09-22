using System.Text;
using Base64Extensions;
using FluentAssertions;
using Moq;
using Newtonsoft.Json;
using RNG = System.Security.Cryptography.RandomNumberGenerator;

namespace Rusty.Jwt.Tests;

public class JwtFactoryTests
{
    [Fact]
    public async Task CreateAsync_GivenSigningKeyAndClaims_CreatesJwt()
    {
        const string keyId = "F941AB44-94C4-4B92-8DCB-E08FEAC2AC6C";
        var cancellationToken = new CancellationToken();

        var signature = new byte[25];
        RNG.Fill(signature);

        var key = new Mock<ISigningKey>();
        key.SetupGet(x => x.Id).Returns(keyId);
        key.SetupGet(x => x.Algorithm).Returns(SigningKeyAlgorithm.Rsa);
        key.SetupGet(x => x.HashAlgorithm).Returns(HashAlgorithm.SHA256);
        key.Setup(x => x.SignAsync(It.IsAny<byte[]>(), cancellationToken))
            .ReturnsAsync(signature);

        var keyRing = new Mock<IKeyRing>();
        keyRing.Setup(x => x.GetSigningKey())
            .Returns(key.Object);

        var factory = new JwtFactory(keyRing.Object);
        var jwt = await factory.CreateAsync(c =>
        {
            c["foo"] = "bar";
        }, cancellationToken);

        var parts = jwt.Token.Split(".");
        var header = JsonConvert.DeserializeObject<Dictionary<string, string>>(Base64Convert.Decode(parts[0]))!;
        header["jti"].Should().NotBeNullOrEmpty();
        header["kid"].Should().Be(keyId);
        header["alg"].Should().Be("RS256");
        header["typ"].Should().Be("jwt");
        
        var claims = JsonConvert.DeserializeObject<Dictionary<string, string>>(Base64Convert.Decode(parts[1]))!;
        claims["foo"].Should().Be("bar");

        parts[2].Should().Be(Encoding.UTF8.GetString(Base64Convert.Encode(signature, true)));
    }
    
    [Fact]
    public async Task CreateAsync_GivenSigningKeyName_CreatesJwt()
    {
        const string keyId = "F941AB44-94C4-4B92-8DCB-E08FEAC2AC6C";
        const string keyName = "test";
        var cancellationToken = new CancellationToken();

        var signature = new byte[25];
        RNG.Fill(signature);

        var key = new Mock<ISigningKey>();
        key.SetupGet(x => x.Id).Returns(keyId);
        key.SetupGet(x => x.Algorithm).Returns(SigningKeyAlgorithm.Rsa);
        key.SetupGet(x => x.HashAlgorithm).Returns(HashAlgorithm.SHA256);
        key.Setup(x => x.SignAsync(It.IsAny<byte[]>(), cancellationToken))
            .ReturnsAsync(signature);

        var keyRing = new Mock<IKeyRing>();
        keyRing.Setup(x => x.GetSigningKey(keyName))
            .Returns(key.Object);

        var factory = new JwtFactory(keyRing.Object);
        var jwt = await factory.CreateAsync(c =>
        {
            c["foo"] = "bar";
        }, keyName, cancellationToken);

        var parts = jwt.Token.Split(".");
        var header = JsonConvert.DeserializeObject<Dictionary<string, string>>(Base64Convert.Decode(parts[0]))!;
        header["jti"].Should().NotBeNullOrEmpty();
        header["kid"].Should().Be(keyId);
        header["alg"].Should().Be("RS256");
        
        var claims = JsonConvert.DeserializeObject<Dictionary<string, string>>(Base64Convert.Decode(parts[1]))!;
        claims["foo"].Should().Be("bar");

        parts[2].Should().Be(Encoding.UTF8.GetString(Base64Convert.Encode(signature, true)));
    }
}