using System.Text;
using Base64Extensions;
using FluentAssertions;
using Moq;
using Rusty.Jwt.Caching;

namespace Rusty.Jwt.Tests;

public class JwtVerifierTests
{
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task VerifyAsync_GivenEmptyToken_ThrowsInvalidToken(string token)
    {
        var keyRing = new Mock<IKeyRing>();
        var verifier = CreateService(keyRing: keyRing.Object);

        await Assert.ThrowsAsync<InvalidTokenException>(
            () => verifier.VerifyAsync(token, CancellationToken.None));
    }
    
    [Theory]
    [InlineData("hello")]
    [InlineData("hello.world")]
    [InlineData("one.two.three.four")]
    public async Task VerifyAsync_GivenTokenWithInvalidStructure_ThrowsInvalidToken(string token)
    {
        var keyRing = new Mock<IKeyRing>();
        var verifier = CreateService(keyRing: keyRing.Object);

        await Assert.ThrowsAsync<InvalidTokenException>(
            () => verifier.VerifyAsync(token, CancellationToken.None));
    }
    
    [Theory]
    [InlineData("not base 64.324324.234234")]
    [InlineData("aGVsbG8ud29ybGQK.ewjrlwer.ewrwerwe")] // not json
    public async Task VerifyAsync_GivenTokenWithInvalidHeader_ThrowsInvalidToken(string token)
    {
        var keyRing = new Mock<IKeyRing>();
        var verifier = CreateService(keyRing: keyRing.Object);

        await Assert.ThrowsAsync<InvalidTokenException>(
            () => verifier.VerifyAsync(token, CancellationToken.None));
    }

    [Fact]
    public async Task VerifyAsync_GivenTokenWithKeyId_VerifiesWithTheCorrectKey()
    {
        const string tokenData = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        const string signatureData = "LoE9f0HmUNvJ9td_O0327K6yWgUqGp4GrRYLpH6ca1c";
        const string keyId = "123";
        var cancellationToken = new CancellationToken();
        var now = DateTime.Now;

        var dataBytes = Encoding.UTF8.GetBytes(tokenData);
        var signatureBytes = Base64Convert.Decode(Encoding.UTF8.GetBytes(signatureData));
        
        var key = new Mock<ISigningKey>();
        key.Setup(x => x.VerifyAsync(dataBytes, signatureBytes, cancellationToken))
            .ReturnsAsync(true)
            .Verifiable();

        var keyRing = new Mock<IKeyRing>();
        keyRing.Setup(x => x.GetVerificationKey(keyId))
            .Returns(key.Object)
            .Verifiable();

        var clock = new Mock<ISystemClock>();
        clock.SetupGet(x => x.Now).Returns(now);

        var cache = new Mock<ITokenCache>();
        cache.Setup(x => x.GetAsync($"{tokenData}.{signatureData}", cancellationToken))
            .ReturnsAsync((TokenCacheValue?) null)
            .Verifiable();
        cache.Setup(x => x.SetAsync($"{tokenData}.{signatureData}", It.Is<TokenCacheValue>(d =>
                d.Valid == true &&
                d.Expiry == now.AddMinutes(JwtVerifier.DefaultCacheMinutes)), cancellationToken))
            .Verifiable();

        var verifier = CreateService(
            keyRing: keyRing.Object,
            tokenCache: cache.Object,
            systemClock: clock.Object);
        var claims = await verifier.VerifyAsync($"{tokenData}.{signatureData}", cancellationToken);

        claims["sub"].Should().Be("1234567890");
        
        key.VerifyAll();
        keyRing.VerifyAll();
        cache.VerifyAll();
    }
    
    [Fact]
    public async Task VerifyAsync_GivenCachedToken_BypassesVerification()
    {
        const string tokenData = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        const string signatureData = "LoE9f0HmUNvJ9td_O0327K6yWgUqGp4GrRYLpH6ca1c";
        const string keyId = "123";
        var cancellationToken = new CancellationToken();
        var now = DateTime.Now;

        var clock = new Mock<ISystemClock>();
        clock.SetupGet(x => x.Now).Returns(now);

        var cache = new Mock<ITokenCache>();
        cache.Setup(x => x.GetAsync($"{tokenData}.{signatureData}", cancellationToken))
            .ReturnsAsync(new TokenCacheValue{Valid = true})
            .Verifiable();

        var verifier = CreateService(
            tokenCache: cache.Object,
            systemClock: clock.Object);
        var claims = await verifier.VerifyAsync($"{tokenData}.{signatureData}", cancellationToken);

        claims["sub"].Should().Be("1234567890");

        cache.VerifyAll();
    }
    
    [Fact]
    public async Task VerifyAsync_WhereTokensKeyIsNotFound_VerifiesWithDefaultKey()
    {
        const string tokenData = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        const string signatureData = "LoE9f0HmUNvJ9td_O0327K6yWgUqGp4GrRYLpH6ca1c";
        const string keyId = "123";
        var cancellationToken = new CancellationToken();
        var now = DateTime.Now;

        var dataBytes = Encoding.UTF8.GetBytes(tokenData);
        var signatureBytes = Base64Convert.Decode(Encoding.UTF8.GetBytes(signatureData));
        
        var key = new Mock<ISigningKey>();
        key.Setup(x => x.VerifyAsync(dataBytes, signatureBytes, cancellationToken))
            .ReturnsAsync(true)
            .Verifiable();

        var keyRing = new Mock<IKeyRing>();
        keyRing.Setup(x => x.GetVerificationKey(keyId))
            .Returns((IVerificationKey?) null)
            .Verifiable();
        keyRing.Setup(x => x.GetVerificationKey(SigningKeyAlgorithm.Hmac, HashAlgorithm.SHA256))
            .Returns(key.Object)
            .Verifiable();

        var clock = new Mock<ISystemClock>();
        clock.SetupGet(x => x.Now).Returns(now);

        var cache = new Mock<ITokenCache>();
        cache.Setup(x => x.GetAsync($"{tokenData}.{signatureData}", cancellationToken))
            .ReturnsAsync((TokenCacheValue?) null)
            .Verifiable();
        cache.Setup(x => x.SetAsync($"{tokenData}.{signatureData}", It.Is<TokenCacheValue>(d =>
                d.Valid == true &&
                d.Expiry == now.AddMinutes(JwtVerifier.DefaultCacheMinutes)), cancellationToken))
            .Verifiable();

        var verifier = CreateService(
            keyRing: keyRing.Object,
            tokenCache: cache.Object,
            systemClock: clock.Object);
        var claims = await verifier.VerifyAsync($"{tokenData}.{signatureData}", cancellationToken);

        claims["sub"].Should().Be("1234567890");
        
        key.VerifyAll();
        keyRing.VerifyAll();
        cache.VerifyAll();
    }
    
    [Theory]
    [InlineData("eyd0eXAnOidqd3QnLCdhbGcnOidIUzI1Nid9Cg==", SigningKeyAlgorithm.Hmac, HashAlgorithm.SHA256)]
    [InlineData("eyd0eXAnOidqd3QnLCdhbGcnOidSUzM4NCd9Cg==", SigningKeyAlgorithm.Rsa, HashAlgorithm.SHA384)]
    [InlineData("eyd0eXAnOidqd3QnLCdhbGcnOidFUzUxMid9Cg==", SigningKeyAlgorithm.EllipticCurve, HashAlgorithm.SHA512)]
    public async Task VerifyAsync_WhereTokenHasNoKeyId_VerifiesWithDefaultKey(string header,
        SigningKeyAlgorithm algorithm, HashAlgorithm hashAlgorithm)
    {
        var tokenData = header + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        const string signatureData = "LoE9f0HmUNvJ9td_O0327K6yWgUqGp4GrRYLpH6ca1c";
        var cancellationToken = new CancellationToken();
        var now = DateTime.Now;

        var dataBytes = Encoding.UTF8.GetBytes(tokenData);
        var signatureBytes = Base64Convert.Decode(Encoding.UTF8.GetBytes(signatureData));
        
        var key = new Mock<ISigningKey>();
        key.Setup(x => x.VerifyAsync(dataBytes, signatureBytes, cancellationToken))
            .ReturnsAsync(true)
            .Verifiable();

        var keyRing = new Mock<IKeyRing>();
        keyRing.Setup(x => x.GetVerificationKey(algorithm, hashAlgorithm))
            .Returns(key.Object)
            .Verifiable();
        
        var clock = new Mock<ISystemClock>();
        clock.SetupGet(x => x.Now).Returns(now);

        var cache = new Mock<ITokenCache>();
        cache.Setup(x => x.GetAsync($"{tokenData}.{signatureData}", cancellationToken))
            .ReturnsAsync((TokenCacheValue?) null)
            .Verifiable();
        cache.Setup(x => x.SetAsync($"{tokenData}.{signatureData}", It.Is<TokenCacheValue>(d =>
                d.Valid == true &&
                d.Expiry == now.AddMinutes(JwtVerifier.DefaultCacheMinutes)), cancellationToken))
            .Verifiable();

        var verifier = CreateService(
            keyRing: keyRing.Object,
            tokenCache: cache.Object,
            systemClock: clock.Object);
        
        var claims = await verifier.VerifyAsync($"{tokenData}.{signatureData}", cancellationToken);

        claims["sub"].Should().Be("1234567890");
        
        key.VerifyAll();
        keyRing.VerifyAll();
        cache.VerifyAll();
    }
    
    [Fact]
    public async Task VerifyAsync_WhereSignatureIsInvalid_ThrowsInvalidToken()
    {
        const string tokenData = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        const string signatureData = "LoE9f0HmUNvJ9td_O0327K6yWgUqGp4GrRYLpH6ca1c";
        var cancellationToken = new CancellationToken();
        var now = DateTime.Now;

        var dataBytes = Encoding.UTF8.GetBytes(tokenData);
        var signatureBytes = Encoding.UTF8.GetBytes(Base64Convert.Decode(signatureData));
        
        var key = new Mock<ISigningKey>();
        key.Setup(x => x.VerifyAsync(dataBytes, signatureBytes, cancellationToken))
            .ReturnsAsync(false)
            .Verifiable();

        var keyRing = new Mock<IKeyRing>();
        keyRing.Setup(x => x.GetVerificationKey(SigningKeyAlgorithm.Hmac, HashAlgorithm.SHA256))
            .Returns(key.Object)
            .Verifiable();
        
        var clock = new Mock<ISystemClock>();
        clock.SetupGet(x => x.Now).Returns(now);

        var cache = new Mock<ITokenCache>();
        cache.Setup(x => x.GetAsync($"{tokenData}.{signatureData}", cancellationToken))
            .ReturnsAsync((TokenCacheValue?) null)
            .Verifiable();
        cache.Setup(x => x.SetAsync($"{tokenData}.{signatureData}", It.Is<TokenCacheValue>(d =>
                d.Valid == false &&
                d.Expiry == now.AddMinutes(JwtVerifier.DefaultCacheMinutes)), cancellationToken))
            .Verifiable();

        var verifier = CreateService(
            keyRing: keyRing.Object,
            tokenCache: cache.Object,
            systemClock: clock.Object);

        await Assert.ThrowsAsync<InvalidTokenException>(
            () => verifier.VerifyAsync($"{tokenData}.{signatureData}", cancellationToken));
        
        cache.VerifyAll();
    }
    
    [Theory]
    [InlineData("not base 64")]
    [InlineData("aGVsbG8K")] // not json
    public async Task VerifyAsync_WherePayloadIsNotValid_ThrowsInvalidToken(string payload)
    {
        var tokenData = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + payload;
        const string signatureData = "LoE9f0HmUNvJ9td_O0327K6yWgUqGp4GrRYLpH6ca1c";
        var cancellationToken = new CancellationToken();
        var now = DateTime.Now;

        var dataBytes = Encoding.UTF8.GetBytes(tokenData);
        var signatureBytes = Encoding.UTF8.GetBytes(Base64Convert.Decode(signatureData));
        
        var key = new Mock<ISigningKey>();
        key.Setup(x => x.VerifyAsync(dataBytes, signatureBytes, cancellationToken))
            .ReturnsAsync(true)
            .Verifiable();

        var keyRing = new Mock<IKeyRing>();
        keyRing.Setup(x => x.GetVerificationKey(SigningKeyAlgorithm.Hmac, HashAlgorithm.SHA256))
            .Returns(key.Object)
            .Verifiable();
        
        var clock = new Mock<ISystemClock>();
        clock.SetupGet(x => x.Now).Returns(now);

        var cache = new Mock<ITokenCache>();
        cache.Setup(x => x.GetAsync($"{tokenData}.{signatureData}", cancellationToken))
            .ReturnsAsync((TokenCacheValue?) null)
            .Verifiable();
        cache.Setup(x => x.SetAsync($"{tokenData}.{signatureData}", It.Is<TokenCacheValue>(d =>
                d.Valid == false &&
                d.Expiry == now.AddMinutes(JwtVerifier.DefaultCacheMinutes)), cancellationToken))
            .Verifiable();

        var verifier = CreateService(
            keyRing: keyRing.Object,
            tokenCache: cache.Object,
            systemClock: clock.Object);

        await Assert.ThrowsAsync<InvalidTokenException>(
            () => verifier.VerifyAsync($"{tokenData}.{signatureData}", cancellationToken));
        
        cache.VerifyAll();
    }
    
    [Fact]
    public async Task VerifyAsync_WhereAlgorithmIsNotSupported_ThrowsInvalidToken()
    {
        // {"alg":"XS256"}
        const string token = "eyd0eXAnOidqd3QnLCdhbGcnOidYUzI1Nid9Cg.eyJzdWIiOiIxMjM0NTY3ODkwIn0.LoE9f0HmUNvJ9td_O0327K6yWgUqGp4GrRYLpH6ca1c";
        var cancellationToken = new CancellationToken();

        var verifier = CreateService();

        await Assert.ThrowsAsync<InvalidTokenException>(
            () => verifier.VerifyAsync(token, cancellationToken));
    }

    private static JwtVerifier CreateService(
        IKeyRing? keyRing = null,
        ITokenCache? tokenCache = null,
        ISystemClock? systemClock = null)
    {
        keyRing ??= Mock.Of<IKeyRing>();
        tokenCache ??= Mock.Of<ITokenCache>();
        systemClock ??= Mock.Of<ISystemClock>();

        return new JwtVerifier(keyRing, tokenCache, systemClock);
    }
}