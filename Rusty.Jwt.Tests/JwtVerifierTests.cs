using System.Text;
using Base64Extensions;
using FluentAssertions;
using Moq;

namespace Rusty.Jwt.Tests;

public class JwtVerifierTests
{
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task VerifyAsync_GivenEmptyToken_ThrowsInvalidToken(string token)
    {
        var keyRing = new Mock<IKeyRing>();
        var verifier = new JwtVerifier(keyRing.Object);

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
        var verifier = new JwtVerifier(keyRing.Object);

        await Assert.ThrowsAsync<InvalidTokenException>(
            () => verifier.VerifyAsync(token, CancellationToken.None));
    }
    
    [Theory]
    [InlineData("not base 64.324324.234234")]
    [InlineData("aGVsbG8ud29ybGQK.ewjrlwer.ewrwerwe")] // not json
    public async Task VerifyAsync_GivenTokenWithInvalidHeader_ThrowsInvalidToken(string token)
    {
        var keyRing = new Mock<IKeyRing>();
        var verifier = new JwtVerifier(keyRing.Object);

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

        var dataBytes = Encoding.UTF8.GetBytes(tokenData);
        var signatureBytes = Encoding.UTF8.GetBytes(Base64Convert.Decode(signatureData));
        
        var key = new Mock<ISigningKey>();
        key.Setup(x => x.VerifyAsync(dataBytes, signatureBytes, cancellationToken))
            .ReturnsAsync(true)
            .Verifiable();

        var keyRing = new Mock<IKeyRing>();
        keyRing.Setup(x => x.GetVerificationKey(keyId))
            .Returns(key.Object)
            .Verifiable();

        var verifier = new JwtVerifier(keyRing.Object);
        var claims = await verifier.VerifyAsync($"{tokenData}.{signatureData}", cancellationToken);

        claims["sub"].Should().Be("1234567890");
        
        key.VerifyAll();
        keyRing.VerifyAll();
    }
    
    [Fact]
    public async Task VerifyAsync_WhereTokensKeyIsNotFound_VerifiesWithDefaultKey()
    {
        const string tokenData = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        const string signatureData = "LoE9f0HmUNvJ9td_O0327K6yWgUqGp4GrRYLpH6ca1c";
        const string keyId = "123";
        var cancellationToken = new CancellationToken();

        var dataBytes = Encoding.UTF8.GetBytes(tokenData);
        var signatureBytes = Encoding.UTF8.GetBytes(Base64Convert.Decode(signatureData));
        
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

        var verifier = new JwtVerifier(keyRing.Object);
        var claims = await verifier.VerifyAsync($"{tokenData}.{signatureData}", cancellationToken);

        claims["sub"].Should().Be("1234567890");
        
        key.VerifyAll();
        keyRing.VerifyAll();
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

        var dataBytes = Encoding.UTF8.GetBytes(tokenData);
        var signatureBytes = Encoding.UTF8.GetBytes(Base64Convert.Decode(signatureData));
        
        var key = new Mock<ISigningKey>();
        key.Setup(x => x.VerifyAsync(dataBytes, signatureBytes, cancellationToken))
            .ReturnsAsync(true)
            .Verifiable();

        var keyRing = new Mock<IKeyRing>();
        keyRing.Setup(x => x.GetVerificationKey(algorithm, hashAlgorithm))
            .Returns(key.Object)
            .Verifiable();

        var verifier = new JwtVerifier(keyRing.Object);
        var claims = await verifier.VerifyAsync($"{tokenData}.{signatureData}", cancellationToken);

        claims["sub"].Should().Be("1234567890");
        
        key.VerifyAll();
        keyRing.VerifyAll();
    }
    
    [Fact]
    public async Task VerifyAsync_WhereSignatureIsInvalid_ThrowsInvalidToken()
    {
        const string tokenData = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        const string signatureData = "LoE9f0HmUNvJ9td_O0327K6yWgUqGp4GrRYLpH6ca1c";
        var cancellationToken = new CancellationToken();

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

        var verifier = new JwtVerifier(keyRing.Object);

        await Assert.ThrowsAsync<InvalidTokenException>(
            () => verifier.VerifyAsync($"{tokenData}.{signatureData}", cancellationToken));
    }
    
    [Theory]
    [InlineData("not base 64")]
    [InlineData("aGVsbG8K")] // not json
    public async Task VerifyAsync_WherePayloadIsNotValid_ThrowsInvalidToken(string payload)
    {
        var tokenData = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + payload;
        const string signatureData = "LoE9f0HmUNvJ9td_O0327K6yWgUqGp4GrRYLpH6ca1c";
        var cancellationToken = new CancellationToken();

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

        var verifier = new JwtVerifier(keyRing.Object);

        await Assert.ThrowsAsync<InvalidTokenException>(
            () => verifier.VerifyAsync($"{tokenData}.{signatureData}", cancellationToken));
    }
    
    [Fact]
    public async Task VerifyAsync_WhereAlgorithmIsNotSupported_ThrowsInvalidToken()
    {
        // {"alg":"XS256"}
        const string token = "eyd0eXAnOidqd3QnLCdhbGcnOidYUzI1Nid9Cg.eyJzdWIiOiIxMjM0NTY3ODkwIn0.LoE9f0HmUNvJ9td_O0327K6yWgUqGp4GrRYLpH6ca1c";
        var cancellationToken = new CancellationToken();

        var verifier = new JwtVerifier(Mock.Of<IKeyRing>());

        await Assert.ThrowsAsync<InvalidTokenException>(
            () => verifier.VerifyAsync(token, cancellationToken));
    }
    
    [Fact]
    public async Task VerifyAsync_WhereHashAlgorithmIsNotSupported_ThrowsInvalidToken()
    {
        // {"alg":"XS256"}
        const string token = "eyd0eXAnOidqd3QnLCdhbGcnOidSWDI3Mid9Cg.eyJzdWIiOiIxMjM0NTY3ODkwIn0.LoE9f0HmUNvJ9td_O0327K6yWgUqGp4GrRYLpH6ca1c";
        var cancellationToken = new CancellationToken();

        var verifier = new JwtVerifier(Mock.Of<IKeyRing>());

        await Assert.ThrowsAsync<InvalidTokenException>(
            () => verifier.VerifyAsync(token, cancellationToken));
    }
}