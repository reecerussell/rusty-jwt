using System.Text;
using Azure.Security.KeyVault.Keys;
using FluentAssertions;
using Rusty.Jwt.Keys;

namespace Rusty.Jwt.Azure.Tests;

public class AzureSigningKeyTests
{
    [Theory(Skip = "Key rework")]
    [InlineData("rsa", HashAlgorithm.SHA256, SigningKeyAlgorithm.Rsa)]
    [InlineData("rsa", HashAlgorithm.SHA384, SigningKeyAlgorithm.Rsa)]
    [InlineData("rsa", HashAlgorithm.SHA512, SigningKeyAlgorithm.Rsa)]
    [InlineData("elliptic-curve", HashAlgorithm.SHA256, SigningKeyAlgorithm.EllipticCurve)]
    [InlineData("elliptic-curve-384", HashAlgorithm.SHA384, SigningKeyAlgorithm.EllipticCurve)]
    [InlineData("elliptic-curve-512", HashAlgorithm.SHA512, SigningKeyAlgorithm.EllipticCurve)]
    public void Ctor_GivenValidCredentials_ReturnsInstance(string keyName,
        HashAlgorithm hashAlgorithm, SigningKeyAlgorithm expectedAlgorithm)
    {
        var key = new AzureSigningKey(new KeyVaultKey(keyName),
            Credentials.Default,
            hashAlgorithm);

        key.Id.Should().NotBeNullOrWhiteSpace();
        key.HashAlgorithm.Should().Be(hashAlgorithm);
        key.Algorithm.Should().Be(expectedAlgorithm);
    }
    
    [Theory(Skip = "Key rework")]
    [InlineData("rsa", HashAlgorithm.SHA256)]
    [InlineData("rsa", HashAlgorithm.SHA384)]
    [InlineData("rsa", HashAlgorithm.SHA512)]
    [InlineData("elliptic-curve", HashAlgorithm.SHA256)]
    [InlineData("elliptic-curve-384", HashAlgorithm.SHA384)]
    [InlineData("elliptic-curve-512", HashAlgorithm.SHA512)]
    public async Task SignAsync_GivenValidData_ReturnsASignature(string keyName, HashAlgorithm hashAlgorithm)
    {
        var key = new AzureSigningKey(new KeyVaultKey(keyName),
            Credentials.Default,
            hashAlgorithm);

        var data = Encoding.UTF8.GetBytes("hello world");
        var signature = await key.SignAsync(data, CancellationToken.None);
        signature.Should().NotBeNull();
        signature.Should().NotBeEmpty();
    }
    
    [Fact(Skip = "Key rework")]
    public async Task SignAsync_InvalidHashAlgorithm_Throws()
    {
        var key = new AzureSigningKey(new KeyVaultKey("foo"),
            Credentials.Default,
            (HashAlgorithm)39443);

        var data = Encoding.UTF8.GetBytes("hello world");

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => key.SignAsync(data, CancellationToken.None));
    }
}