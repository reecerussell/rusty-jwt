using System.Text;
using FluentAssertions;
using Rusty.Jwt.Keys;

namespace Rusty.Jwt.Azure.Tests;

public class AzureSigningKeyTests
{
    [Theory]
    [InlineData("rsa", HashAlgorithm.SHA256, SigningKeyAlgorithm.Rsa)]
    [InlineData("rsa", HashAlgorithm.SHA384, SigningKeyAlgorithm.Rsa)]
    [InlineData("rsa", HashAlgorithm.SHA512, SigningKeyAlgorithm.Rsa)]
    [InlineData("elliptic-curve", HashAlgorithm.SHA256, SigningKeyAlgorithm.EllipticCurve)]
    [InlineData("elliptic-curve-384", HashAlgorithm.SHA384, SigningKeyAlgorithm.EllipticCurve)]
    [InlineData("elliptic-curve-512", HashAlgorithm.SHA512, SigningKeyAlgorithm.EllipticCurve)]
    public void Ctor_GivenValidCredentials_ReturnsInstance(string keyName,
        HashAlgorithm hashAlgorithm, SigningKeyAlgorithm expectedAlgorithm)
    {
        const string keyUrl = "https://rusty-jwt.vault.azure.net/";

        var key = new AzureSigningKey(keyUrl, keyName,
            Credentials.Default,
            hashAlgorithm);

        key.Id.Should().NotBeNullOrWhiteSpace();
        key.HashAlgorithm.Should().Be(hashAlgorithm);
        key.Algorithm.Should().Be(expectedAlgorithm);
    }
    
    [Theory]
    [InlineData("rsa", HashAlgorithm.SHA256)]
    [InlineData("rsa", HashAlgorithm.SHA384)]
    [InlineData("rsa", HashAlgorithm.SHA512)]
    [InlineData("elliptic-curve", HashAlgorithm.SHA256)]
    [InlineData("elliptic-curve-384", HashAlgorithm.SHA384)]
    [InlineData("elliptic-curve-512", HashAlgorithm.SHA512)]
    public async Task SignAsync_GivenValidData_ReturnsASignature(string keyName, HashAlgorithm hashAlgorithm)
    {
        const string keyUrl = "https://rusty-jwt.vault.azure.net/";

        var key = new AzureSigningKey(keyUrl, keyName,
            Credentials.Default,
            hashAlgorithm);

        var data = Encoding.UTF8.GetBytes("hello world");
        var signature = await key.SignAsync(data, CancellationToken.None);
        signature.Should().NotBeNull();
        signature.Should().NotBeEmpty();
    }
    
    [Fact]
    public async Task SignAsync_InvalidHashAlgorithm_Throws()
    {
        const string keyUrl = "https://rusty-jwt.vault.azure.net/";

        var key = new AzureSigningKey(keyUrl, "rsa",
            Credentials.Default,
            (HashAlgorithm)39443);

        var data = Encoding.UTF8.GetBytes("hello world");

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => key.SignAsync(data, CancellationToken.None));
    }
}