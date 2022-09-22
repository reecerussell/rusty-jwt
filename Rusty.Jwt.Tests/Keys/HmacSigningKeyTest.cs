using System.Text;
using Base64Extensions;
using FluentAssertions;

namespace Rusty.Jwt.Tests.Keys;

public class HmacSigningKeyTest
{
    [Fact]
    public void GetAlgorithm_GivenValidSigningKey_ReturnsHmac()
    {
        const string key = "foo";

        var signingKey = new HmacSigningKey(key, HashAlgorithm.SHA256);
        signingKey.Algorithm.Should().Be(SigningKeyAlgorithm.Hmac);
    }
    
    [Fact]
    public void GetId_GivenValidSigningKey_ReturnsId()
    {
        var signingKey = new HmacSigningKey("test", HashAlgorithm.SHA256);
        signingKey.Id.Should().Be("3A221AFF-C802-4BA1-80C4-49BA2981D023");
    }

    [Theory]
    [InlineData(HashAlgorithm.SHA256, "sWCJ9RnczxtDiCqReMlW+z3XCGgYGj4Xt5cjgvnCXBM=")]
    [InlineData(HashAlgorithm.SHA384, "K8xvsWU4PhJl1uiKzYSOZxDFpkytFmi65ornQE24Xwd5aNPlprLVuQYi1i2gpZEs")]
    [InlineData(HashAlgorithm.SHA512, "+WPY39Wh5eTOQPKziILhestsd3Nw/A2BPJnUXqUP6iCZHzUzWeIcro95Rn0LtEvKdKtBnL316VqB2PNp7lSQEA==")]
    public async Task SignAsync_GivenValidData_ReturnsSignature(
        HashAlgorithm hashAlgorithm, string expectedBase64)
    {
        const string key = "foo";
        const string plainText = "Hello World";

        var signingKey = new HmacSigningKey(key, hashAlgorithm);
        var cipher = await signingKey.SignAsync(
            Encoding.UTF8.GetBytes(plainText),
            CancellationToken.None);

        var cipherBase64 = Encoding.UTF8.GetString(
            Base64Convert.Encode(cipher));
        cipherBase64.Should().Be(expectedBase64);
    }
    
    [Fact]
    public async Task SignAsync_GivenInvalidHashAlgorithm_ThrowsOutOfRange()
    {
        var hashAlgorithm = (HashAlgorithm) 46;
        var signingKey = new HmacSigningKey("foo", hashAlgorithm);
        
        var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => signingKey.SignAsync(new byte[]{0x01, 0x02},
                CancellationToken.None));

        ex.ParamName.Should().Be(nameof(signingKey.HashAlgorithm));
    }
    
    [Theory]
    [InlineData(HashAlgorithm.SHA256, "sWCJ9RnczxtDiCqReMlW+z3XCGgYGj4Xt5cjgvnCXBM=")]
    [InlineData(HashAlgorithm.SHA384, "K8xvsWU4PhJl1uiKzYSOZxDFpkytFmi65ornQE24Xwd5aNPlprLVuQYi1i2gpZEs")]
    [InlineData(HashAlgorithm.SHA512, "+WPY39Wh5eTOQPKziILhestsd3Nw/A2BPJnUXqUP6iCZHzUzWeIcro95Rn0LtEvKdKtBnL316VqB2PNp7lSQEA==")]
    public async Task VerifyAsync_GivenValidDataAndSignature_ReturnsSuccess(
        HashAlgorithm hashAlgorithm, string cipherBase64)
    {
        const string key = "foo";
        const string plainText = "Hello World";

        var signingKey = new HmacSigningKey(key, hashAlgorithm);
        var result = await signingKey.VerifyAsync(
            Encoding.UTF8.GetBytes(plainText),
            Convert.FromBase64String(cipherBase64),
            CancellationToken.None);

        result.Should().BeTrue();
    }
}