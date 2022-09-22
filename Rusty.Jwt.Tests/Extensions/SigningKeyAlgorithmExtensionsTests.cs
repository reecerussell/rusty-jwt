using FluentAssertions;

namespace Rusty.Jwt.Tests.Extensions;

public class SigningAlgorithmExtensionsTests
{
    [Theory]
    [InlineData(SigningKeyAlgorithm.Hmac, "HS")]
    [InlineData(SigningKeyAlgorithm.Rsa, "RS")]
    [InlineData(SigningKeyAlgorithm.EllipticCurve, "ES")]
    public void GetPrefix_GivenValidAlg_ReturnsExpected(SigningKeyAlgorithm alg, string expected)
    {
        alg.GetPrefix().Should().Be(expected);
    }

    [Fact]
    public void GetPrefix_GivenInvalidAlg_Throws()
    {
        var alg = (SigningKeyAlgorithm) 324;

        var ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => alg.GetPrefix());
        ex.ParamName.Should().Be("algorithm");
    }
}