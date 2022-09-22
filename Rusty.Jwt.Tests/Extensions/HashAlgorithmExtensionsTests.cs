using FluentAssertions;

namespace Rusty.Jwt.Tests.Extensions;

public class HashAlgorithmExtensionsTests
{
    [Theory]
    [InlineData(HashAlgorithm.SHA256, 256)]
    [InlineData(HashAlgorithm.SHA384, 384)]
    [InlineData(HashAlgorithm.SHA512, 512)]
    public void GetHashSize_GivenValidAlg_ReturnsExpected(HashAlgorithm alg, int expected)
    {
        alg.GetHashSize().Should().Be(expected);
    }

    [Fact]
    public void GetHashSize_GivenInvalidAlg_Throws()
    {
        var alg = (HashAlgorithm) 324;

        var ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => alg.GetHashSize());
        ex.ParamName.Should().Be("hashAlgorithm");
    }
}