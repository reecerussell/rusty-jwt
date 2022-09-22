using FluentAssertions;

namespace Rusty.Jwt.Tests;

public class HeaderTests
{
    [Fact]
    public void GetId_WhereHasValue_ReturnsValue()
    {
        const string value = "foo";

        var header = new Header
        {
            [JwtHeaderClaimTypes.Id] = value
        };

        header.Id.Should().Be(value);
    }
    
    [Fact]
    public void GetId_WhereHasNoValue_ReturnsNull()
    {
        var header = new Header();

        header.Id.Should().BeNull();
    }
    
    [Fact]
    public void SetId_GivenValue_SetsValue()
    {
        const string value = "foo";

        var header = new Header()
        {
            Id = value
        };

        header[JwtHeaderClaimTypes.Id].Should().Be(value);
    }
    
    [Fact]
    public void SetId_GivenNullValue_RemovesValue()
    {
        var header = new Header()
        {
            Id = "foo"
        };

        header.Id = null;

        header.ContainsKey(JwtHeaderClaimTypes.Id).Should().BeFalse();
    }
    
    [Fact]
    public void GetKeyId_WhereHasValue_ReturnsValue()
    {
        const string value = "foo";

        var header = new Header
        {
            [JwtHeaderClaimTypes.KeyId] = value
        };

        header.KeyId.Should().Be(value);
    }
    
    [Fact]
    public void GetKeyId_WhereHasNoValue_ReturnsNull()
    {
        var header = new Header();

        header.KeyId.Should().BeNull();
    }
    
    [Fact]
    public void SetKeyId_GivenValue_SetsValue()
    {
        const string value = "foo";

        var header = new Header()
        {
            KeyId = value
        };

        header[JwtHeaderClaimTypes.KeyId].Should().Be(value);
    }
    
    [Fact]
    public void SetKeyId_GivenNullValue_RemovesValue()
    {
        var header = new Header()
        {
            KeyId = "foo"
        };

        header.KeyId = null;

        header.ContainsKey(JwtHeaderClaimTypes.KeyId).Should().BeFalse();
    }
    
    [Fact]
    public void GetAlgorithm_WhereHasValue_ReturnsValue()
    {
        const string value = "foo";

        var header = new Header
        {
            [JwtHeaderClaimTypes.Algorithm] = value
        };

        header.Algorithm.Should().Be(value);
    }
    
    [Fact]
    public void GetAlgorithm_WhereHasNoValue_ReturnsNull()
    {
        var header = new Header();

        header.Algorithm.Should().BeNull();
    }
    
    [Fact]
    public void SetAlgorithm_GivenValue_SetsValue()
    {
        const string value = "foo";

        var header = new Header()
        {
            Algorithm = value
        };

        header[JwtHeaderClaimTypes.Algorithm].Should().Be(value);
    }
    
    [Fact]
    public void SetAlgorithm_GivenNullValue_RemovesValue()
    {
        var header = new Header()
        {
            Algorithm = "foo"
        };

        header.Algorithm = null;

        header.ContainsKey(JwtHeaderClaimTypes.Algorithm).Should().BeFalse();
    }
}