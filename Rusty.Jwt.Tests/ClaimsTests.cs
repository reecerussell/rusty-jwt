using FluentAssertions;

namespace Rusty.Jwt.Tests;

public class ClaimsTests
{
    [Fact]
    public void GetIssuer_WhereHasValue_ReturnsValue()
    {
        const string value = "foo";

        var claims = new Claims
        {
            [JwtClaimTypes.Issuer] = value
        };

        claims.Issuer.Should().Be(value);
    }
    
    [Fact]
    public void GetIssuer_WhereHasNoValue_ReturnsNull()
    {
        var claims = new Claims();

        claims.Issuer.Should().BeNull();
    }
    
    [Fact]
    public void SetIssuer_GivenValue_SetsValue()
    {
        const string value = "foo";

        var claims = new Claims
        {
            Issuer = value
        };

        claims[JwtClaimTypes.Issuer].Should().Be(value);
    }
    
    [Fact]
    public void SetIssuer_GivenNullValue_RemovesValue()
    {
        var claims = new Claims
        {
            Issuer = "foo"
        };

        claims.Issuer = null;

        claims.ContainsKey(JwtClaimTypes.Issuer).Should().BeFalse();
    }
    
    [Fact]
    public void GetAudience_WhereHasValue_ReturnsValue()
    {
        const string value = "foo";

        var claims = new Claims
        {
            [JwtClaimTypes.Audience] = value
        };

        claims.Audience.Should().Be(value);
    }
    
    [Fact]
    public void GetAudience_WhereHasNoValue_ReturnsNull()
    {
        var claims = new Claims();

        claims.Audience.Should().BeNull();
    }
    
    [Fact]
    public void SetAudience_GivenValue_SetsValue()
    {
        const string value = "foo";

        var claims = new Claims
        {
            Audience = value
        };

        claims[JwtClaimTypes.Audience].Should().Be(value);
    }
    
    [Fact]
    public void SetAudience_GivenNullValue_RemovesValue()
    {
        var claims = new Claims
        {
            Audience = "foo"
        };

        claims.Audience = null;

        claims.ContainsKey(JwtClaimTypes.Audience).Should().BeFalse();
    }
    
    [Fact]
    public void GetSubject_WhereHasValue_ReturnsValue()
    {
        const string value = "foo";

        var claims = new Claims
        {
            [JwtClaimTypes.Subject] = value
        };

        claims.Subject.Should().Be(value);
    }
    
    [Fact]
    public void GetSubject_WhereHasNoValue_ReturnsNull()
    {
        var claims = new Claims();

        claims.Subject.Should().BeNull();
    }
    
    [Fact]
    public void SetSubject_GivenValue_SetsValue()
    {
        const string value = "foo";

        var claims = new Claims
        {
            Subject = value
        };

        claims[JwtClaimTypes.Subject].Should().Be(value);
    }
    
    [Fact]
    public void SetSubject_GivenNullValue_RemovesValue()
    {
        var claims = new Claims
        {
            Subject = "foo"
        };

        claims.Subject = null;

        claims.ContainsKey(JwtClaimTypes.Subject).Should().BeFalse();
    }
    
    [Fact]
    public void GetExpiry_WhereHasValue_ReturnsValue()
    {
        var value = DateTimeOffset.UtcNow;

        var claims = new Claims
        {
            [JwtClaimTypes.Expiry] = value.ToUnixTimeSeconds()
        };

        claims.Expiry.Should().BeCloseTo(value, TimeSpan.FromSeconds(1));
    }
    
    [Fact]
    public void GetExpiry_WhereHasNoValue_ReturnsNull()
    {
        var claims = new Claims();

        claims.Expiry.Should().BeNull();
    }
    
    [Fact]
    public void SetExpiry_GivenValue_SetsValue()
    {
        var value = DateTimeOffset.UtcNow;

        var claims = new Claims
        {
            Expiry = value
        };

        claims[JwtClaimTypes.Expiry].Should().Be(value.ToUnixTimeSeconds());
    }
    
    [Fact]
    public void SetExpiry_GivenNullValue_RemovesValue()
    {
        var claims = new Claims
        {
            Expiry = DateTimeOffset.UtcNow
        };

        claims.Expiry = null;

        claims.ContainsKey(JwtClaimTypes.Expiry).Should().BeFalse();
    }
    
    [Fact]
    public void GetNotBefore_WhereHasValue_ReturnsValue()
    {
        var value = DateTimeOffset.UtcNow;

        var claims = new Claims
        {
            [JwtClaimTypes.NotBefore] = value.ToUnixTimeSeconds()
        };

        claims.NotBefore.Should().BeCloseTo(value, TimeSpan.FromSeconds(1));
    }
    
    [Fact]
    public void GetNotBefore_WhereHasNoValue_ReturnsNull()
    {
        var claims = new Claims();

        claims.NotBefore.Should().BeNull();
    }
    
    [Fact]
    public void SetNotBefore_GivenValue_SetsValue()
    {
        var value = DateTimeOffset.UtcNow;

        var claims = new Claims
        {
            NotBefore = value
        };

        claims[JwtClaimTypes.NotBefore].Should().Be(value.ToUnixTimeSeconds());
    }
    
    [Fact]
    public void SetNotBefore_GivenNullValue_RemovesValue()
    {
        var claims = new Claims
        {
            NotBefore = DateTimeOffset.UtcNow
        };

        claims.NotBefore = null;

        claims.ContainsKey(JwtClaimTypes.NotBefore).Should().BeFalse();
    }
    
    [Fact]
    public void GetIssuedAt_WhereHasValue_ReturnsValue()
    {
        var value = DateTimeOffset.UtcNow;

        var claims = new Claims
        {
            [JwtClaimTypes.IssuedAt] = value.ToUnixTimeSeconds()
        };

        claims.IssuedAt.Should().BeCloseTo(value, TimeSpan.FromSeconds(1));
    }
    
    [Fact]
    public void GetIssuedAt_WhereHasNoValue_ReturnsNull()
    {
        var claims = new Claims();

        claims.IssuedAt.Should().BeNull();
    }
    
    [Fact]
    public void SetIssuedAt_GivenValue_SetsValue()
    {
        var value = DateTimeOffset.UtcNow;

        var claims = new Claims
        {
            IssuedAt = value
        };

        claims[JwtClaimTypes.IssuedAt].Should().Be(value.ToUnixTimeSeconds());
    }
    
    [Fact]
    public void SetIssuedAt_GivenNullValue_RemovesValue()
    {
        var claims = new Claims
        {
            IssuedAt = DateTimeOffset.UtcNow
        };

        claims.IssuedAt = null;

        claims.ContainsKey(JwtClaimTypes.IssuedAt).Should().BeFalse();
    }
}