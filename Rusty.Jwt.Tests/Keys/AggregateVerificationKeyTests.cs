using System.Text;
using FluentAssertions;
using Moq;

namespace Rusty.Jwt.Tests.Keys;

public class AggregateVerificationKeyTests
{
    [Fact]
    public async Task VerifyAsync_WhereSignatureIsValid_ReturnsTrue()
    {
        var data = Encoding.UTF8.GetBytes("foo");
        var signature = Encoding.UTF8.GetBytes("bar");
        var cancellationToken = new CancellationToken();

        var key = new Mock<IVerificationKey>();
        key.Setup(x => x.VerifyAsync(data, signature, cancellationToken))
            .ReturnsAsync(true)
            .Verifiable();

        var aggregateKey = new AggregateVerificationKey(
            new[] {key.Object});

        var result = await aggregateKey.VerifyAsync(data, signature, cancellationToken);
        result.Should().BeTrue();
        
        key.VerifyAll();
        key.Verify(x => x.VerifyAsync(data, signature, cancellationToken), Times.Once);
    }
    
    [Fact]
    public async Task VerifyAsync_WhereSecondKeyIsValid_ReturnsTrue()
    {
        var data = Encoding.UTF8.GetBytes("foo");
        var signature = Encoding.UTF8.GetBytes("bar");
        var cancellationToken = new CancellationToken();

        var key1 = new Mock<IVerificationKey>();
        key1.Setup(x => x.VerifyAsync(data, signature, cancellationToken))
            .ReturnsAsync(false)
            .Verifiable();
        
        var key2 = new Mock<IVerificationKey>();
        key2.Setup(x => x.VerifyAsync(data, signature, cancellationToken))
            .ReturnsAsync(true)
            .Verifiable();

        var aggregateKey = new AggregateVerificationKey(
            new[] {key1.Object, key2.Object});

        var result = await aggregateKey.VerifyAsync(data, signature, cancellationToken);
        result.Should().BeTrue();
        
        key1.VerifyAll();
        key1.Verify(x => x.VerifyAsync(data, signature, cancellationToken), Times.Once);
        key2.VerifyAll();
        key2.Verify(x => x.VerifyAsync(data, signature, cancellationToken), Times.Once);
    }
    
    [Fact]
    public async Task VerifyAsync_WhereAllKeysReturnFalse_ReturnsFalse()
    {
        var data = Encoding.UTF8.GetBytes("foo");
        var signature = Encoding.UTF8.GetBytes("bar");
        var cancellationToken = new CancellationToken();

        var key1 = new Mock<IVerificationKey>();
        key1.Setup(x => x.VerifyAsync(data, signature, cancellationToken))
            .ReturnsAsync(false)
            .Verifiable();
        
        var key2 = new Mock<IVerificationKey>();
        key2.Setup(x => x.VerifyAsync(data, signature, cancellationToken))
            .ReturnsAsync(false)
            .Verifiable();

        var aggregateKey = new AggregateVerificationKey(
            new[] {key1.Object, key2.Object});

        var result = await aggregateKey.VerifyAsync(data, signature, cancellationToken);
        result.Should().BeFalse();
        
        key1.VerifyAll();
        key1.Verify(x => x.VerifyAsync(data, signature, cancellationToken), Times.Once);
        key2.VerifyAll();
        key2.Verify(x => x.VerifyAsync(data, signature, cancellationToken), Times.Once);
    }
}