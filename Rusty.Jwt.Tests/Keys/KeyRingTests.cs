using System.Reflection;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Moq;

namespace Rusty.Jwt.Tests.Keys;

public class KeyRingTests
{
    [Fact]
    public void GetSigningKey_WhereKeyRingHasKeys_ReturnsFirst()
    {
        var key1 = Mock.Of<ISigningKey>();
        var keyDefinition1 = new Mock<ISigningKeyDefinition>();
        keyDefinition1.SetupGet(x => x.Mode).Returns(SigningKeyMode.VerifyOnly);
        keyDefinition1.SetupGet(x => x.Key).Returns(key1);
        
        var key2 = Mock.Of<ISigningKey>();
        var keyDefinition2 = new Mock<ISigningKeyDefinition>();
        keyDefinition1.SetupGet(x => x.Mode).Returns(SigningKeyMode.SignAndVerify);
        keyDefinition1.SetupGet(x => x.Key).Returns(key2);
        
        var keyDefinition3 = new Mock<ISigningKeyDefinition>();
        keyDefinition1.SetupGet(x => x.Mode).Returns(SigningKeyMode.SignAndVerify);

        var services = new ServiceCollection();
        services.AddTransient(_ => keyDefinition1.Object);
        services.AddTransient(_ => keyDefinition2.Object);
        services.AddTransient(_ => keyDefinition3.Object);

        var keyRing = new KeyRing(services.BuildServiceProvider());
        var key = keyRing.GetSigningKey();

        // Key2 is the first key that can be used for signing.
        key.Should().Be(key2);
    }
    
    [Fact]
    public void GetSigningKey_WhereKeyRingHasNoKeys_ThrowsInvalidOperation()
    {
        var services = new ServiceCollection();
        var keyRing = new KeyRing(services.BuildServiceProvider());

        Assert.Throws<InvalidOperationException>(keyRing.GetSigningKey);
    }
    
    [Fact]
    public void GetSigningKey_GivenValidName_ReturnsKey()
    {
        const string name = "test";
        
        var key1 = Mock.Of<ISigningKey>();
        var keyDefinition1 = new Mock<ISigningKeyDefinition>();
        keyDefinition1.SetupGet(x => x.Mode).Returns(SigningKeyMode.SignAndVerify);
        keyDefinition1.SetupGet(x => x.Name).Returns(name);
        keyDefinition1.SetupGet(x => x.Key).Returns(key1);
        
        var keyDefinition2 = new Mock<ISigningKeyDefinition>();
        keyDefinition2.SetupGet(x => x.Mode).Returns(SigningKeyMode.SignAndVerify);
        keyDefinition2.SetupGet(x => x.Name).Returns("foo"); // not equal to name

        var services = new ServiceCollection();
        services.AddTransient(_ => keyDefinition1.Object);
        services.AddTransient(_ => keyDefinition2.Object);

        var keyRing = new KeyRing(services.BuildServiceProvider());
        var key = keyRing.GetSigningKey(name);

        key.Should().Be(key1);
    }
    
    [Fact]
    public void GetSigningKey_WhereKeyIsNotFound_ThrowsKeyNotFound()
    {
        const string name = "test";

        var services = new ServiceCollection();
        var keyRing = new KeyRing(services.BuildServiceProvider());
        
        Assert.Throws<KeyNotFoundException>(() => keyRing.GetSigningKey(name));
    }
    
    [Fact]
    public void GetVerificationKey_WhereKeyRingHasKeys_ReturnsAggregateKey()
    {
        var key1 = new Mock<ISigningKey>();
        key1.Setup(x => x.Algorithm).Returns(SigningKeyAlgorithm.Hmac);
        key1.Setup(x => x.HashAlgorithm).Returns(HashAlgorithm.SHA256);
        
        var keyDefinition1 = new Mock<ISigningKeyDefinition>();
        keyDefinition1.SetupGet(x => x.Mode).Returns(SigningKeyMode.SignAndVerify);
        keyDefinition1.SetupGet(x => x.Key).Returns(key1.Object);
        
        var key2 = new Mock<ISigningKey>();
        key2.Setup(x => x.Algorithm).Returns(SigningKeyAlgorithm.Rsa);
        key2.Setup(x => x.HashAlgorithm).Returns(HashAlgorithm.SHA256);
        
        var keyDefinition2 = new Mock<ISigningKeyDefinition>();
        keyDefinition2.SetupGet(x => x.Mode).Returns(SigningKeyMode.SignAndVerify);
        keyDefinition2.SetupGet(x => x.Key).Returns(key2.Object);
        
        var key3 = new Mock<ISigningKey>();
        key3.Setup(x => x.Algorithm).Returns(SigningKeyAlgorithm.Rsa);
        key3.Setup(x => x.HashAlgorithm).Returns(HashAlgorithm.SHA384);
        
        var keyDefinition3 = new Mock<ISigningKeyDefinition>();
        keyDefinition3.SetupGet(x => x.Mode).Returns(SigningKeyMode.SignAndVerify);
        keyDefinition3.SetupGet(x => x.Key).Returns(key3.Object);

        var services = new ServiceCollection();
        services.AddTransient(_ => keyDefinition1.Object);
        services.AddTransient(_ => keyDefinition2.Object);

        var keyRing = new KeyRing(services.BuildServiceProvider());
        var key = keyRing.GetVerificationKey(SigningKeyAlgorithm.Hmac, HashAlgorithm.SHA256);

        key.Should().BeOfType<AggregateVerificationKey>();

        var keys = key.GetType().GetField("_keys", BindingFlags.NonPublic | BindingFlags.Instance)
            .GetValue(key) as IEnumerable<ISigningKey>;

        keys.Should().BeEquivalentTo(new[] {key1.Object});
    }

    [Fact]
    public void GetVerificationKey_GivenKeyId_ReturnsCorrectKey()
    {
        const string id = "23947234";
        
        var key1 = new Mock<ISigningKey>();
        key1.Setup(x => x.Id).Returns(id);
        
        var keyDefinition1 = new Mock<ISigningKeyDefinition>();
        keyDefinition1.SetupGet(x => x.Mode).Returns(SigningKeyMode.SignAndVerify);
        keyDefinition1.SetupGet(x => x.Key).Returns(key1.Object);
        
        var key2 = new Mock<ISigningKey>();
        key2.Setup(x => x.Id).Returns("foo");
        
        var keyDefinition2 = new Mock<ISigningKeyDefinition>();
        keyDefinition2.SetupGet(x => x.Mode).Returns(SigningKeyMode.SignAndVerify);
        keyDefinition2.SetupGet(x => x.Key).Returns(key2.Object);

        var services = new ServiceCollection();
        services.AddTransient(_ => keyDefinition1.Object);
        services.AddTransient(_ => keyDefinition2.Object);

        var keyRing = new KeyRing(services.BuildServiceProvider());
        var key = keyRing.GetVerificationKey(id);

        key.Should().Be(key1.Object);
    }
    
    [Fact]
    public void GetVerificationKey_GivenUnknownKeyId_ReturnsNull()
    {
        const string id = "23947234";
        
        var key1 = new Mock<ISigningKey>();
        key1.Setup(x => x.Id).Returns("foo");
        
        var keyDefinition1 = new Mock<ISigningKeyDefinition>();
        keyDefinition1.SetupGet(x => x.Mode).Returns(SigningKeyMode.SignAndVerify);
        keyDefinition1.SetupGet(x => x.Key).Returns(key1.Object);

        var services = new ServiceCollection();
        services.AddTransient(_ => keyDefinition1.Object);

        var keyRing = new KeyRing(services.BuildServiceProvider());
        var key = keyRing.GetVerificationKey(id);

        key.Should().BeNull();
    }
}