using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;

namespace Rusty.Jwt.Tests.Extensions;

public class JwtServiceBuilderExtensionsTests
{
    [Fact]
    public void AddSigningKey_GivenType_RegistersKey()
    {
        var collection = new ServiceCollection();
        var builder = new JwtServiceBuilder(collection);

        builder.AddSigningKey<TestSigningKey>();

        var services = collection.BuildServiceProvider();

        services.GetService<TestSigningKey>().Should().NotBeNull();
        
        var keys = services.GetServices<ISigningKeyDefinition>().ToList();
        keys.Count.Should().Be(1);

        keys[0].Name.Should().BeNull();
        keys[0].Mode.Should().Be(SigningKeyMode.SignAndVerify);
        keys[0].Key.Should().NotBeNull();
        keys[0].Key.Should().BeOfType<TestSigningKey>();
    }
    
    [Fact]
    public void AddSigningKey_GivenTypeAndName_RegistersKey()
    {
        const string name = "foo";
        
        var collection = new ServiceCollection();
        var builder = new JwtServiceBuilder(collection);

        builder.AddSigningKey<TestSigningKey>(name);

        var services = collection.BuildServiceProvider();

        services.GetService<TestSigningKey>().Should().NotBeNull();
        
        var keys = services.GetServices<ISigningKeyDefinition>().ToList();
        keys.Count.Should().Be(1);

        keys[0].Name.Should().Be(name);
        keys[0].Mode.Should().Be(SigningKeyMode.SignAndVerify);
        keys[0].Key.Should().NotBeNull();
        keys[0].Key.Should().BeOfType<TestSigningKey>();
    }
    
    [Fact]
    public void AddSigningKey_GivenTypeNameAndMode_RegistersKey()
    {
        const string name = "foo";
        const SigningKeyMode mode = SigningKeyMode.VerifyOnly;
        
        var collection = new ServiceCollection();
        var builder = new JwtServiceBuilder(collection);

        builder.AddSigningKey<TestSigningKey>(name, mode);

        var services = collection.BuildServiceProvider();

        services.GetService<TestSigningKey>().Should().NotBeNull();
        
        var keys = services.GetServices<ISigningKeyDefinition>().ToList();
        keys.Count.Should().Be(1);

        keys[0].Name.Should().Be(name);
        keys[0].Mode.Should().Be(mode);
        keys[0].Key.Should().NotBeNull();
        keys[0].Key.Should().BeOfType<TestSigningKey>();
    }
    
    [Fact]
    public void AddSigningKey_GivenTypeAndMode_RegistersKey()
    {
        const SigningKeyMode mode = SigningKeyMode.VerifyOnly;
        
        var collection = new ServiceCollection();
        var builder = new JwtServiceBuilder(collection);

        builder.AddSigningKey<TestSigningKey>(mode);

        var services = collection.BuildServiceProvider();

        services.GetService<TestSigningKey>().Should().NotBeNull();
        
        var keys = services.GetServices<ISigningKeyDefinition>().ToList();
        keys.Count.Should().Be(1);

        keys[0].Name.Should().BeNull();
        keys[0].Mode.Should().Be(mode);
        keys[0].Key.Should().NotBeNull();
        keys[0].Key.Should().BeOfType<TestSigningKey>();
    }
    
    [Fact]
    public void AddHmacSigningKey_GivenValidArgs_RegistersKey()
    {
        const string key = "3204234";
        const HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;
        const string name = "foo";
        const SigningKeyMode mode = SigningKeyMode.VerifyOnly;

        var collection = new ServiceCollection();
        var builder = new JwtServiceBuilder(collection);

        builder.AddHmacSigningKey(key, hashAlgorithm, name, mode);

        var services = collection.BuildServiceProvider();

        services.GetService<HmacSigningKey>().Should().NotBeNull();
        
        var keys = services.GetServices<ISigningKeyDefinition>().ToList();
        keys.Count.Should().Be(1);

        keys[0].Name.Should().Be(name);
        keys[0].Mode.Should().Be(mode);
        keys[0].Key.Should().NotBeNull();
        keys[0].Key.Should().BeOfType<HmacSigningKey>();
    }

    private class TestSigningKey : ISigningKey
    {
        public string Id { get; }
        public HashAlgorithm HashAlgorithm { get; }
        public SigningKeyAlgorithm Algorithm { get; }
        
        public Task<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
        
        public Task<bool> VerifyAsync(byte[] data, byte[] signature, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
    }
}