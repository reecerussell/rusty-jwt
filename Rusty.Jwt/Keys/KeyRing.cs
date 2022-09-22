using Microsoft.Extensions.DependencyInjection;

namespace Rusty.Jwt.Keys;

internal class KeyRing : IKeyRing
{
    private readonly IReadOnlyList<ISigningKeyDefinition> _keys;

    public KeyRing(IServiceProvider services)
    {
        _keys = services.GetServices<ISigningKeyDefinition>().ToList();
    }
    
    public ISigningKey GetSigningKey()
    {
        var key = _keys.FirstOrDefault(x => x.Mode == SigningKeyMode.SignAndVerify);
        if (key == null)
        {
            throw new InvalidOperationException("No instances of ISigningKey have been registered.");
        }

        return key.Key;
    }

    public ISigningKey GetSigningKey(string name)
    {
        var key = _keys.FirstOrDefault(x => x.Mode == SigningKeyMode.SignAndVerify && x.Name == name);
        if (key == null)
        {
            throw new KeyNotFoundException(name);
        }

        return key.Key;
    }

    public IVerificationKey GetVerificationKey(SigningKeyAlgorithm algorithm, HashAlgorithm hashAlgorithm)
    {
        var keys = _keys.Where(x => x.Key.Algorithm == algorithm &&
                                    x.Key.HashAlgorithm == hashAlgorithm)
            .Select(x => x.Key);
        
        return new AggregateVerificationKey(keys);
    }

    public IVerificationKey? GetVerificationKey(string id)
    {
        return _keys.FirstOrDefault(x => x.Key.Id == id)?.Key;
    }
}