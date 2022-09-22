namespace Rusty.Jwt.Keys;

public class AggregateVerificationKey : IVerificationKey
{
    private readonly IEnumerable<IVerificationKey> _keys;

    public AggregateVerificationKey(IEnumerable<IVerificationKey> keys)
    {
        _keys = keys;
    }
    
    public async Task<bool> VerifyAsync(byte[] data, byte[] signature, CancellationToken cancellationToken = default)
    {
        foreach (var key in _keys)
        {
            var result = await key.VerifyAsync(data, signature, cancellationToken);
            if (result)
            {
                return true;
            }
        }

        return false;
    }
}