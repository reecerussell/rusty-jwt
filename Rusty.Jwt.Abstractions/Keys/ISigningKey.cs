namespace Rusty.Jwt.Keys;

public interface ISigningKey : IVerificationKey
{
    /// <summary>
    /// Gets the id of the signing key.
    /// </summary>
    string Id { get; }
        
    /// <summary>
    /// Gets the hashing algorithm used.
    /// </summary>
    HashAlgorithm HashAlgorithm { get; }
        
    /// <summary>
    /// Gets the name of the signing algorithm used.
    /// </summary>
    SigningKeyAlgorithm Algorithm { get; }
        
    /// <summary>
    /// Used to sign a given set of <paramref name="data"/>.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>A signature of <paramref name="data"/>.</returns>
    Task<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default);
}