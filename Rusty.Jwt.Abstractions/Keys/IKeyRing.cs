namespace Rusty.Jwt.Keys;

public interface IKeyRing
{
    /// <summary>
    /// Used to get a key to sign data.
    /// </summary>
    ISigningKey GetSigningKey();
    
    /// <summary>
    /// Used to get a key to sign data.
    /// </summary>
    /// <param name="name">The name of the to get.</param>
    /// <exception cref="KeyNotFoundException">Thrown if the key does not exist.</exception>
    ISigningKey GetSigningKey(string name);

    /// <summary>
    /// Used to get a key to verify data and a signature. Only fetches keys without
    /// a name, this is so that explicitly defined keys are only used for their
    /// intended purpose.
    /// </summary>
    /// <param name="algorithm">The signing algorithm of key to get.</param>
    /// <param name="hashAlgorithm">The hashing algorithm of key to get.</param>
    IVerificationKey GetVerificationKey(SigningKeyAlgorithm algorithm, HashAlgorithm hashAlgorithm);

    /// <summary>
    /// Used to get a key to verify data and a signature.
    /// </summary>
    /// <param name="id">The id of the key to get.</param>
    IVerificationKey? GetVerificationKey(string id);
}