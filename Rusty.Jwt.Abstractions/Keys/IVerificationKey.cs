namespace Rusty.Jwt.Keys;

/// <summary>
/// A key interface used to verify data with a signature.
/// </summary>
public interface IVerificationKey
{
    /// <summary>
    /// Used to verify a <paramref name="signature"/> against a given set of <paramref name="data"/>.
    /// </summary>
    /// <param name="data">The data to verify against.</param>
    /// <param name="signature">The signature used to verify the data.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    Task<bool> VerifyAsync(byte[] data, byte[] signature, CancellationToken cancellationToken = default);
}