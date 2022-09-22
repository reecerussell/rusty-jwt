namespace Rusty.Jwt;

public interface IJwtVerifier
{
    /// <summary>
    /// Used to verify a token is valid/
    /// </summary>
    /// <param name="token">The JWT to verify.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    Task<Claims> VerifyAsync(string token, CancellationToken cancellationToken = default);
}