namespace Rusty.Jwt;

public interface IJwtFactory
{
    /// <summary>
    /// Used to create a new JSON-Web-Token with the given claims.
    /// </summary>
    /// <param name="claimsBuilder">An action used to set the claims.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    Task<Jwt> CreateAsync(Action<Claims> claimsBuilder, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Used to create a new JSON-Web-Token with the given claims.
    /// </summary>
    /// <param name="claimsBuilder">An action used to set the claims.</param>
    /// <param name="keyName">The name of the signing key to use.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    Task<Jwt> CreateAsync(Action<Claims> claimsBuilder, string keyName, CancellationToken cancellationToken = default);
}