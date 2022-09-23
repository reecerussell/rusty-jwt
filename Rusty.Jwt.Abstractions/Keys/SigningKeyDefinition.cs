namespace Rusty.Jwt.Keys;

internal class SigningKeyDefinition : ISigningKeyDefinition
{
    public string? Name { get; set; }
    public ISigningKey Key { get; set; }
    public SigningKeyMode Mode { get; set; }
}