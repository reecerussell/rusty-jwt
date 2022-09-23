namespace Rusty.Jwt.Keys;

public class SigningKeyDefinition : ISigningKeyDefinition
{
    public string? Name { get; set; }
    public ISigningKey Key { get; set; }
    public SigningKeyMode Mode { get; set; }
}