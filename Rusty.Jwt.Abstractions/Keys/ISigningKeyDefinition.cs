namespace Rusty.Jwt.Keys;

public interface ISigningKeyDefinition
{ 
    public string? Name { get; }
    public ISigningKey Key { get; }
    public SigningKeyMode Mode { get; }
}