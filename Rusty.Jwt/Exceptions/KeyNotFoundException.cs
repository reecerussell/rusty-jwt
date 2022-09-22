namespace Rusty.Jwt;

public class KeyNotFoundException : Exception
{
    public KeyNotFoundException(string name)
        : base($"A key with the name '{name}' could not be found.")
    {
    }
}