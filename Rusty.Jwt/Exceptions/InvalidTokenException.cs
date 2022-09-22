namespace Rusty.Jwt;

public class InvalidTokenException : Exception
{
    public InvalidTokenException(string reason)
        : base("Token is invalid: " + reason)
    {
    }
}