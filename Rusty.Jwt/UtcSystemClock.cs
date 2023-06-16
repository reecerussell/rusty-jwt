namespace Rusty.Jwt;

/// <summary>
/// An implementation of <see cref="ISystemClock"/> used to return the UTC time.
/// </summary>
public class UtcSystemClock : ISystemClock
{
    /// <summary>
    /// Gets the current UTC time.
    /// </summary>
    public DateTime Now => DateTime.UtcNow;
}