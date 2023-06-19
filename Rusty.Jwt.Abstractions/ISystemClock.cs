namespace Rusty.Jwt;

/// <summary>
/// Used to abstract logic to get the current time.
/// </summary>
public interface ISystemClock
{
    /// <summary>
    /// Gets the current date time.
    /// </summary>
    DateTime Now { get; }
}