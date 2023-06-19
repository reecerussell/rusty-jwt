using FluentAssertions;

namespace Rusty.Jwt.Tests;

public class UtcSystemClockTests
{
    [Fact]
    public void Now_ReturnsCurrent_UtcTime()
    {
        var clock = new UtcSystemClock();

        clock.Now.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromMilliseconds(1));
    }
}