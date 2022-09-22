using Microsoft.Extensions.DependencyInjection;

namespace Rusty.Jwt;

public interface IJwtServiceBuilder
{
    public IServiceCollection Services { get; }
}