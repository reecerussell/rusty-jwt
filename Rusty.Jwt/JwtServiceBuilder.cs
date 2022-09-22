using Microsoft.Extensions.DependencyInjection;

namespace Rusty.Jwt;

internal class JwtServiceBuilder : IJwtServiceBuilder
{
    public IServiceCollection Services { get;}

    public JwtServiceBuilder(IServiceCollection services)
    {
        Services = services;
    }
}