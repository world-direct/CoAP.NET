namespace WorldDirect.CoAP.Hosting.Hosting;

using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// The builder for the coap server.
/// </summary>
internal class CoAPServerBuilder : ICoAPServerBuilder
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CoAPServerBuilder"/> class.
    /// </summary>
    /// <param name="services">The service collection.</param>
    public CoAPServerBuilder(IServiceCollection services)
    {
        Services = services;
    }

    /// <inheritdoc />
    public IServiceCollection Services { get; }
}
