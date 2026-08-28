namespace WorldDirect.CoAP.Hosting.Hosting;

using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// The builder to configure a coap endpoint.
/// </summary>
public class CoAPEndpointBuilder : ICoAPEndpointBuilder
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CoAPEndpointBuilder"/> class.
    /// </summary>
    /// <param name="name">The name of the endpoint.</param>
    /// <param name="services">The service collection.</param>
    public CoAPEndpointBuilder(string name, IServiceCollection services)
    {
        Services = services;
        this.Name = name;
    }

    /// <inheritdoc />
    public string Name { get; }

    /// <inheritdoc />
    public IServiceCollection Services { get; }
}
