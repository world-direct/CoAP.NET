namespace WorldDirect.CoAP.Hosting.Hosting;

using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// The builder to configure a coaps endpoints.
/// </summary>
public class CoAPSEndpointBuilder : ICoAPSEndpointBuilder
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CoAPSEndpointBuilder"/> class.
    /// </summary>
    /// <param name="name">The name of the endpoint.</param>
    /// <param name="services">The service collection.</param>
    public CoAPSEndpointBuilder(string name, IServiceCollection services)
    {
        this.Services = services;
        this.Name = name;
    }

    /// <inheritdoc />
    public string Name { get; }

    /// <inheritdoc />
    public IServiceCollection Services { get; }
}
