namespace WorldDirect.CoAP.Hosting.Hosting;

using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Provides an interface to build a coap endpoint.
/// </summary>
public interface ICoAPEndpointBuilder
{
    /// <summary>
    /// Gets the name of the endpoint.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Gets the service collection.
    /// </summary>
    public IServiceCollection Services { get; }
}
