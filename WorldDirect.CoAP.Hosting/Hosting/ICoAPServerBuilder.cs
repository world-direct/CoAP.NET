namespace WorldDirect.CoAP.Hosting.Hosting;

using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Provides an interface to build a coap server.
/// </summary>
public interface ICoAPServerBuilder
{
    /// <summary>
    /// Gets the service collection.
    /// </summary>
    public IServiceCollection Services { get; }
}
