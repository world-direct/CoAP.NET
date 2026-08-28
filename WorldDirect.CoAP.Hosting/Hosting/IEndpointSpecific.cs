namespace WorldDirect.CoAP.Hosting.Hosting;

/// <summary>
/// Provides an interface to add a service for a specific endpoint.
/// </summary>
/// <typeparam name="T">The type of the service.</typeparam>
public interface IEndpointSpecific<T>
{
    /// <summary>
    /// Gets or sets the name of the endpoint this service should be used for.
    /// </summary>
    string Name { get; set; }

    /// <summary>
    /// Gets or sets the service.
    /// </summary>
    T Entity { get; set; }
}
