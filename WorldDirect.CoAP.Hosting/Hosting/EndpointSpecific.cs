namespace WorldDirect.CoAP.Hosting.Hosting;

/// <summary>
/// Default implementation of the <see cref="IEndpointSpecific{T}"/>.
/// </summary>
/// <typeparam name="T">The type of the service.</typeparam>
public class EndpointSpecific<T> : IEndpointSpecific<T>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="EndpointSpecific{T}"/> class.
    /// </summary>
    /// <param name="name">The name of the endpoint.</param>
    /// <param name="entity">The service.</param>
    public EndpointSpecific(string name, T entity)
    {
        Name = name;
        Entity = entity;
    }

    /// <inheritdoc />
    public string Name { get; set; }

    /// <inheritdoc />
    public T Entity { get; set; }
}