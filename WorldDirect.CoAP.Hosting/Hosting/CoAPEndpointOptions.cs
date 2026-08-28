namespace WorldDirect.CoAP.Hosting.Hosting;

/// <summary>
/// The available options to configure a coap endpoint.
/// </summary>
public class CoAPEndpointOptions
{
    /// <summary>
    /// Gets or sets the url the endpoint will listen on.
    /// </summary>
    public string Url { get; set; } = string.Empty;
}
