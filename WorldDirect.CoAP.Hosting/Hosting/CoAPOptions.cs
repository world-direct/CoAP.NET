namespace WorldDirect.CoAP.Hosting.Hosting;

/// <summary>
/// The available options to configure the coap stack.
/// </summary>
public class CoAPOptions
{
    /// <summary>
    /// Gets or sets the max allowed coap message size.
    /// </summary>
    public ushort? MaxMessageSize { get; set; }

    /// <summary>
    /// Gets or sets the default block size.
    /// </summary>
    public ushort? DefaultBlockSize { get; set; }
}
