namespace WorldDirect.CoAP.DTLS;

/// <summary>
/// An interface to create a <see cref="DTLSServer"/>.
/// </summary>
public interface IDTLSFactory
{
    /// <summary>
    /// Create a new <see cref="DTLSServer"/> instance.
    /// </summary>
    /// <returns>The newly created <see cref="DTLSServer"/>.</returns>
    public DTLSServer CreateServer();
}
