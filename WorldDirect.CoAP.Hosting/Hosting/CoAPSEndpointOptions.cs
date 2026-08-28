namespace WorldDirect.CoAP.Hosting.Hosting;

using Configuration;

/// <summary>
/// The available options to configure a coaps endpoint.
/// </summary>
public class CoAPSEndpointOptions
{
    /// <summary>
    /// Gets or sets the url the endpoint will listen on.
    /// </summary>
    public string Url { get; set; }

    /// <summary>
    /// Gets or sets the certificate used by the server.
    /// </summary>
    public CertificateOption? Certificate { get; set; }

    /// <summary>
    /// Gets or sets the certificates used to check validity of client certificates.
    /// </summary>
    public List<CertificateOption> ClientCA { get; set; } = new ();

    /// <summary>
    /// Gets or sets the timeout of a dtls handshake.
    /// </summary>
    public TimeSpan HandshakeTimeout { get; set; }
}
