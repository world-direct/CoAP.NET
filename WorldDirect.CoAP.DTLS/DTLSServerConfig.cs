namespace WorldDirect.CoAP.DTLS;

using Org.BouncyCastle.Tls;
using Org.BouncyCastle.X509;

/// <summary>
/// Represents the configuration of the <see cref="DTLSServer"/>.
/// </summary>
public class DTLSServerConfig
{
    /// <summary>
    /// Gets or sets the certificate of the server.
    /// </summary>
    public EcServerCertificate? EcCertificate { get; set; }

    /// <summary>
    /// Gets or sets the CA to authorize the connecting clients.
    /// </summary>
    public List<Org.BouncyCastle.X509.X509Certificate> CAs { get; set; } = new List<X509Certificate>();

    /// <summary>
    /// Gets or sets the available cipher suites.
    /// </summary>
    public List<int> CipherSuites { get; set; } = new();

    /// <summary>
    /// Gets or sets the timeout of the dtls handshake.
    /// </summary>
    /// <remarks>
    /// 0 means no timeout
    /// </remarks>
    public TimeSpan HandshakeTimeout { get; set; } = TimeSpan.Zero;

    /// <summary>
    /// Gets or sets the provider for psk keys.
    /// </summary>
    public TlsPskIdentityManager? PskManager { get; set; }
}
