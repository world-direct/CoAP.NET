namespace WorldDirect.CoAP.DTLS;

using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.X509;

/// <summary>
/// Represents the configuration of the <see cref="DTLSServer"/>.
/// </summary>
public class DTLSServerConfig
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DTLSServerConfig"/> class.
    /// </summary>
    /// <param name="config">The configuration to copy.</param>
    public DTLSServerConfig(MutableDTLSServerConfig config)
    {
        this.Crypto = config.Crypto;
        this.EcCertificate = config.EcCertificate;
        this.CAs = config.CAs;
        this.CipherSuites = config.CipherSuites;
        this.HandshakeTimeout = config.HandshakeTimeout;
        this.PskManager = config.PskManager;
    }

    /// <summary>
    /// Gets or sets the crypto stack.
    /// </summary>
    public BcTlsCrypto Crypto { get; }

    /// <summary>
    /// Gets or sets the certificate of the server.
    /// </summary>
    public EcServerCertificate? EcCertificate { get; }

    /// <summary>
    /// Gets or sets the CA to authorize the connecting clients.
    /// </summary>
    public List<Org.BouncyCastle.X509.X509Certificate> CAs { get; } = new List<X509Certificate>();

    /// <summary>
    /// Gets or sets the available cipher suites.
    /// </summary>
    public List<int> CipherSuites { get; } = new();

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
    public TlsPskIdentityManager? PskManager { get; }
}

/// <summary>
/// Represents the configuration of the <see cref="DTLSServer"/> in build mode.
/// </summary>
public class MutableDTLSServerConfig
{
    /// <summary>
    /// Gets or sets the crypto stack.
    /// </summary>
    public BcTlsCrypto Crypto { get; set; }

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
