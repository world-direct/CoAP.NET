namespace WorldDirect.CoAP.DTLS;

public class DTLSServerConfig
{
    public List<EcServerCertificate> EcCertificates { get; set; } = new();

    public List<Org.BouncyCastle.X509.X509Certificate> CAs { get; set; } = new ();

    public List<int> CipherSuites { get; set; } = new();

    /// <summary>
    /// Gets or sets the timeout of the dtls handshake.
    /// </summary>
    /// <remarks>
    /// 0 means no timeout
    /// </remarks>
    public TimeSpan HandshakeTimeout { get; set; } = TimeSpan.Zero;
}
