namespace WorldDirect.CoAP.DTLS;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.X509;

/// <summary>
/// Represents a dtls server implementation which communicates with one client.
/// </summary>
public class DTLSServer : AbstractTlsServer
{
    private readonly DTLSServerConfig config;

    /// <summary>
    /// Initializes a new instance of the <see cref="DTLSServer"/> class.
    /// </summary>
    /// <param name="crypto">The cryptostack.</param>
    /// <param name="config">The configuration of the server.</param>
    public DTLSServer(BcTlsCrypto crypto, DTLSServerConfig config) : base(crypto)
    {
        this.config = config;
        this.IsAuthenticated = false;
    }

    /// <summary>
    /// Gets whether the client connected with this server is authenticated.
    /// </summary>
    public bool IsAuthenticated { get; private set; }

    /// <summary>
    /// Gets the certificate of the connected client.
    /// </summary>
    public TlsCertificate? PeerCertificate => this.m_context.SecurityParameters.PeerCertificate.IsEmpty ? null : this.m_context.SecurityParameters.PeerCertificate.GetCertificateAt(0);

    /// <summary>
    /// Get the timeout of handshake.
    /// </summary>
    /// <returns>The timeout in milliseconds.</returns>
    public override int GetHandshakeTimeoutMillis()
    {
        return (int)this.config.HandshakeTimeout.TotalMilliseconds;
    }

    /// <summary>
    /// Get the supported TLS versions.
    /// </summary>
    /// <returns>The supported TLS versions.</returns>
    protected override ProtocolVersion[] GetSupportedVersions()
    {
        return ProtocolVersion.DTLSv12.Only();
    }

    /// <summary>
    /// Get all supported cipher suites.
    /// </summary>
    /// <returns>The supported cipher suites.</returns>
    protected override int[] GetSupportedCipherSuites()
    {
        return this.config.CipherSuites.ToArray();
    }

    /// <summary>
    /// Get the certificate request send to the client.
    /// </summary>
    /// <returns>The generated request.</returns>
    public override Org.BouncyCastle.Tls.CertificateRequest GetCertificateRequest()
    {
        // if no CAs are registered, we wont need a certificate for authentication.
        if (this.config.CA == null)
        {
            return null;
        }

        var serverSigAlgs = TlsUtilities.GetDefaultSupportedSignatureAlgorithms(m_context);
        // currently only ecdsa supported
        // todo check if any is RSA certificate and add RSA certificate type
        serverSigAlgs = serverSigAlgs.Where(s => s.Signature == SignatureAlgorithm.ecdsa).ToList();

        // send back a list of supported CAs
        var authorities = new List<X509Name>() {this.config.CA.SubjectDN};
        
        short[] certificateTypes = new short[] { ClientCertificateType.ecdsa_sign, };

        return new CertificateRequest(certificateTypes, serverSigAlgs, authorities);
    }

    /// <summary>
    /// Get the credentials of the server.
    /// </summary>
    /// <returns>The credentials.</returns>
    /// <exception cref="TlsFatalAlert">Thrown when a key exchange algorithm is not supported.</exception>
    public override TlsCredentials GetCredentials()
    {
        int keyExchangeAlgorithm = m_context.SecurityParameters.KeyExchangeAlgorithm;
        switch (keyExchangeAlgorithm)
        {
            case KeyExchangeAlgorithm.ECDHE_ECDSA:
                return GetECDsaSignerCredentials();
            default:
                throw new TlsFatalAlert(AlertDescription.handshake_failure, "Unsupported exchange algorithm");
        }
    }

    /// <summary>
    /// Handling of the reported client certificate.
    /// </summary>
    /// <param name="clientCertificate">The certificate of the client.</param>
    public override void NotifyClientCertificate(Certificate clientCertificate)
    {
        if (clientCertificate.IsEmpty)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        var chain = clientCertificate.GetCertificateList()!;
        var chainAsCertificate = chain.Select(c => new X509Certificate(c.GetEncoded())).ToArray();
        var trustAnchor = new TrustAnchor(this.config.CA, null);

        var parameters = new PkixParameters(new SortedSet<TrustAnchor>() { trustAnchor });
        parameters.IsRevocationEnabled = false;
        var path = new PkixCertPath(chainAsCertificate);
        var validator = new PkixCertPathValidator();
        validator.Validate(path, parameters);
        this.IsAuthenticated = true;
    }

    private TlsCredentialedSigner GetECDsaSignerCredentials()
    {
        var clientSupportedSigAlgs = this.m_context.SecurityParameters.ClientSigAlgs;
        var clientECDsaSigAlgs = clientSupportedSigAlgs.Where(sig => sig.Signature == SignatureAlgorithm.ecdsa);
        if (!clientECDsaSigAlgs.Any())
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        // the servername the client wants to connect
        var serverNames = this.m_context.SecurityParameters.ClientServerNames;

        var ecCert = FindCertificate(serverNames);

        var signer = new BcTlsECDsaSigner((BcTlsCrypto)this.Crypto, ecCert.PrivateKey);
        var parameter = new TlsCryptoParameters(this.m_context);
        var ecdsa = SignatureAlgorithm.ecdsa;
        var alg = clientSupportedSigAlgs.First(alg => alg.Hash == this.m_context.SecurityParameters.PrfCryptoHashAlgorithm && alg.Signature == ecdsa);
        var credSigner = new DefaultTlsCredentialedSigner(parameter, signer, ecCert.Certificate, alg);
        return credSigner;
    }

    private EcServerCertificate FindCertificate(IList<ServerName> names)
    {
        // todo implement if multiple certificates are required.
        // how to distinguish?
        // https://en.wikipedia.org/wiki/Subject_Alternative_Name#:~:text=Subject%20Alternative%20Name%20(SAN)%20is,Subject%20Alternative%20Names%20(SANs).
        // or only common name?
        return this.config.EcCertificate!;
    }
}
