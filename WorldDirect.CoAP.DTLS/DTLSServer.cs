namespace WorldDirect.CoAP.DTLS;

using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.X509;

public class DTLSServer : AbstractTlsServer
{
    private readonly DTLSServerConfig config;

    public DTLSServer(BcTlsCrypto crypto, DTLSServerConfig config) : base(crypto)
    {
        this.config = config;
    }

    public TlsCertificate? PeerCertificate => this.m_context.SecurityParameters.PeerCertificate.IsEmpty ? null : this.m_context.SecurityParameters.PeerCertificate.GetCertificateAt(0);

    public override int GetHandshakeTimeoutMillis()
    {
        return (int)this.config.HandshakeTimeout.TotalMilliseconds;
    }

    protected override ProtocolVersion[] GetSupportedVersions()
    {
        return ProtocolVersion.DTLSv12.Only();
    }

    protected override int[] GetSupportedCipherSuites()
    {
        return this.config.CipherSuites.ToArray();
    }

    public override Org.BouncyCastle.Tls.CertificateRequest GetCertificateRequest()
    {
        // if no CAs are registered, we wont need a certificate for authentication.
        if (this.config.CAs.Count == 0)
        {
            return null;
        }

        var serverSigAlgs = TlsUtilities.GetDefaultSupportedSignatureAlgorithms(m_context);
        // currently only ecdsa supported
        // todo check if any is RSA certificate and add RSA certificate type
        serverSigAlgs = serverSigAlgs.Where(s => s.Signature == SignatureAlgorithm.ecdsa).ToList();

        // send back a list of supported CAs
        var authorities = this.config.CAs.Select(ca => ca.SubjectDN).ToList();
        
        short[] certificateTypes = new short[] { ClientCertificateType.ecdsa_sign, };

        return new CertificateRequest(certificateTypes, serverSigAlgs, authorities);
    }

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

    public override void NotifyClientCertificate(Certificate clientCertificate)
    {
        if (clientCertificate.IsEmpty)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        var chain = clientCertificate.GetCertificateList()!;
        var chainAsCertificate = chain.Select(c => new X509Certificate(c.GetEncoded())).ToArray();
        var trustAnchors = this.config.CAs.Select(ca => new TrustAnchor(ca, null));

        var parameters = new PkixParameters(new SortedSet<TrustAnchor>(trustAnchors));
        parameters.IsRevocationEnabled = false;
        var path = new PkixCertPath(chainAsCertificate);
        var validator = new PkixCertPathValidator();
        validator.Validate(path, parameters);
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
        return this.config.EcCertificates.First();
    }
}
