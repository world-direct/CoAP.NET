namespace WorldDirect.Dtls;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;

class Server : DefaultTlsServer
{
    private static readonly int[] DefaultCipherSuites = new int[]
    {
        /*
             * TLS 1.3
             */
        //CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_AES_256_GCM_SHA384,
        CipherSuite.TLS_AES_128_GCM_SHA256,

        /*
         * pre-TLS 1.3
         */
        /*CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
        CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,*/
        CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
    };
    public Server(TlsCrypto crypto) : base(crypto)
    {

    }

    public override ProtocolVersion GetServerVersion()
    {
        ProtocolVersion serverVersion = base.GetServerVersion();

        Console.WriteLine("DTLS server negotiated " + serverVersion);

        return serverVersion;
    }

    public override CertificateRequest GetCertificateRequest()
    {
        var serverSigAlgs = TlsUtilities.GetDefaultSupportedSignatureAlgorithms(m_context);
        var certificateAuthorities = new List<X509Name>() { new X509Name("CN=World-DirectRootCA512"), };
        short[] certificateTypes = new short[] { ClientCertificateType.rsa_sign, };

        return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
    }

    protected override ProtocolVersion[] GetSupportedVersions()
    {
        return ProtocolVersion.DTLSv12.Only();
    }

    protected override int[] GetSupportedCipherSuites()
    {
        return TlsUtilities.GetSupportedCipherSuites(Crypto, DefaultCipherSuites);
    }

    protected override TlsCredentialedDecryptor GetRsaEncryptionCredentials()
    {
        var privateKey = LoadPrivateKey("server-key.pem");
        var certificate = LoadCertificate("server-cert.pem");
        return new BcDefaultTlsCredentialedDecryptor((BcTlsCrypto)this.Crypto, new Certificate(new[] { certificate }),
            privateKey);
    }

    public bool IsConnected { get; private set; } = false;

    public override void NotifyHandshakeComplete()
    {
        base.NotifyHandshakeComplete();
        this.IsConnected = true;
    }

    public override void NotifyClientCertificate(Certificate clientCertificate)
    {
        if (clientCertificate.IsEmpty)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
        var ca = LoadCertificate("WorldDirectRoot.crt");

        var chain = clientCertificate.GetCertificateList();

        var chainAsCertificate = chain.Select(c => new X509Certificate(c.GetEncoded())).ToArray();

        var caX509 = new X509Certificate(ca.GetEncoded());
        var trustAnchor = new TrustAnchor(caX509, null);

        var parameters = new PkixParameters(new SortedSet<TrustAnchor>() { trustAnchor });
        parameters.IsRevocationEnabled = false;
        var path = new PkixCertPath(chainAsCertificate);
        var validator = new PkixCertPathValidator();
        validator.Validate(path, parameters);
    }

    public System.Security.Cryptography.X509Certificates.X509Certificate GetPeerCertificate()
    {

        var certBytes = this.m_context.SecurityParameters.PeerCertificate.GetCertificateList().First().GetEncoded();
        var cert = new System.Security.Cryptography.X509Certificates.X509Certificate(certBytes);
        return cert;
    }

    /*protected override TlsCredentialedSigner GetRsaSignerCredentials()
        {
            var key = LoadPrivateKey("ecc-key.pem");
            var certificate = LoadCertificate("server-cert.pem");
            return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(this.m_context), (BcTlsCrypto)this.Crypto, key,
                new Certificate(new [] {certificate}), SignatureAndHashAlgorithm.rsa_pss_pss_sha256);
        }*/

    private TlsCertificate LoadCertificate(string path)
    {
        using var file = File.Open(path, FileMode.Open);
        using var streamReader = new StreamReader(file);
        using var pemReader = new PemReader(streamReader);
        var pem = pemReader.ReadPemObject();
        if (pem.Type.EndsWith("CERTIFICATE"))
        {
            return this.Crypto.CreateCertificate(pem.Content);
        }

        throw new Exception("Cant load certificate");
    }

    private AsymmetricKeyParameter LoadPrivateKey(string path)
    {
        using var file = File.Open(path, FileMode.Open);
        using var streamReader = new StreamReader(file);
        using var pemReader = new PemReader(streamReader);
        var pem = pemReader.ReadPemObject();
        if (!pem.Type.Equals("RSA PRIVATE KEY"))
        {
            throw new Exception("Expected RSA private key");
        }

        var rsa = RsaPrivateKeyStructure.GetInstance(pem.Content);
        return new RsaPrivateCrtKeyParameters(rsa.Modulus, rsa.PublicExponent,
            rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1,
            rsa.Exponent2, rsa.Coefficient);
    }
}