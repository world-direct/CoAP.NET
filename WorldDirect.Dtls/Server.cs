namespace WorldDirect.Dtls;

using System.Text;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;

class Server : AbstractTlsServer
{
    private readonly TlsPskIdentityManager? pskManager;

    private static readonly int[] DefaultCipherSuites = new int[]
    {
        /*
             * TLS 1.3
             */
        //CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        //CipherSuite.TLS_AES_256_GCM_SHA384,
        //CipherSuite.TLS_AES_128_GCM_SHA256,
        //CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
        //CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
        CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256,
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
        /*CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,*/
    };
    public Server(TlsCrypto crypto, TlsPskIdentityManager? pskManager) : base(crypto)
    {
        this.pskManager = pskManager;
    }

    public string PublicIdentifier
    {
        get
        {
            if (this.Certificate == null)
            {
                return Encoding.ASCII.GetString(this.m_context.SecurityParameters.PskIdentity);
            }

            return this.Certificate.GetCommonName();
        }
    }

    public System.Security.Cryptography.X509Certificates.X509Certificate? Certificate
    {
        get
        {
            return this.GetPeerCertificate();
        }
    }

    private System.Security.Cryptography.X509Certificates.X509Certificate? GetPeerCertificate()
    {
        if (this.m_context.SecurityParameters.PeerCertificate == null || this.m_context.SecurityParameters.PeerCertificate.IsEmpty)
        {
            return null;
        }
        var certBytes = this.m_context.SecurityParameters.PeerCertificate.GetCertificateList().First().GetEncoded();
        var cert = new System.Security.Cryptography.X509Certificates.X509Certificate(certBytes);
        return cert;
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
        // send back a list of supported CAs (if wanted)
        var certificateAuthorities = new List<X509Name>() { new X509Name("CN=World-DirectRootCA512"), };
        short[] certificateTypes = new short[] { ClientCertificateType.rsa_sign, ClientCertificateType.ecdsa_sign, };

        return new CertificateRequest(certificateTypes, serverSigAlgs, null);
    }

    protected override ProtocolVersion[] GetSupportedVersions()
    {
        return ProtocolVersion.DTLSv12.Only();
    }

    protected override int[] GetSupportedCipherSuites()
    {
        return TlsUtilities.GetSupportedCipherSuites(Crypto, DefaultCipherSuites);
    }

    protected virtual TlsCredentialedDecryptor GetRsaEncryptionCredentials()
    {
        var privateKey = LoadPrivateKey("crypt/server-key-wolfssl.pem");
        var certificate = LoadCertificate("crypt/server-cert-wolfssl.pem");
        return new BcDefaultTlsCredentialedDecryptor((BcTlsCrypto)this.Crypto, new Certificate(new[] { certificate }),
            privateKey);
    }

    protected virtual TlsCredentialedSigner GetECDsaSignerCredentials()
    {
        var serverNames = this.m_context.SecurityParameters.ClientServerNames;
        var key = this.LoadPrivateKey("server-key.pem");
        var certificate = this.LoadCertificate("server-cert.pem");
        if (key is ECPrivateKeyParameters eckey)
        {
            var signer = new BcTlsECDsaSigner((BcTlsCrypto)this.Crypto, eckey);
            var parameter = new TlsCryptoParameters(this.m_context);
            var scheme = SignatureScheme.ecdsa_secp256r1_sha256;
            var alg = new SignatureAndHashAlgorithm(SignatureScheme.GetHashAlgorithm(scheme), SignatureScheme.GetSignatureAlgorithm(scheme));
            var credSigner = new DefaultTlsCredentialedSigner(parameter, signer, new Certificate(new[] {certificate}), alg);
            return credSigner;
        }
        //var sig = new BcTlsECDsaSigner((BcTlsCrypto)this.Crypto, )
        //var signer = new DefaultTlsCredentialedSigner()
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public override TlsCredentials GetCredentials()
    {
        int keyExchangeAlgorithm = m_context.SecurityParameters.KeyExchangeAlgorithm;

        switch (keyExchangeAlgorithm)
        {
            case KeyExchangeAlgorithm.DHE_DSS:
            // return GetDsaSignerCredentials(); // see DefaultTlsServer for possible implementation
            case KeyExchangeAlgorithm.DHE_RSA:
            case KeyExchangeAlgorithm.ECDHE_RSA:
                //return GetRsaSignerCredentials(); // see DefaultTlsServer for possible implementation

                throw new TlsFatalAlert(AlertDescription.internal_error);


            case KeyExchangeAlgorithm.ECDHE_ECDSA:
                return GetECDsaSignerCredentials();

            case KeyExchangeAlgorithm.RSA:
                return GetRsaEncryptionCredentials();

            case KeyExchangeAlgorithm.DHE_PSK:
            case KeyExchangeAlgorithm.ECDHE_PSK:
            case KeyExchangeAlgorithm.PSK:
                return null;


            default:
                // Note: internal error here; selected a key exchange we don't implement!
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }
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
        //var ca = LoadCertificate("WorldDirectRoot.crt");
        var ca = LoadCertificate("ca-cert.pem");

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

    /*protected override TlsCredentialedSigner GetRsaSignerCredentials()
        {
            var key = LoadPrivateKey("ecc-key.pem");
            var certificate = LoadCertificate("server-cert.pem");
            return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(this.m_context), (BcTlsCrypto)this.Crypto, key,
                new Certificate(new [] {certificate}), SignatureAndHashAlgorithm.rsa_pss_pss_sha256);
        }*/

    public override TlsPskIdentityManager GetPskIdentityManager()
    {
        if (this.pskManager == null)
        {
            return base.GetPskIdentityManager();
        }

        return this.pskManager;
    }

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
        PemObject pem;
        {
            using var file = File.Open(path, FileMode.Open);
            using var streamReader = new StreamReader(file);
            using var pemReader = new PemReader(streamReader);

            pem = pemReader.ReadPemObject();
        }
        
        if (pem.Type.Equals("RSA PRIVATE KEY"))
        {
            var rsa = RsaPrivateKeyStructure.GetInstance(pem.Content);
            return new RsaPrivateCrtKeyParameters(rsa.Modulus, rsa.PublicExponent,
                rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1,
                rsa.Exponent2, rsa.Coefficient);
        }
        else if (pem.Type.Equals("EC PRIVATE KEY"))
        {
            ECPrivateKeyStructure pKey = ECPrivateKeyStructure.GetInstance(pem.Content);
            AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey,
                pKey.GetParameters());
            PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, pKey);
            return PrivateKeyFactory.CreateKey(privInfo);
        }

        throw new InvalidOperationException($"Cant decode private key in file {path}");


    }
}
