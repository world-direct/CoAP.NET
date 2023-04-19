namespace WorldDirect.CoAP.DTLS;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.X509;

/// <summary>
///
/// </summary>
/// <remarks>
/// Limitations:
///     only one ECDSA Chain Certificate work (not RSA, not multiple)
/// </remarks>
public class DTLSServerBuilder
{
    private readonly BcTlsCrypto crypto;
    private Pkcs12Store? store;
    private List<Org.BouncyCastle.X509.X509Certificate> CAs = new();

    private readonly DTLSServerConfig config;

    public DTLSServerBuilder()
    {
        this.crypto = new BcTlsCrypto(new SecureRandom());
        this.config = new DTLSServerConfig();
    }

    public DTLSServerBuilder WithStore(string file, string password)
    {
        var store = new Pkcs12StoreBuilder().Build();
        using var reader = File.OpenRead(file);
        store.Load(reader, password.ToCharArray());
        this.store = store;
        return this;
    }

    public DTLSServerBuilder WithHandShakeTimeout(TimeSpan timeout)
    {
        this.config.HandshakeTimeout = timeout;
        return this;
    }

    /// <summary>
    /// Loads the certificate chain and its private key from the store. The store must be loaded before with <seealso cref="WithStore"/> function.
    /// </summary>
    /// <param name="alias">The alias which identifies the certificate.</param>
    /// <returns></returns>
    public DTLSServerBuilder WithEcdsaCertificate(string alias)
    {
        // check if certificate is ecdsa certificate.
        var certificateChain = this.store!.GetCertificateChain(alias);
        var key = this.store!.GetKey(alias);

        var serverCert = certificateChain[0].Certificate;
        var der = new DerObjectIdentifier(serverCert.SigAlgOid);
        if (!der.On(X9ObjectIdentifiers.id_ecSigType))
        {
            // signature algorithm of certificate is not ECDSA
            throw new InvalidOperationException(
                $"Provided certificate of {alias} was signed with {serverCert.SigAlgName}. This not an ECDSA algorithm");
        }
        if (key.Key.GetType() != typeof(ECPrivateKeyParameters))
        {
            throw new InvalidOperationException($"Provided key of {alias} is not an ECKey");
        }

        var x509Certs = certificateChain.Select(c => this.crypto.CreateCertificate(c.Certificate.GetEncoded()));

        var ecPrivateKey = (key.Key as ECPrivateKeyParameters)!;
        var ecdsaCertificate = new Certificate(x509Certs.ToArray());

        this.config.EcCertificates.Add(new EcServerCertificate(ecdsaCertificate, ecPrivateKey));
        if (this.config.EcCertificates.Count > 1)
        {
            throw new InvalidOperationException("Currently one one certificate is supported.");
        }
        return this;
    }

    /// <summary>
    /// Loads a trusted root CA from a pem encoded file.
    /// </summary>
    /// <param name="filename">The filename fo load the CA from.</param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException"></exception>
    /// <exception cref="IOException"></exception>
    public DTLSServerBuilder WithTrustedRoot(string filename)
    {
        X509CertificateParser parser = new X509CertificateParser();
        using var file = File.Open(filename, FileMode.Open);
        var cert = parser.ReadCertificate(file);
        if (cert == null)
        {
            throw new InvalidOperationException($"Could not read certificate from {filename}");
        }
        this.config.CAs.Add(cert);
        return this;
    }

    public DTLSServerBuilder WithCipherSuites(IEnumerable<int> suites)
    {
        this.config.CipherSuites.AddRange(suites);
        // todo check if possibility to check if selected suites are valid with current configuration (ECDSA & RSA avaiable? configured psk?)
        return this;
    }

    public DTLSServer Build()
    {
        return new DTLSServer(this.crypto, this.config);
    }
}
