namespace WorldDirect.CoAP.Server.Extensions;

using System.Security.Cryptography.X509Certificates;
using Configuration;
using DTLS;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

public class DTLSServerConfigBuilder
{
    // TODO: Check if certificate usage is allowed for server auth when loaded from files
    // TODO: Check if CA is allowed to be used for (KeyCertSign) when loaded from file
    private readonly BcTlsCrypto crypto;
    private readonly MutableDTLSServerConfig config;
    public DTLSServerConfigBuilder()
    {
        this.crypto = new BcTlsCrypto(new SecureRandom());
        this.config = new MutableDTLSServerConfig();
        this.config.Crypto = this.crypto;
    }

    public DTLSServerConfig Config => new (this.config);

    /// <summary>
    /// Loads the servers certificate based on the configuration settings.
    /// </summary>
    /// <param name="config">The settings to identify the certificate.</param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException"></exception>
    public DTLSServerConfigBuilder SetCertificate(CertificateConfig config)
    {
        if (config.IsFromStore)
        {
            var ecdasCert = this.LoadCertAndKeyFromStore(config);
            this.config.EcCertificate = ecdasCert;
        }
        else if (config.IsFile)
        {
            try
            {
                // *.pem and *.key file
                if (!string.IsNullOrEmpty(config.Path) && !string.IsNullOrEmpty(config.KeyPath))
                {
                    var ecdsaCert = this.LoadCertAndKeyFromFiles(config);
                    this.config.EcCertificate = ecdsaCert;
                }
                // pfx file
                else if (!string.IsNullOrEmpty(config.Path))
                {
                    var ecdsaCert = this.LoadCertAndKeyFromPfxFile(config);
                    this.config.EcCertificate = ecdsaCert;
                }
                else
                {
                    throw new InvalidOperationException("Invalid configuration for certificate");
                }
            }
            catch (IOException e)
            {
                throw new InvalidOperationException($"Failed to load certificate file {config.Path}", e);
            }
        }
        else
        {
            throw new InvalidOperationException($"Invalid configuration for certificate");
        }
        this.config.CipherSuites.Add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
        this.config.CipherSuites.Add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);

        return this;
    }

    public DTLSServerConfigBuilder AddCA(CertificateConfig config)
    {
        if (config.IsFromStore)
        {
            var cert = this.LoadCAFromStore(config);
            this.config.CAs.Add(cert);
        }
        else if (config.IsFile)
        {
            try
            {
                // pfx file, password can be empty
                if (!string.IsNullOrEmpty(config.Path) && config.Password != null)
                {
                    throw new NotImplementedException("");
                }
                // pem file
                else if (!string.IsNullOrEmpty(config.Path))
                {
                    var cert = this.LoadCertFromFile(config.Path!);
                    this.config.CAs.Add(cert);
                }
                else
                {
                    throw new InvalidOperationException("Invalid file configuration for CA certificate.");
                }
            }
            catch (IOException e)
            {
                throw new InvalidOperationException($"Failed to load CA certificate file {config.Path}", e);
            }
        }
        else
        {
            throw new InvalidOperationException($"Could not identify where to search for CA certificate.");
        }
        return this;
    }

    public DTLSServerConfigBuilder SetHandshakeTimeout(TimeSpan timeout)
    {
        this.config.HandshakeTimeout = timeout;
        return this;
    }

    /// <summary>
    /// Add an exporter of the session keys.
    /// </summary>
    /// <remarks>ATTENTION!! will export session keys. Only use in development.</remarks>
    /// <param name="store">The store where the keys should be exported.</param>
    /// <returns>The builder.</returns>
    public DTLSServerConfigBuilder EnableExportOfSessionKeys(IKeyStore store)
    {
        this.config.KeyStore = store;
        return this;
    }

    public DTLSServerConfigBuilder SetPskManager(TlsPskIdentityManager manager)
    {
        this.config.PskManager = manager;
        this.config.CipherSuites.Add(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8);
        this.config.CipherSuites.Add(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256);
        return this;
    }

    private Org.BouncyCastle.X509.X509Certificate LoadCertFromFile(string filename)
    {
        using var certReader = File.OpenRead(filename);
        using var certTextReader = new StreamReader(certReader);
        var certPemReader = new PemReader(certTextReader);
        var certObject = certPemReader.ReadObject();
        if (certObject.GetType() != typeof(Org.BouncyCastle.X509.X509Certificate))
        {
            throw new InvalidOperationException($"Expected certificate in {filename}");
        }

        var cert = certObject as Org.BouncyCastle.X509.X509Certificate;
        return cert!;
    }

    private EcServerCertificate LoadCertAndKeyFromFiles(CertificateConfig config)
    {
        var password = config.Password ?? string.Empty;
        using var reader = File.OpenRead(config.KeyPath!);
        using var textReader = new StreamReader(reader);
        PemReader pemReader = new PemReader(textReader, new InMemoryPasswordFinder(password));

        var keyObj = pemReader.ReadPemObject();
        var key = PrivateKeyFactory.CreateKey(keyObj.Content);

        if (key.GetType() != typeof(ECPrivateKeyParameters))
        {
            throw new InvalidOperationException($"{config.KeyPath} does not store a EC key. Currently only ECDSA is supported");
        }

        var caPrivateKey = key as ECPrivateKeyParameters;

        var cert = this.LoadCertFromFile(config.Path!);

        var x509bc = this.crypto.CreateCertificate(cert!.GetEncoded());

        var ecdsaCertificate = new Certificate(new[] { x509bc });
        var ecCert = new EcServerCertificate(ecdsaCertificate, caPrivateKey!);
        return ecCert;
    }

    private EcServerCertificate LoadCertAndKeyFromPfxFile(CertificateConfig config)
    {
        var password = config.Password ?? string.Empty;
        using var file = File.OpenRead(config.Path!);
        var store = new Pkcs12StoreBuilder().Build();
        store.Load(file, password.ToCharArray());
        X509CertificateEntry? certEntry = null;
        AsymmetricKeyEntry? keyEntry = null;
        foreach (var alias in store.Aliases)
        {
            var cert = store.GetCertificate(alias);
            if (cert != null)
            {
                certEntry = cert;
            }

            var k = store.GetKey(alias);
            if (k != null)
            {
                keyEntry = k;
            }
        }

        if (certEntry == null)
        {
            throw new InvalidOperationException($"Could not decode certificate in {config.Path}");
        }
        if (keyEntry == null)
        {
            throw new InvalidOperationException($"Could not decode key in {config.Path}");
        }

        if (keyEntry.Key.GetType() != typeof(ECPrivateKeyParameters))
        {
            throw new InvalidOperationException($"Currently on EC Key/Certificate is supported. File: {config.Path} contains invalid pair.");
        }

        var x509bc = this.crypto.CreateCertificate(certEntry.Certificate.GetEncoded());
        var ecPrivateKey = (keyEntry.Key as ECPrivateKeyParameters)!;

        var ecdsaCertificate = new Certificate(new[] { x509bc });
        var ecCert = new EcServerCertificate(ecdsaCertificate, ecPrivateKey);
        return ecCert;
    }

    private EcServerCertificate LoadCertAndKeyFromStore(CertificateConfig config)
    {
        var cert = CertificateManager.LoadFromStore(config.Store!, config.Location!, config.Subject!, config.AllowInvalid);
        if (!cert.HasPrivateKey)
        {
            throw new InvalidOperationException($"Private key of {config.Subject} is missing");
        }
        // other algorithms than ecdsa are currently not supported
        var key = cert.GetECDsaPrivateKey();
        if (key == null)
        {
            throw new InvalidOperationException($"Certificate {config.Subject} is not a ECDSA Certificate.");
        }


        // need to convert to Bouncycastle Certificate
        var ecdasCert = this.ToECServerCertificate(cert);
        return ecdasCert;
    }

    private Org.BouncyCastle.X509.X509Certificate LoadCAFromStore(CertificateConfig config)
    {
        var cert = CertificateManager.LoadCAFromStore(config.Store!, config.Location!, config.Subject!, config.AllowInvalid);
        return cert.ToBouncyCastle();
    }

    private EcServerCertificate ToECServerCertificate(X509Certificate2 certificate)
    {
        var certBuffer = certificate.Export(X509ContentType.Pkcs12);
        var store = new Pkcs12StoreBuilder().Build();
        store.Load(new MemoryStream(certBuffer), Array.Empty<char>());
        X509CertificateEntry? certEntry = null;
        AsymmetricKeyEntry? keyEntry = null;
        foreach (var alias in store.Aliases)
        {
            var cert = store.GetCertificate(alias);

            var k = store.GetKey(alias);
            if (k != null && cert != null)
            {
                keyEntry = k;
                certEntry = cert;
            }
        }

        if (certEntry == null || keyEntry == null)
        {
            throw new InvalidOperationException($"Could not find certificate or key for {certificate.SubjectName}");
        }

        var x509bc = this.crypto.CreateCertificate(certEntry.Certificate.GetEncoded());
        var ecPrivateKey = (keyEntry.Key as ECPrivateKeyParameters)!;

        var ecdsaCertificate = new Certificate(new[] { x509bc });
        var ecCert = new EcServerCertificate(ecdsaCertificate, ecPrivateKey);
        return ecCert;
    }
}
