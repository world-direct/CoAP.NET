namespace WorldDirect.CoAP.Hosting.Configuration
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.OpenSsl;
    using Org.BouncyCastle.Pkcs;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.Tls;
    using Org.BouncyCastle.Tls.Crypto;
    using WorldDirect.CoAP.DTLS;

    internal class CertificateLoader
    {
        private readonly TlsCrypto crypto;

        public CertificateLoader(TlsCrypto crypto)
        {
            this.crypto = crypto;
        }

        public EcServerCertificate LoadCertificate(CertificateOption config)
        {
            if (config.IsFromStore)
            {
                var ecdasCert = this.LoadCertAndKeyFromStore(config);
                return ecdasCert;
            }

            if (config.IsFile)
            {
                try
                {
                    // *.pem and *.key file
                    if (!string.IsNullOrEmpty(config.Path) && !string.IsNullOrEmpty(config.KeyPath))
                    {
                        var ecdsaCert = this.LoadCertAndKeyFromFiles(config);
                        return ecdsaCert;
                    }
                    // pfx file

                    if (!string.IsNullOrEmpty(config.Path))
                    {
                        var ecdsaCert = this.LoadCertAndKeyFromPfxFile(config);
                        return ecdsaCert;
                    }
                    throw new InvalidOperationException("Invalid configuration for certificate");
                }
                catch (IOException e)
                {
                    throw new InvalidOperationException($"Failed to load certificate file {config.Path}", e);
                }
            }
            throw new InvalidOperationException($"Invalid configuration for certificate");
        }

        public Org.BouncyCastle.X509.X509Certificate LoadCA(CertificateOption config)
        {
            if (config.IsFromStore)
            {
                var cert = this.LoadCAFromStore(config);
                return cert;
            }

            if (config.IsFile)
            {
                try
                {
                    // pfx file, password can be empty
                    if (!string.IsNullOrEmpty(config.Path) && config.Password != null)
                    {
                        throw new NotImplementedException("Please provide CA in pem format.");
                    }
                    // pem file

                    if (!string.IsNullOrEmpty(config.Path))
                    {
                        var cert = this.LoadCertFromFile(config.Path!);
                        return cert;
                    }
                    throw new InvalidOperationException("Invalid file configuration for CA certificate.");
                }
                catch (IOException e)
                {
                    throw new InvalidOperationException($"Failed to load CA certificate file {config.Path}", e);
                }
            }
            throw new InvalidOperationException($"Could not identify where to search for CA certificate.");
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

        private EcServerCertificate LoadCertAndKeyFromFiles(CertificateOption config)
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

        private EcServerCertificate LoadCertAndKeyFromPfxFile(CertificateOption config)
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

        private EcServerCertificate LoadCertAndKeyFromStore(CertificateOption config)
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

        private Org.BouncyCastle.X509.X509Certificate LoadCAFromStore(CertificateOption config)
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
}
