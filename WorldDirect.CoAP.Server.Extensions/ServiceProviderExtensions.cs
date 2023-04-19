namespace WorldDirect.CoAP.Server.Extensions
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;
    using Channel;
    using Configuration;
    using DTLS;
    using Microsoft.Extensions.Caching.Memory;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Net;
    using Org.BouncyCastle.Asn1.Cmp;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Ocsp;
    using Org.BouncyCastle.OpenSsl;
    using Org.BouncyCastle.Pkcs;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.Tls;
    using Org.BouncyCastle.Tls.Crypto.Impl.BC;
    using Org.BouncyCastle.X509;

    internal class CertificateManager
    {
        private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

        public static X509Certificate2 LoadFromStore(string subject, StoreName storeName, StoreLocation storeLocation, bool allowInvalid)
        {
            using (var store = new X509Store(storeName, storeLocation))
            {
                X509Certificate2Collection? storeCertificates = null;
                X509Certificate2? foundCertificate = null;
                store.Open(OpenFlags.ReadOnly);
                storeCertificates = store.Certificates;
                foreach (var certificate in storeCertificates.Find(X509FindType.FindBySubjectName, subject, !allowInvalid)
                             .OfType<X509Certificate2>()
                             .Where(IsCertificateAllowedForServerAuth)
                             .Where(cert => cert.HasPrivateKey)
                             .OrderByDescending(certificate => certificate.NotAfter))
                {
                    // Pick the first one if there's no exact match as a fallback to substring default.
                    foundCertificate ??= certificate;

                    if (certificate.GetNameInfo(X509NameType.SimpleName, true).Equals(subject, StringComparison.InvariantCultureIgnoreCase))
                    {
                        foundCertificate = certificate;
                        break;
                    }
                }

                if (foundCertificate == null)
                {
                    throw new InvalidOperationException($"Found no certificate with name {subject}");
                }

                return foundCertificate;
            }
        }


        public static X509Certificate2 LoadFromStore(string name, string location, string subject, bool allowInvalid)
        {

            var storeName = Enum.Parse<StoreName>(name);
            var storeLocation = Enum.Parse<StoreLocation>(location);

            return LoadFromStore(subject, storeName, storeLocation, allowInvalid);
        }

        public static X509Certificate2 LoadCAFromStore(string subject, StoreName storeName, StoreLocation storeLocation, bool allowInvalid)
        {
            using (var store = new X509Store(storeName, storeLocation))
            {
                X509Certificate2Collection? storeCertificates = null;
                X509Certificate2? foundCertificate = null;
                store.Open(OpenFlags.ReadOnly);
                storeCertificates = store.Certificates;
                foreach (var certificate in storeCertificates.Find(X509FindType.FindBySubjectName, subject, !allowInvalid)
                             .OfType<X509Certificate2>()
                             .Where(IsCertificateAllowedForCA)
                             .OrderByDescending(certificate => certificate.NotAfter))
                {
                    // Pick the first one if there's no exact match as a fallback to substring default.
                    foundCertificate ??= certificate;

                    if (certificate.GetNameInfo(X509NameType.SimpleName, true).Equals(subject, StringComparison.InvariantCultureIgnoreCase))
                    {
                        foundCertificate = certificate;
                        break;
                    }
                }

                if (foundCertificate == null)
                {
                    throw new InvalidOperationException($"Found no certificate with name {subject}");
                }

                return foundCertificate;
            }
        }

        public static X509Certificate2 LoadCAFromStore(string name, string location, string subject, bool allowInvalid)
        {

            var storeName = Enum.Parse<StoreName>(name);
            var storeLocation = Enum.Parse<StoreLocation>(location);

            return LoadCAFromStore(subject, storeName, storeLocation, allowInvalid);
        }

        private static bool IsCertificateAllowedForCA(X509Certificate2 certificate)
        {

            var keyUsageExtension = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            if (keyUsageExtension != null)
            {
                if ((keyUsageExtension.KeyUsages & X509KeyUsageFlags.KeyCertSign) == X509KeyUsageFlags.None)
                {
                    return false;
                }
            }

            var basicConstraintExtension = certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
            if (basicConstraintExtension != null)
            {
                if (!basicConstraintExtension.CertificateAuthority)
                {
                    return false;
                }
            }

            return true;
        }

        private static bool IsCertificateAllowedForServerAuth(X509Certificate2 certificate)
        {
            /* If the Extended Key Usage extension is included, then we check that the serverAuth usage is included. (http://oid-info.com/get/1.3.6.1.5.5.7.3.1)
             * If the Extended Key Usage extension is not included, then we assume the certificate is allowed for all usages.
             *
             * See also https://blogs.msdn.microsoft.com/kaushal/2012/02/17/client-certificates-vs-server-certificates/
             *
             * From https://tools.ietf.org/html/rfc3280#section-4.2.1.13 "Certificate Extensions: Extended Key Usage"
             *
             * If the (Extended Key Usage) extension is present, then the certificate MUST only be used
             * for one of the purposes indicated.  If multiple purposes are
             * indicated the application need not recognize all purposes indicated,
             * as long as the intended purpose is present.  Certificate using
             * applications MAY require that a particular purpose be indicated in
             * order for the certificate to be acceptable to that application.
             */

            var hasEkuExtension = false;

            foreach (var extension in certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>())
            {
                hasEkuExtension = true;
                foreach (var oid in extension.EnhancedKeyUsages)
                {
                    if (string.Equals(oid.Value, ServerAuthenticationOid, StringComparison.Ordinal))
                    {
                        return true;
                    }
                }
            }

            return !hasEkuExtension;
        }
    }

    internal class InMemoryPasswordFinder : IPasswordFinder
    {
        private readonly string password;
        public InMemoryPasswordFinder(string password)
        {
            this.password = password;
        }
        public char[] GetPassword()
        {
            return this.password.ToCharArray();
        }
    }

    public class DTLSServerBuilder
    {
        // TODO: Check if certificate usage is allowed for server auth when loaded from files
        // TODO: Check if CA is allowed to be used for (KeyCertSign) when loaded from file
        private readonly BcTlsCrypto crypto;
        private readonly DTLSServerConfig config;
        public DTLSServerBuilder()
        {
            this.crypto = new BcTlsCrypto(new SecureRandom());
            this.config = new DTLSServerConfig();
        }

        public DTLSServerBuilder AddCertificate(CertificateConfig config)
        {
            // todo check if multiple certificates are valid for same host
            // see DTLSServer FindCertificate Function for more information
            if (config.IsFromStore)
            {
                var ecdasCert = this.LoadCertAndKeyFromStore(config);
                this.config.EcCertificates.Add(ecdasCert);
            }
            else if (config.IsFile)
            {
                try
                {
                    // *.pem and *.key file
                    if (!string.IsNullOrEmpty(config.Path) && !string.IsNullOrEmpty(config.KeyPath))
                    {
                        var ecdsaCert = this.LoadCertAndKeyFromFiles(config);
                        this.config.EcCertificates.Add(ecdsaCert);
                    }
                    // pfx file
                    else if (!string.IsNullOrEmpty(config.Path))
                    {
                        var ecdsaCert = this.LoadCertAndKeyFromPfxFile(config);
                        this.config.EcCertificates.Add(ecdsaCert);
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

        public DTLSServerBuilder AddCA(CertificateConfig config)
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
                    // pem file
                    if (!string.IsNullOrEmpty(config.Path))
                    {
                        var cert = this.LoadCertFromFile(config.Path!);
                        this.config.CAs.Add(cert);
                    }
                    else
                    {
                        throw new InvalidOperationException("Invalid configuration for CA certificate");
                    }
                }
                catch (IOException e)
                {
                    throw new InvalidOperationException($"Failed to load CA certificate file {config.Path}", e);
                }
            }
            else
            {
                throw new InvalidOperationException($"Invalid configuration for CA certificate");
            }
            return this;
        }

        public DTLSServerBuilder SetHandshakeTimeout(TimeSpan timeout)
        {
            this.config.HandshakeTimeout = timeout;
            return this;
        }


        public DTLSServer Build()
        {
            return new DTLSServer(this.crypto, this.config);
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

            object keyObj = pemReader.ReadObject();

            if (keyObj.GetType() != typeof(ECPrivateKeyParameters))
            {
                throw new InvalidOperationException($"{config.KeyPath} does not store a EC key. Currently only ECDSA is supported");
            }

            var key = keyObj as ECPrivateKeyParameters;

            var cert = this.LoadCertFromFile(config.Path!);

            var x509bc = this.crypto.CreateCertificate(cert!.GetEncoded());

            var ecdsaCertificate = new Certificate(new[] { x509bc });
            var ecCert = new EcServerCertificate(ecdsaCertificate, key!);
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
            return this.ToBcCertificate(cert);
        }

        private Org.BouncyCastle.X509.X509Certificate ToBcCertificate(X509Certificate2 cert)
        {
            return new Org.BouncyCastle.X509.X509Certificate(cert.Export(X509ContentType.Cert));
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

    internal class DTLSFactory : IDTLSFactory
    {
        private readonly DTLSServerBuilder builder;

        public DTLSFactory(DTLSServerBuilder builder)
        {
            this.builder = builder;
        }
        public DTLSServer CreateServer()
        {
            return this.builder.Build();
        }
    }

    public static class ServiceProviderExtensions
    {

        /// <summary>
        /// Requires an <see cref="IMemoryCache"/> in the service provider.
        /// </summary>
        /// <param name="services"></param>
        /// <param name="configuration"></param>
        /// <returns></returns>
        public static IServiceCollection ConfigureCoAPServer(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddSingleton(serviceProvider => Configure(serviceProvider, configuration));

            return services;
        }

        private static CoapServer Configure(IServiceProvider serviceProvider, IConfiguration configuration)
        {
            var server = new CoapServer();


            var loader = new CoAPServerOptionsLoader(configuration);
            var options = loader.Options;

            foreach (var listenEndpoint in options.ListenOptions)
            {
                if (listenEndpoint!.EndpointConfig.CertificateConfig == null)
                {
                    // unsecure
                    server.AddEndPoint(listenEndpoint.Endpoint as IPEndPoint);
                }
                else
                {
                    var dtlsServerBuilder = new DTLSServerBuilder()
                        .AddCertificate(listenEndpoint.EndpointConfig.CertificateConfig)
                        .SetHandshakeTimeout(listenEndpoint.EndpointConfig.HandshakeTimeout);

                    if (listenEndpoint.EndpointConfig.ClientCA != null && listenEndpoint.EndpointConfig.ClientCA.Length > 0)
                    {
                        foreach (var ca in listenEndpoint.EndpointConfig.ClientCA)
                        {
                            dtlsServerBuilder.AddCA(ca);
                        }
                    }

                    var channel = new UDPChannel(listenEndpoint.Endpoint);
                    var config = CoapConfig.Default;
                    channel.ReceiveBufferSize = config.ChannelReceiveBufferSize;
                    channel.SendBufferSize = config.ChannelSendBufferSize;
                    channel.ReceivePacketSize = config.ChannelReceivePacketSize;

                    var ep = new CoAPSEndpoint(serviceProvider.GetRequiredService<IMemoryCache>(), new DTLSFactory(dtlsServerBuilder), channel);

                    server.AddEndPoint(ep);
                }
            }



            return server;
        }
    }
}
