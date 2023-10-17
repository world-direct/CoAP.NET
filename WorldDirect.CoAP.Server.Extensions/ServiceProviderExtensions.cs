namespace WorldDirect.CoAP.Server.Extensions
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Runtime.CompilerServices;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using Channel;
    using Configuration;
    using DTLS;
    using LazyCache;
    using Microsoft.Extensions.Caching.Memory;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Net;
    using Org.BouncyCastle.Asn1.Cmp;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Ocsp;
    using Org.BouncyCastle.Tls;
    using Org.BouncyCastle.X509;
    using Threading;
    using WorldDirect.CoAP.Log;

    /// <summary>
    /// A helper function to determinate how PSKs are loaded and mapped to a CoAPS endpoint.
    /// </summary>
    /// <param name="serviceProvider">The service provider to load needed services from.</param>
    /// <param name="key">The name of the endpoint configuration.</param>
    /// <returns>The psk store.</returns>
    public delegate TlsPskIdentityManager? PskIdentityManagerResolver(IServiceProvider serviceProvider, string key);

    public static class ServiceProviderExtensions
    {

        /// <summary>
        /// Configures a <see cref="CoapServer"/> based on the provided configuration.
        /// </summary>
        /// <remarks>
        /// If PSKs should be used <see cref="PskIdentityManagerResolver"/> must be added to the ServiceCollection.
        /// </remarks>
        /// <param name="services"></param>
        /// <param name="configuration"></param>
        /// <returns></returns>
        public static IServiceCollection ConfigureCoAPServer(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddLazyCache();
            services.AddSingleton(serviceProvider => Configure(serviceProvider, configuration));

            return services;
        }

        private static CoapServer Configure(IServiceProvider serviceProvider, IConfiguration configuration)
        {
            LogManager.Provider = serviceProvider;
            var server = new CoapServer();


            var loader = new CoAPServerOptionsLoader(configuration);
            var options = loader.Options;

            foreach (var listenEndpoint in options.ListenOptions)
            {
                if (listenEndpoint!.EndpointConfig.CertificateConfig == null && !listenEndpoint.EndpointConfig.Url.StartsWith("coaps"))
                {
                    // insecure
                    server.AddEndPoint(listenEndpoint.Endpoint as IPEndPoint);
                }
                else
                {
                    var dtlsServerBuilder = new DTLSServerConfigBuilder();
                    if (listenEndpoint.EndpointConfig.CertificateConfig != null)
                    {
                        dtlsServerBuilder.SetCertificate(listenEndpoint.EndpointConfig.CertificateConfig);
                    }
                    dtlsServerBuilder.SetHandshakeTimeout(listenEndpoint.EndpointConfig.HandshakeTimeout);
                    var resolver = serviceProvider.GetService<PskIdentityManagerResolver>();
                    if (resolver != null)
                    {
                        var pskManager = resolver(serviceProvider, listenEndpoint.EndpointConfig.Name);
                        if (pskManager != null)
                        {
                            dtlsServerBuilder.SetPskManager(pskManager);
                        }
                    }

                    var keyStore = serviceProvider.GetService<IKeyStore>();
                    if (keyStore != null)
                    {
                        dtlsServerBuilder.EnableExportOfSessionKeys(keyStore);
                    }

                    foreach (var ca in listenEndpoint.EndpointConfig.ClientCAs)
                    {
                        dtlsServerBuilder.AddCA(ca);
                    }

                    var channel = new UDPChannel(listenEndpoint.Endpoint);
                    var config = (CoapConfig)CoapConfig.Default;
                    // config.MaxMessageSize is used to check payload length
                    // we SHOULD store DTLSServer.MaxFragmentLength in block layer for each client
                    // to be able to determine how long the longest CoAP Message for a client is
                    // but this is too much of a refactoring at the moment
                    // thats why we use some buffer and only support FragmentLength defined by MaxMessageSize
                    // possible values are 128, 256 and 512
                    // MaxMessageSize must be set to the least expected FragmentLength of the DTLS Clients
                    // Otherwise sending request wont work the FragmentLength is not in sync with the Blockwise layer
                    config.MaxMessageSize = options.MaxMessageSize - 64;
                    if(config.MaxMessageSize <= config.DefaultBlockSize)
                    {
                        config.DefaultBlockSize = config.MaxMessageSize / 2;
                    }
                    channel.ReceiveBufferSize = config.ChannelReceiveBufferSize;
                    channel.SendBufferSize = config.ChannelSendBufferSize;
                    channel.ReceivePacketSize = config.ChannelReceivePacketSize;

                    var ep = new CoAPSEndpoint(serviceProvider.GetRequiredService<IAppCache>(), dtlsServerBuilder.Config, channel, config);
                    //ep.Executor = new ThreadPoolExecutor();
                    server.AddEndPoint(ep);
                }
            }



            return server;
        }
    }
}
