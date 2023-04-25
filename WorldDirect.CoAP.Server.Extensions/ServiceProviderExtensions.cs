namespace WorldDirect.CoAP.Server.Extensions
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using Channel;
    using Configuration;
    using Microsoft.Extensions.Caching.Memory;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Net;
    using Org.BouncyCastle.Asn1.Cmp;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Ocsp;
    using Org.BouncyCastle.X509;

    public static class ServiceProviderExtensions
    {

        /// <summary>
        /// Configures a <see cref="CoapServer"/> based on the provided configuration.
        /// </summary>
        /// <remarks>
        /// If DTLS is used for for encryption a <see cref="IMemoryCache"/> must be provided in the service provider.
        /// </remarks>
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
                        .SetCertificate(listenEndpoint.EndpointConfig.CertificateConfig)
                        .SetHandshakeTimeout(listenEndpoint.EndpointConfig.HandshakeTimeout);

                    if (listenEndpoint.EndpointConfig.ClientCA != null)
                    {
                        dtlsServerBuilder.SetCA(listenEndpoint.EndpointConfig.ClientCA);
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
