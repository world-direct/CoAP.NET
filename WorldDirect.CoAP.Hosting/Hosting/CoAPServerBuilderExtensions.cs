namespace WorldDirect.CoAP.Hosting.Hosting;

using System.Net;
using Configuration;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using WorldDirect.CoAP.DTLS;
using WorldDirect.CoAP.Net;
using WorldDirect.CoAP.Server.Resources;

/// <summary>
/// Extensions for the <see cref="ICoAPServerBuilder"/>.
/// </summary>
public static class CoAPServerBuilderExtensions
{
    /// <summary>
    /// Add a resource to the coap server.
    /// </summary>
    /// <typeparam name="T">The type of the resource.</typeparam>
    /// <param name="builder">The server builder.</param>
    /// <returns>The server builder.</returns>
    public static ICoAPServerBuilder AddResource<T>(this ICoAPServerBuilder builder) where T : class, IResource
    {
        builder.Services.TryAddSingleton<IResource, T>();
        return builder;
    }

    /// <summary>
    /// Adds a resource to the coap server.
    /// </summary>
    /// <typeparam name="T">The type of the resource.</typeparam>
    /// <param name="builder">The server builder.</param>
    /// <param name="factory">The factory to create the resource.</param>
    /// <returns>The server builder.</returns>
    public static ICoAPServerBuilder AddResource<T>(this ICoAPServerBuilder builder, Func<IServiceProvider, T> factory) where T : class, IResource
    {
        builder.Services.TryAddSingleton(typeof(IResource), factory);
        return builder;
    }

    /// <summary>
    /// Add an udp endpoint to the coap server.
    /// </summary>
    /// <param name="builder">The server builder.</param>
    /// <param name="name">The name of the new endpoint.</param>
    /// <param name="configuration">The configuration.</param>
    /// <returns>A new endpoint builder.</returns>
    public static ICoAPEndpointBuilder AddUdpEndpoint(this ICoAPServerBuilder builder, string name, IConfiguration configuration)
    {
        return builder.AddUdpEndpoint(name, configuration, null);
    }

    /// <summary>
    /// Add an udp endpoint to the coap server.
    /// </summary>
    /// <param name="builder">The server builder.</param>
    /// <param name="name">The name of the new endpoint.</param>
    /// <param name="configuration">The configuration.</param>
    /// <param name="configure">The callback to configure the <see cref="CoAPEndpointOptions"/>.</param>
    /// <returns>The new endpoint builder.</returns>
    public static ICoAPEndpointBuilder AddUdpEndpoint(this ICoAPServerBuilder builder, string name, IConfiguration configuration,
        Action<CoAPEndpointOptions>? configure)
    {
        builder.Services.Configure<CoAPEndpointOptions>(name, configuration);

        builder.Services.AddSingleton<IEndPoint>((sp) =>
        {
            var options = sp.GetRequiredService<IOptionsMonitor<CoAPEndpointOptions>>().Get(name);
            configure?.Invoke(options);
            var coapConfig = sp.GetRequiredService<ICoapConfig>();
            var address = (IPEndPoint)BindingAddress.Parse(options.Url);

            return new CoAPEndPoint(address, coapConfig);
        });

        return new CoAPEndpointBuilder(name, builder.Services);
    }

    /// <summary>
    /// Add a dtls endpoint to the coap server.
    /// </summary>
    /// <param name="builder">The server builder.</param>
    /// <param name="name">The name of the endpoint.</param>
    /// <param name="configuration">The configuration.</param>
    /// <param name="configure">The callback to configure the <see cref="CoAPSEndpointOptions"/>.</param>
    /// <returns>The coaps endpoint builder.</returns>
    public static ICoAPSEndpointBuilder AddDTLSEndpoint(this ICoAPServerBuilder builder, string name, IConfiguration configuration, Action<CoAPSEndpointOptions>? configure = null)
    {
        builder.Services.Configure<CoAPSEndpointOptions>(name, configuration);
        builder.Services.AddSingleton<IEndPoint>(sp =>
        {
            var cipherSuites = new HashSet<int>();
            var options = sp.GetRequiredService<IOptionsMonitor<CoAPSEndpointOptions>>().Get(name);
            configure?.Invoke(options);
            var pskManager = sp.GetServices<IEndpointSpecific<TlsPskIdentityManager>>().SingleOrDefault(manager => manager.Name == name)?.Entity;
            var cipherSuitesCallbacks = sp.GetServices<IEndpointSpecific<CipherSuiteConfigurationCallback>>().Where(callback => callback.Name == name);
            foreach (var cipherSuitesCallback in cipherSuitesCallbacks)
            {
                cipherSuitesCallback.Entity(cipherSuites);
            }

            var crypto = new BcTlsCrypto();
            var certificateLoader = new CertificateLoader(crypto);

            var address = (IPEndPoint)BindingAddress.Parse(options.Url);
            var preMasterStore = sp.GetServices<IEndpointSpecific<IKeyStore>>().SingleOrDefault(store => store.Name == name)?.Entity;
            var coapConfig = sp.GetRequiredService<ICoapConfig>();

            var dtlsConfig = new MutableDTLSServerConfig();
            dtlsConfig.Crypto = crypto;
            if (options.Certificate != null)
            {
                dtlsConfig.EcCertificate = certificateLoader.LoadCertificate(options.Certificate);
                foreach (var certificateConfig in options.ClientCA)
                {
                    dtlsConfig.CAs.Add(certificateLoader.LoadCA(certificateConfig));
                }
            }

            dtlsConfig.CipherSuites = cipherSuites.ToList();
            dtlsConfig.KeyStore = preMasterStore;
            dtlsConfig.PskManager = pskManager;
            dtlsConfig.HandshakeTimeout = options.HandshakeTimeout;
            var cache = sp.GetRequiredService<IMemoryCache>();

            return new CoAPSEndpoint(cache, new (dtlsConfig), address, coapConfig);
        });

        return new CoAPSEndpointBuilder(name, builder.Services);
    }
}
