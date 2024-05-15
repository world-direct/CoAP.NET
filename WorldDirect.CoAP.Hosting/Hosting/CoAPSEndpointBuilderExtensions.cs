namespace WorldDirect.CoAP.Hosting.Hosting;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Org.BouncyCastle.Tls;
using WorldDirect.CoAP.DTLS;

/// <summary>
/// Extensions for the <see cref="ICoAPSEndpointBuilder"/>.
/// </summary>
public static class CoAPSEndpointBuilderExtensions
{
    /// <summary>
    /// Add pre shared key authentication for this endpoint.
    /// </summary>
    /// <param name="builder">The builder of the endpoint.</param>
    /// <param name="factory">The factory to create the <see cref="TlsPskIdentityManager"/>.</param>
    /// <returns>The endpoint builder.</returns>
    public static ICoAPSEndpointBuilder AddPreSharedKeys(this ICoAPSEndpointBuilder builder, Func<IServiceProvider, TlsPskIdentityManager> factory)
    {
        builder.Services.TryAddTransient<IEndpointSpecific<TlsPskIdentityManager>>(sp => new EndpointSpecific<TlsPskIdentityManager>(builder.Name, factory(sp)));
        return builder;
    }

    /// <summary>
    /// Adds the exporter of PreMasterSecrets to the endpoint.
    /// </summary>
    /// <remarks>
    /// PreMasterSecrets can be used to decipher the messages of the dtls session.
    /// </remarks>
    /// <param name="builder">The builder of the endpoint.</param>
    /// <param name="factory">The factory of the <see cref="IKeyStore"/> to store secrets.</param>
    /// <returns>The endpoint builder.</returns>
    public static ICoAPSEndpointBuilder AddPreMasterSecretExporter(this ICoAPSEndpointBuilder builder, Func<IServiceProvider, IKeyStore> factory)
    {
        builder.Services.TryAddSingleton<IEndpointSpecific<IKeyStore>>(sp => new EndpointSpecific<IKeyStore>(builder.Name, factory(sp)));
        return builder;
    }

    /// <summary>
    /// Add enabled cipher suites to the endpoint.
    /// </summary>
    /// <param name="builder">The builder of the endpoint.</param>
    /// <param name="callback">The callback which will add cipher suites.</param>
    /// <returns>The endpoint builder.</returns>
    public static ICoAPSEndpointBuilder AddCipherSuites(this ICoAPSEndpointBuilder builder, CipherSuiteConfigurationCallback callback)
    {
        builder.Services.AddTransient<IEndpointSpecific<CipherSuiteConfigurationCallback>>((_) => new EndpointSpecific<CipherSuiteConfigurationCallback>(builder.Name, callback));
        return builder;
    }
}
