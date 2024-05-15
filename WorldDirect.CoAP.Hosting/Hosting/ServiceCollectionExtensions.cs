namespace WorldDirect.CoAP.Hosting.Hosting;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Server;
using Services;
using WorldDirect.CoAP.Log;
using WorldDirect.CoAP.Net;
using WorldDirect.CoAP.Server.Resources;

/// <summary>
/// Extensions for the <see cref="IServiceCollection"/>.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Add the coap server.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">A callback to configure the coap server.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddCoAPServer(this IServiceCollection services, Action<ICoAPServerBuilder>? configure = null)
    {
        services.TryAddSingleton<ICoapConfig>(sp =>
        {
            var options = ServiceProviderServiceExtensions.GetService<IOptions<CoAPOptions>>(sp);
            var cfg = (CoapConfig)CoapConfig.Default;
            if (options != null && options.Value.MaxMessageSize.HasValue)
            {
                cfg.MaxMessageSize = options.Value.MaxMessageSize.Value;
            }

            if (options != null && options.Value.DefaultBlockSize.HasValue)
            {
                cfg.DefaultBlockSize = options.Value.DefaultBlockSize.Value;
            }

            return cfg;
        });
        services.TryAddSingleton((sp) =>
        {
            // initialize logging for coap stack initially
            LogManager.Provider = sp;
            var config = sp.GetRequiredService<ICoapConfig>();
            return new CoapServer(config);
        });
        services.AddHostedService(sp =>
        {
            var server = sp.GetRequiredService<CoapServer>();
            var endpoints = sp.GetServices<IEndPoint>();
            var resources = sp.GetServices<IResource>();
            var lifetime = sp.GetRequiredService<IHostApplicationLifetime>();
            var logger = sp.GetRequiredService<ILogger<CoAPServerService>>();
            return new CoAPServerService(server, endpoints, resources, sp, lifetime, logger);
        });

        configure?.Invoke(new CoAPServerBuilder(services));
        return services;
    }
}
