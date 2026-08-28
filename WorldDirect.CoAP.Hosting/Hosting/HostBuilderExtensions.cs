namespace WorldDirect.CoAP.Hosting.Hosting
{
    using System;
    using Microsoft.Extensions.Hosting;

    /// <summary>
    /// Extensions for the <see cref="IHostBuilder"/>.
    /// </summary>
    public static class HostBuilderExtensions
    {
        /// <summary>
        /// Configure the coap server on the host.
        /// </summary>
        /// <param name="hostBuilder">The host builder.</param>
        /// <param name="configure">A callback to configure the coap server.</param>
        /// <returns>The host builder.</returns>
        public static IHostBuilder ConfigureCoAPServer(this IHostBuilder hostBuilder, Action<HostBuilderContext, ICoAPServerBuilder> configure)
        {
            hostBuilder.ConfigureServices((ctx, services) =>
            {
                services.AddCoAPServer((builder) => configure(ctx, builder));
            });
            return hostBuilder;
        }
    }
}
