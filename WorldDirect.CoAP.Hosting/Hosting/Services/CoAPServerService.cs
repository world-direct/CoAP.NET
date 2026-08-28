namespace WorldDirect.CoAP.Hosting.Hosting.Services;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WorldDirect.CoAP.Log;
using WorldDirect.CoAP.Net;
using WorldDirect.CoAP.Server;
using WorldDirect.CoAP.Server.Resources;

/// <summary>
/// The service whose purpose is to run the coap server.
/// </summary>
internal class CoAPServerService : VitalBackgroundService
{
    private readonly ILogger<CoAPServerService> logger;
    private readonly CoapServer server;

    /// <summary>
    /// Initializes a new instance of the <see cref="CoAPServerService"/> class.
    /// </summary>
    /// <param name="server">The server that will be run.</param>
    /// <param name="endpoints">The endpoints the server is available on.</param>
    /// <param name="resources">The resources of the server.</param>
    /// <param name="serviceProvider">The service provider to create services.</param>
    /// <param name="lifetime">The lifetime.</param>
    /// <param name="logger">The logger.</param>
    public CoAPServerService(CoapServer server, IEnumerable<IEndPoint> endpoints, IEnumerable<IResource> resources, IServiceProvider serviceProvider, IHostApplicationLifetime lifetime, ILogger<CoAPServerService> logger) : base(lifetime, logger)
    {
        // initialize logger for coap stack
        LogManager.Provider = serviceProvider;
        this.logger = logger;
        this.server = server;
        foreach (var endpoint in endpoints)
        {
            this.server.AddEndPoint(endpoint);
        }

        this.server.Add(resources.ToArray());
    }

    /// <inheritdoc />
    protected override Task ExecuteAsync(CancellationToken ct)
    {
        ct.Register(() => server.Stop());
        server.Start();

        logger.LogInformation("CoAP Server started on {@LocalEndpoints}", server.EndPoints.Select(e => e.LocalEndPoint.ToString()));

        return Task.CompletedTask;
    }
}
