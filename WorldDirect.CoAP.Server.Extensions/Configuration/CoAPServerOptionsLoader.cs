namespace WorldDirect.CoAP.Server.Extensions.Configuration;

using System.Net;
using Microsoft.Extensions.Configuration;

public class CoAPServerOptionsLoader
{
    private readonly IConfiguration config;

    public CoAPServerOptionsLoader(IConfiguration config)
    {
        this.config = config;
    }

    public CoAPServerOptions Options => this.Build();

    private CoAPServerOptions Build()
    {
        var reader = new ConfigurationReader(this.config);
        var endpoints = reader.Endpoints;

        var listenOptions = new List<ListenOption>();

        foreach (var endpoint in endpoints)
        {
            var address = BindingAddress.Parse(endpoint.Url);
            if (address.Host == "localhost")
            {
                listenOptions.Add(new ListenOption(new IPEndPoint(IPAddress.Loopback, address.Port), endpoint));
            }
            else
            {
                listenOptions.Add(new ListenOption(new IPEndPoint(IPAddress.Any, address.Port), endpoint));
            }
        }

        return new CoAPServerOptions(listenOptions);
    }
}