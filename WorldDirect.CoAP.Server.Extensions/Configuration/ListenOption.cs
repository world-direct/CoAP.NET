namespace WorldDirect.CoAP.Server.Extensions.Configuration;

using System.Net;

public class ListenOption
{

    public ListenOption(EndPoint endpoint, EndpointConfig endpointConfig)
    {
        this.Endpoint = endpoint;
        this.EndpointConfig = endpointConfig;
    }
    public EndPoint Endpoint { get; set; }
    public EndpointConfig EndpointConfig { get; set; }
}
