namespace WorldDirect.CoAP.Server.Extensions.Configuration;

using Microsoft.Extensions.Configuration;

/// <summary>
/// 
/// </summary>
/// <remarks>
/// Based on Kestrel:
/// https://github.com/dotnet/aspnetcore/blob/68ae6b0d8aa2f4a0ff189d5cedc741e32cc643d2/src/Servers/Kestrel/Core/src/Internal/ConfigurationReader.cs#L67
/// </remarks>
public class ConfigurationReader
{
    private const string EndpointsKey = "Endpoints";
    private const string UrlKey = "Url";
    private const string CertificateKey = "Certificate";
    private const string ClientCAKey = "ClientCA";
    private const string HandshakeTimeoutKey = "HandshakeTimeout";
    private readonly IConfiguration config;

    public ConfigurationReader(IConfiguration config)
    {
        this.config = config;
    }

    public IEnumerable<EndpointConfig> Endpoints => this.ReadEndpoints();

    private IEnumerable<EndpointConfig> ReadEndpoints()
    {
        var endpoints = new List<EndpointConfig>();
        var endpointConfig = this.config.GetSection(EndpointsKey);
        var endpointsConfigurations = endpointConfig.GetChildren();
        foreach (var endpointCfg in endpointsConfigurations)
        {
            var url = endpointCfg[UrlKey];
            if (string.IsNullOrEmpty(url))
            {
                throw new InvalidOperationException($"Url of endpoint {endpointCfg.Key} must be defined.");
            }

                
            CertificateConfig? certificateConfig = null;
            if (endpointCfg.GetSection(CertificateKey).GetChildren().Any())
            {
                certificateConfig = new CertificateConfig(endpointCfg.GetSection(CertificateKey));
            }
            CertificateConfig? clientCAConfig = null;
            if (endpointCfg.GetSection(ClientCAKey).GetChildren().Any())
            {
                clientCAConfig = new CertificateConfig(endpointCfg.GetSection(ClientCAKey));
            }
            var endpoint = new EndpointConfig(endpointCfg.Key, url)
            {
                CertificateConfig = certificateConfig,
                ClientCA = clientCAConfig,
                HandshakeTimeout = endpointCfg.GetSection(HandshakeTimeoutKey).Get<TimeSpan>(),
            };

            endpoints.Add(endpoint);
        }

        return endpoints;
    }
}