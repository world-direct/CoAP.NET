namespace WorldDirect.CoAP.Server.Extensions.Configuration
{
    using System;
    using System.Collections.Generic;
    using Microsoft.Extensions.Configuration;

    /*
     *  "CoAP": {
     *      "Endpoints": {
     *          "CoAPSWithCertAuth": {
     *              "Url": "coaps://*:5684",
     *              "ClientAuthenticationMode": "Certificate",
     *              "Certificate": {
     *                  ...
     *              }
     *          }
     *      }
     *  }
     *
     */

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
        private const string HandshakeTimeout = "HandshakeTimeout";
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

                var caSections = endpointCfg.GetSection(ClientCAKey).GetChildren();
                var cas = caSections.Select(section => new CertificateConfig(section)).ToArray();
                CertificateConfig? certificateConfig = null;
                if (endpointCfg.GetSection(CertificateKey).GetChildren().Any())
                {
                    certificateConfig = new CertificateConfig(endpointCfg.GetSection(CertificateKey));
                }
                var endpoint = new EndpointConfig(endpointCfg.Key, url)
                {
                    CertificateConfig = certificateConfig,
                    ClientCA = cas,
                    HandshakeTimeout = endpointCfg.GetSection(HandshakeTimeout).Get<TimeSpan>(),
                };

                endpoints.Add(endpoint);
            }

            return endpoints;
        }

        private ClientAuthenticationMode ReadClientAuthenticationMode(string? value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return ClientAuthenticationMode.NoAuthentication;
            }

            if(Enum.TryParse<ClientAuthenticationMode>(value,true, out var mode))
            {
                return mode;
            }

            throw new InvalidOperationException($"Unknown ClientAuthenticationMode was selected {value}");
        }
    }

    public enum ClientAuthenticationMode
    {
        NoAuthentication,
        Certificate,
        PSK,
        CertificateOrPSK,
    }

    /// <summary>
    ///
    /// </summary>
    /// <remarks>
    /// Based on Kestrel:
    /// https://github.com/dotnet/aspnetcore/blob/68ae6b0d8aa2f4a0ff189d5cedc741e32cc643d2/src/Servers/Kestrel/Core/src/Internal/ConfigurationReader.cs#L267
    /// </remarks>
    public class EndpointConfig
    {

        public EndpointConfig(string name, string url)
        {
            this.Name = name;
            this.Url = url;
        }

        public string Name { get; set; }
        public string Url { get; set; }
        public CertificateConfig? CertificateConfig { get; set; }
        public CertificateConfig[]? ClientCA { get; set; }
        public TimeSpan HandshakeTimeout { get; set; }
    }
}
