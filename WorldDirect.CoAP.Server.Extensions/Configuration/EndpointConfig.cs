namespace WorldDirect.CoAP.Server.Extensions.Configuration
{
    using System;

    /// <summary>
    /// The conf
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
            this.ClientCAs = new List<CertificateConfig>();
        }

        public string Name { get; set; }
        public string Url { get; set; }
        public CertificateConfig? CertificateConfig { get; set; }
        public List<CertificateConfig> ClientCAs { get; set; }
        public TimeSpan HandshakeTimeout { get; set; }
    }
}
