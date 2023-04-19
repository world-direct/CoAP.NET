namespace WorldDirect.CoAP.Server.Extensions.Configuration
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Net;
    using Microsoft.Extensions.Configuration;

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

    public class CoAPServerOptions
    {

        internal CoAPServerOptions(IEnumerable<ListenOption> listenOptions)
        {
            this.ListenOptions = listenOptions;
        }

        public IEnumerable<ListenOption> ListenOptions { get; }

    }

    /// <summary>
    /// An address a CoAP server may bind to.
    /// </summary>
    public class BindingAddress
    {

        private BindingAddress(string scheme, string host, int port)
        {
            this.Scheme = scheme;
            this.Host = host;
            this.Port = port;
        }

        public string Scheme { get; }
        public string Host { get; set; }
        public int Port { get; set; }

        public static BindingAddress Parse(string address)
        {
            // A null/empty address will throw FormatException
            address = address ?? string.Empty;

            var schemeDelimiterStart = address.IndexOf(Uri.SchemeDelimiter, StringComparison.Ordinal);
            if (schemeDelimiterStart < 0)
            {
                throw new FormatException($"Invalid url: '{address}'");
            }
            var schemeDelimiterEnd = schemeDelimiterStart + Uri.SchemeDelimiter.Length;

            var pathDelimiterStart = address.IndexOf("/", schemeDelimiterEnd, StringComparison.Ordinal);
            var pathDelimiterEnd = pathDelimiterStart;

            if (pathDelimiterStart < 0)
            {
                pathDelimiterStart = pathDelimiterEnd = address.Length;
            }

            var scheme = address.Substring(0, schemeDelimiterStart);
            string? host = null;
            var port = 0;

            var hasSpecifiedPort = false;

            var portDelimiterStart = address.LastIndexOf(":", pathDelimiterStart - 1, pathDelimiterStart - schemeDelimiterEnd, StringComparison.Ordinal);
            if (portDelimiterStart >= 0)
            {
                var portDelimiterEnd = portDelimiterStart + ":".Length;

                var portString = address.Substring(portDelimiterEnd, pathDelimiterStart - portDelimiterEnd);
                int portNumber;
                if (int.TryParse(portString, NumberStyles.Integer, CultureInfo.InvariantCulture, out portNumber))
                {
                    hasSpecifiedPort = true;
                    host = address.Substring(schemeDelimiterEnd, portDelimiterStart - schemeDelimiterEnd);
                    port = portNumber;
                }
            }

            if (!hasSpecifiedPort)
            {
                if (string.Equals(scheme, "coap", StringComparison.OrdinalIgnoreCase))
                {
                    port = 5683;
                }
                else if (string.Equals(scheme, "coaps", StringComparison.OrdinalIgnoreCase))
                {
                    port = 5684;
                }
            }

            if (!hasSpecifiedPort)
            {
                host = address.Substring(schemeDelimiterEnd, pathDelimiterStart - schemeDelimiterEnd);
            }

            if (string.IsNullOrEmpty(host))
            {
                throw new FormatException($"Invalid url: '{address}'");
            }

            return new BindingAddress(host: host, port: port, scheme: scheme);
        }
    }

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
}
