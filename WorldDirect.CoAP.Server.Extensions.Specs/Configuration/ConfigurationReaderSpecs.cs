namespace WorldDirect.CoAP.Server.Extensions.Specs.Configuration
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using FluentAssertions;
    using Microsoft.Extensions.Configuration;
    using WorldDirect.CoAP.Server.Extensions.Configuration;
    using Xunit;

    public class ConfigurationReaderSpecs
    {
        private readonly Dictionary<string, string> exampleDict;
        private readonly string exampleUrl = "coaps://localhost:5684";
        private readonly string examplePath = "example.pfx";
        private readonly string exampleName = "CoAPSWithCertAuth";
        private readonly TimeSpan exampleTimeout = TimeSpan.FromSeconds(20);
        private readonly string exampleBaseKey;
        private IConfiguration config;
        private ConfigurationReader reader;
        public ConfigurationReaderSpecs()
        {
            this.exampleBaseKey = $"Endpoints:{this.exampleName}";
            this.exampleDict = new Dictionary<string, string>()
            {
                { $"{exampleBaseKey}:Url", this.exampleUrl},
                { $"{exampleBaseKey}:Certificate:Path", this.examplePath},
                { $"{exampleBaseKey}:ClientCA:0:Path", this.examplePath},
                { $"{exampleBaseKey}:ClientCA:1:Path", this.examplePath},
                { $"{exampleBaseKey}:HandshakeTimeout", this.exampleTimeout.ToString()},

            };
            this.config = new ConfigurationBuilder()
                .AddInMemoryCollection(exampleDict)
                .Build();
            this.reader = new ConfigurationReader(this.config);
        }

        [Fact]
        public void ReadsOneEndpoint()
        {
            var endpoints = this.reader.Endpoints;
            endpoints.Should().HaveCount(1);
        }

        [Fact]
        public void ReadsNameCorrectly()
        {
            var endpoints = this.reader.Endpoints;
            var endpoint = endpoints.Single();
            endpoint.Name.Should().Be(this.exampleName);
        }

        [Fact]
        public void ReadsUrlCorrectly()
        {
            var endpoints = this.reader.Endpoints;
            var endpoint = endpoints.Single();
            endpoint.Url.Should().Be(this.exampleUrl);
        }

        [Fact]
        public void ReadsTwoClientCAs()
        {
            var endpoints = this.reader.Endpoints;
            var endpoint = endpoints.Single();
            endpoint.ClientCAs.Should().HaveCount(2);
        }

        [Fact]
        public void ReadsCertificateConfig()
        {
            var endpoints = this.reader.Endpoints;
            var endpoint = endpoints.Single();
            endpoint.CertificateConfig.Should().NotBeNull();
        }

        [Fact]
        public void ReadsHandshakeTimeoutCorrectly()
        {
            var endpoints = this.reader.Endpoints;
            var endpoint = endpoints.Single();
            endpoint.HandshakeTimeout.Should().Be(exampleTimeout);
        }
    }
}
