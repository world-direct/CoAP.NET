namespace WorldDirect.CoAP.Server.Extensions.Specs.Configuration
{
    using System.Collections.Generic;
    using FluentAssertions;
    using Microsoft.Extensions.Configuration;
    using WorldDirect.CoAP.Server.Extensions.Configuration;
    using Xunit;

    public class CertificationConfigSpecs
    {
        private readonly string pathConfigValue = "path123";
        private readonly string keyPathConfigValue = "keyPath123";
        private readonly string passwordConfigValue = "password123";
        private readonly string subjectConfigValue = "subject123";
        private readonly string storeConfigValue = "store123";
        private readonly string locationConfigValue = "location123";
        private readonly IConfiguration exampleConfiguration;

        private CertificateConfig certificateConfig;

        public CertificationConfigSpecs()
        {
            var exampleDict = new Dictionary<string, string>()
            {
                { "Path", pathConfigValue },
                { "KeyPath", keyPathConfigValue },
                { "Password", passwordConfigValue},
                { "Subject", subjectConfigValue },
                { "Store", storeConfigValue },
                { "Location", locationConfigValue},
                { "AllowInvalid", "true" }
            };
            this.exampleConfiguration = new ConfigurationBuilder()
                .AddInMemoryCollection(exampleDict)
                .Build();

            this.certificateConfig = new CertificateConfig(this.exampleConfiguration);
        }

        [Fact]
        public void AssignConfigurationCorrectly()
        {
            this.certificateConfig.Configuration.Should().Be(this.exampleConfiguration);
        }

        [Fact]
        public void ExtractsPathCorrectly()
        {
            this.certificateConfig.Path.Should().Be(this.pathConfigValue);
        }

        [Fact]
        public void ExtractsKeyPathCorrectly()
        {
            this.certificateConfig.KeyPath.Should().Be(this.keyPathConfigValue);
        }

        [Fact]
        public void ExtractsPasswordCorrectly()
        {
            this.certificateConfig.Password.Should().Be(this.passwordConfigValue);
        }

        [Fact]
        public void ExtractsSubjectCorrectly()
        {
            this.certificateConfig.Subject.Should().Be(this.subjectConfigValue);
        }

        [Fact]
        public void ExtractsStoreCorrectly()
        {
            this.certificateConfig.Store.Should().Be(this.storeConfigValue);
        }

        [Fact]
        public void ExtractsLocationCorrectly()
        {
            this.certificateConfig.Location.Should().Be(this.locationConfigValue);
        }

        [Fact]
        public void ExtractsAllowInvalidCorrectly()
        {
            this.certificateConfig.AllowInvalid.Should().BeTrue();
        }

        [Fact]
        public void CertificateIsFileWhenPathIsSet()
        {
            var exampleDict = new Dictionary<string, string>()
            {
                { "Path", pathConfigValue },
            };
            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(exampleDict)
                .Build();

            this.certificateConfig = new CertificateConfig(config);

            this.certificateConfig.IsFile.Should().BeTrue();
        }

        [Fact]
        public void CertificateIsNotFileWhenPathIsNotSet()
        {
            var exampleDict = new Dictionary<string, string>();
            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(exampleDict)
                .Build();

            this.certificateConfig = new CertificateConfig(config);

            this.certificateConfig.IsFile.Should().BeFalse();
        }

        [Fact]
        public void CertificateIsFromStoreWhenSubjectIsSet()
        {
            var exampleDict = new Dictionary<string, string>()
            {
                { "Subject", subjectConfigValue },
            };
            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(exampleDict)
                .Build();

            this.certificateConfig = new CertificateConfig(config);

            this.certificateConfig.IsFromStore.Should().BeTrue();
        }

        [Fact]
        public void LocationDefaultsToCurrentUser()
        {
            var exampleDict = new Dictionary<string, string>();
            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(exampleDict)
                .Build();

            this.certificateConfig = new CertificateConfig(config);

            this.certificateConfig.Location.Should().Be("CurrentUser");
        }

        [Fact]
        public void AllowInvalidIsFalsePerDefault()
        {
            var exampleDict = new Dictionary<string, string>()
            {
            };
            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(exampleDict)
                .Build();

            this.certificateConfig = new CertificateConfig(config);

            this.certificateConfig.AllowInvalid.Should().BeFalse();
        }

        [Fact]
        public void CertificateIsFromStoreWhenSubjectIsNotSet()
        {
            var exampleDict = new Dictionary<string, string>();
            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(exampleDict)
                .Build();

            this.certificateConfig = new CertificateConfig(config);

            this.certificateConfig.IsFromStore.Should().BeFalse();
        }
    }
}
