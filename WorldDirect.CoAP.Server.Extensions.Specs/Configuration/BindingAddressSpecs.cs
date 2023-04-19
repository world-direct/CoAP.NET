namespace WorldDirect.CoAP.Server.Extensions.Specs.Configuration
{
    using FluentAssertions;
    using WorldDirect.CoAP.Server.Extensions.Configuration;
    using Xunit;

    public class BindingAddressSpecs
    {


        private readonly int validPort = 5684;
        private readonly string coapScheme = "coap";
        private readonly string coapsScheme = "coaps";
        private readonly string validBindingAddress;
        public BindingAddressSpecs()
        {
            this.validBindingAddress = $"{coapScheme}://*:{validPort}/";
        }

        [Fact]
        public void RecognizesSchemeCorrectly()
        {
            var bindingAddress = BindingAddress.Parse(this.validBindingAddress);
            bindingAddress.Scheme.Should().Be(this.coapScheme);
        }

        [Fact]
        public void RecognizesPortCorrectly()
        {
            var bindingAddress = BindingAddress.Parse(this.validBindingAddress);
            bindingAddress.Port.Should().Be(this.validPort);
        }

        [Fact]
        public void RecognizesHostCorrectly()
        {
            var bindingAddress = BindingAddress.Parse(this.validBindingAddress);
            bindingAddress.Host.Should().Be("*");
        }

        [Fact]
        public void RecognizesLocalhostCorrectly()
        {
            var address = "coap://localhost:1234/";
            var bindingAddress = BindingAddress.Parse(address);
            bindingAddress.Host.Should().Be("localhost");
        }

        [Fact]
        public void RecognizesCoAPPortCorrectly()
        {
            var address = "coap://localhost";
            var bindingAddress = BindingAddress.Parse(address);
            bindingAddress.Port.Should().Be(5683);
        }

        [Fact]
        public void RecognizesCoAPSPortCorrectly()
        {
            var address = "coaps://localhost";
            var bindingAddress = BindingAddress.Parse(address);
            bindingAddress.Port.Should().Be(5684);
        }
    }
}
