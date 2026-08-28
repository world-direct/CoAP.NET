namespace WorldDirect.CoAPS.DTLS.Specs
{
    using CoAP.DTLS;
    using FluentAssertions;
    using Org.BouncyCastle.Tls.Crypto.Impl.BC;

    public class DTLS12KeyFileDataSpecs
    {
        [Fact]
        public void CanExtractSecret()
        {
            var secretData = new byte[] { 0x01, 0x02 };
            var secret = new BcTlsSecret(new BcTlsCrypto(), secretData);
            var clientRandom = new byte[] { 0x03, 0x04 };

            var keyData = DTLS12KeyFileData.FromSecret(clientRandom, secret);

            keyData.Should().NotBeNull();
            keyData.Value.PreMasterSecret.Should().BeEquivalentTo(secretData);
        }
    }
}
