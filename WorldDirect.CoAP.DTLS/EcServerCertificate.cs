namespace WorldDirect.CoAP.DTLS;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Tls;

public class EcServerCertificate
{
    public EcServerCertificate(Certificate certificate, ECPrivateKeyParameters privateKey)
    {
        this.Certificate = certificate;
        this.PrivateKey = privateKey;
    }

    public Certificate Certificate { get; }

    public ECPrivateKeyParameters PrivateKey { get; }
}