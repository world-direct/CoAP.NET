namespace WorldDirect.CoAP.DTLS;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Tls;

/// <summary>
/// Represents a elliptic curve certificate with its private key.
/// </summary>
public class EcServerCertificate
{
    /// <summary>
    /// Initializes a new instance of the <see cref="EcServerCertificate"/> class.
    /// </summary>
    /// <param name="certificate">The server certificate.</param>
    /// <param name="privateKey">The corresponding private key.</param>
    public EcServerCertificate(Certificate certificate, ECPrivateKeyParameters privateKey)
    {
        this.Certificate = certificate;
        this.PrivateKey = privateKey;
    }

    /// <summary>
    /// Gets the certificate.
    /// </summary>
    public Certificate Certificate { get; }

    /// <summary>
    /// Gets the private key.
    /// </summary>
    public ECPrivateKeyParameters PrivateKey { get; }
}
