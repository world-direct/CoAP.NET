namespace WorldDirect.CoAP.DTLS;

public class DTLSServerConfig
{
    public List<EcServerCertificate> EcCertificates { get; set; } = new();

    public List<Org.BouncyCastle.X509.X509Certificate> CAs { get; set; } = new ();

    public List<int> CipherSuites { get; set; } = new();
}