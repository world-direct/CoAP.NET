namespace WorldDirect.CoAP.Server.Extensions;

using System.Security.Cryptography.X509Certificates;

public static class CryptographyExtensions
{
    public static Org.BouncyCastle.X509.X509Certificate ToBouncyCastle(this X509Certificate2 cert)
    {
        return new Org.BouncyCastle.X509.X509Certificate(cert.Export(X509ContentType.Cert));
    }
}