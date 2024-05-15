namespace WorldDirect.CoAP.Hosting;

using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Extensions methods for bouncy castle.
/// </summary>
public static class CryptographyExtensions
{
    /// <summary>
    /// Convert a dotnet certificate into a bouncy castle certificate.
    /// </summary>
    /// <param name="cert">The certificate to convert.</param>
    /// <returns>The corresponding bouncy castle certificate.</returns>
    public static Org.BouncyCastle.X509.X509Certificate ToBouncyCastle(this X509Certificate2 cert)
    {
        return new Org.BouncyCastle.X509.X509Certificate(cert.Export(X509ContentType.Cert));
    }
}
