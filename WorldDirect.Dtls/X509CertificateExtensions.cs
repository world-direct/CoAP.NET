namespace WorldDirect.Dtls;

using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Extensions for the <see cref="X509Certificate"/> class.
/// </summary>
public static class X509CertificateExtensions
{
    /// <summary>
    /// Parse the common name from the certificate subject.
    /// </summary>
    /// <param name="cert">The certificate to load the common name from.</param>
    /// <returns>The common name.</returns>
    public static string GetCommonName(this X509Certificate cert)
    {
        var subject = cert.Subject;

        var cn = subject.Substring(3);
        return cn;
    }
}
