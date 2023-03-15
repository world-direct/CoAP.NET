namespace WorldDirect.Dtls;

using System.Security.Cryptography.X509Certificates;

public static class X509CertificateExtensions
{
    public static string GetCommonName(this X509Certificate cert)
    {
        var subject = cert.Subject;

        var cn = subject.Substring(3);
        return cn;
    }
}