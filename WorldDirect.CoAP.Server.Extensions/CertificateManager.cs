namespace WorldDirect.CoAP.Server.Extensions;

using System.Security.Cryptography.X509Certificates;

internal class CertificateManager
{
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

    public static X509Certificate2 LoadFromStore(string subject, StoreName storeName, StoreLocation storeLocation, bool allowInvalid)
    {
        using (var store = new X509Store(storeName, storeLocation))
        {
            X509Certificate2Collection? storeCertificates = null;
            X509Certificate2? foundCertificate = null;
            store.Open(OpenFlags.ReadOnly);
            storeCertificates = store.Certificates;
            foreach (var certificate in storeCertificates.Find(X509FindType.FindBySubjectName, subject, !allowInvalid)
                         .OfType<X509Certificate2>()
                         .Where(IsCertificateAllowedForServerAuth)
                         .Where(cert => cert.HasPrivateKey)
                         .OrderByDescending(certificate => certificate.NotAfter))
            {
                // Pick the first one if there's no exact match as a fallback to substring default.
                foundCertificate ??= certificate;

                if (certificate.GetNameInfo(X509NameType.SimpleName, true).Equals(subject, StringComparison.InvariantCultureIgnoreCase))
                {
                    foundCertificate = certificate;
                    break;
                }
            }

            if (foundCertificate == null)
            {
                throw new InvalidOperationException($"Found no certificate with name {subject}");
            }

            return foundCertificate;
        }
    }


    public static X509Certificate2 LoadFromStore(string name, string location, string subject, bool allowInvalid)
    {

        var storeName = Enum.Parse<StoreName>(name);
        var storeLocation = Enum.Parse<StoreLocation>(location);

        return LoadFromStore(subject, storeName, storeLocation, allowInvalid);
    }

    public static X509Certificate2 LoadCAFromStore(string subject, StoreName storeName, StoreLocation storeLocation, bool allowInvalid)
    {
        using (var store = new X509Store(storeName, storeLocation))
        {
            X509Certificate2Collection? storeCertificates = null;
            X509Certificate2? foundCertificate = null;
            store.Open(OpenFlags.ReadOnly);
            storeCertificates = store.Certificates;
            foreach (var certificate in storeCertificates.Find(X509FindType.FindBySubjectName, subject, !allowInvalid)
                         .OfType<X509Certificate2>()
                         .Where(IsCertificateAllowedForCA)
                         .OrderByDescending(certificate => certificate.NotAfter))
            {
                // Pick the first one if there's no exact match as a fallback to substring default.
                foundCertificate ??= certificate;

                if (certificate.GetNameInfo(X509NameType.SimpleName, true).Equals(subject, StringComparison.InvariantCultureIgnoreCase))
                {
                    foundCertificate = certificate;
                    break;
                }
            }

            if (foundCertificate == null)
            {
                throw new InvalidOperationException($"Found no certificate with name {subject}");
            }

            return foundCertificate;
        }
    }

    public static X509Certificate2 LoadCAFromStore(string name, string location, string subject, bool allowInvalid)
    {

        var storeName = Enum.Parse<StoreName>(name);
        var storeLocation = Enum.Parse<StoreLocation>(location);

        return LoadCAFromStore(subject, storeName, storeLocation, allowInvalid);
    }

    private static bool IsCertificateAllowedForCA(X509Certificate2 certificate)
    {

        var keyUsageExtension = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (keyUsageExtension != null)
        {
            if ((keyUsageExtension.KeyUsages & X509KeyUsageFlags.KeyCertSign) == X509KeyUsageFlags.None)
            {
                return false;
            }
        }

        var basicConstraintExtension = certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
        if (basicConstraintExtension != null)
        {
            if (!basicConstraintExtension.CertificateAuthority)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsCertificateAllowedForServerAuth(X509Certificate2 certificate)
    {
        /* If the Extended Key Usage extension is included, then we check that the serverAuth usage is included. (http://oid-info.com/get/1.3.6.1.5.5.7.3.1)
             * If the Extended Key Usage extension is not included, then we assume the certificate is allowed for all usages.
             *
             * See also https://blogs.msdn.microsoft.com/kaushal/2012/02/17/client-certificates-vs-server-certificates/
             *
             * From https://tools.ietf.org/html/rfc3280#section-4.2.1.13 "Certificate Extensions: Extended Key Usage"
             *
             * If the (Extended Key Usage) extension is present, then the certificate MUST only be used
             * for one of the purposes indicated.  If multiple purposes are
             * indicated the application need not recognize all purposes indicated,
             * as long as the intended purpose is present.  Certificate using
             * applications MAY require that a particular purpose be indicated in
             * order for the certificate to be acceptable to that application.
             */

        var hasEkuExtension = false;

        foreach (var extension in certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>())
        {
            hasEkuExtension = true;
            foreach (var oid in extension.EnhancedKeyUsages)
            {
                if (string.Equals(oid.Value, ServerAuthenticationOid, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return !hasEkuExtension;
    }
}