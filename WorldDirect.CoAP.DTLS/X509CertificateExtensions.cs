// Copyright (c) World-Direct eBusiness solutions GmbH. All rights reserved.

namespace WorldDirect.CoAP.DTLS
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using System.Text.RegularExpressions;

    public static class X509CertificateExtensions
    {
        public static string GetCommonName(this X509Certificate cert)
        {
            var regex = new Regex("CN=([\\w-]*)");
            var subject = cert.Subject;
            var match = regex.Match(subject);
            if (match.Success)
            {
                return match.Groups[1].Value;
            }

            throw new ArgumentException($"Subject ({cert.Subject}) does not contain a valid common name");
        }
    }
}
