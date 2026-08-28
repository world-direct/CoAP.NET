namespace WorldDirect.CoAP.Net;

using System.Security.Cryptography.X509Certificates;

public class DTLSClientAuthentication
{
    private DTLSClientAuthentication(X509Certificate? certificate, string? pskIdentity)
    {
        this.Certificate = certificate;
        this.PskIdentity = pskIdentity;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DTLSClientAuthentication"/> class.
    /// </summary>
    /// <param name="certificate">The certificate of the peer.</param>
    public DTLSClientAuthentication(X509Certificate certificate)
        : this(certificate, null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DTLSClientAuthentication"/> class.
    /// </summary>
    /// <param name="pskIdentity">The public identity of the peer.</param>
    public DTLSClientAuthentication(string pskIdentity)
        : this(null, pskIdentity)
    {
    }

    /// <summary>
    /// Gets the certificate of the client.
    /// </summary>
    public X509Certificate? Certificate { get; }

    /// <summary>
    /// Gets the public identity of the client to identify the psk.
    /// </summary>
    public string? PskIdentity { get; }
}