namespace WorldDirect.CoAP.DTLS;

using System.Net;
using System.Security.Cryptography.X509Certificates;
using Channel;
using Net;

public class DTLSDataReceivedEventArgs : DataReceivedEventArgs
{
    private DTLSDataReceivedEventArgs(byte[] data, EndPoint endPoint, X509Certificate? certificate, string? pskIdentity)
        : base(data, endPoint)
    {
        if (certificate != null)
        {
            this.ClientAuthentication = new DTLSClientAuthentication(certificate);
        }
        else if (pskIdentity != null)
        {
            this.ClientAuthentication = new DTLSClientAuthentication(pskIdentity);
        }
        else
        {
            throw new ArgumentException("Unauthenticated communication is not allowed");
        }
    }

    /// <summary>
    /// Initialize a new instance of the <see cref="DTLSDataReceivedEventArgs"/> class with the clients certificate.
    /// </summary>
    /// <param name="data">The received payload.</param>
    /// <param name="endPoint">The endpoint of the peer.</param>
    /// <param name="certificate">The certificate of the peer.</param>
    public DTLSDataReceivedEventArgs(byte[] data, EndPoint endPoint, X509Certificate certificate)
        : this(data, endPoint, certificate, null)
    {
    }

    /// <summary>
    /// Initialize a new instance of the <see cref="DTLSDataReceivedEventArgs"/> class with the clients certificate.
    /// </summary>
    /// <param name="data">The received payload.</param>
    /// <param name="endPoint">The endpoint of the peer.</param>
    /// <param name="pskIdentity">The public identity of the peer.</param>
    public DTLSDataReceivedEventArgs(byte[] data, EndPoint endPoint, string pskIdentity)
        : this(data, endPoint, null, pskIdentity)
    {
    }

    public DTLSClientAuthentication ClientAuthentication { get; }
}