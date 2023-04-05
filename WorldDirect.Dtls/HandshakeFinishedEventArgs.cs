namespace WorldDirect.Dtls;

using System.Security.Cryptography.X509Certificates;

public class HandshakeFinishedEventArgs : EventArgs
{
    public bool Result { get; set; }
    public X509Certificate? Certificate { get; set; }
    public string PublicIdentifier { get; set; }
}