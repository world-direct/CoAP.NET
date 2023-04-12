namespace WorldDirect.Dtls;

using System.Net;
using System.Security.Cryptography.X509Certificates;

public class ReceivedAuthenticatedPacketEventArgs
{
    public byte[] Payload { get; set; }
    public IPEndPoint Remote { get; set; }
    public string PublicIdentifier { get; set; }
}
