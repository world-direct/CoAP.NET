namespace WorldDirect.Dtls;

using System.Net;

public class ReceivedPacketEventArgs : EventArgs
{
    public IPEndPoint Remote { get; set; }
    public byte[] Payload { get; set; }
}