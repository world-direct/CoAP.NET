namespace WorldDirect.CoAP.DTLS;

using System.Net;

public interface IUDPSender
{
    void SendTo(ReadOnlySpan<byte> payload, EndPoint remote);
}