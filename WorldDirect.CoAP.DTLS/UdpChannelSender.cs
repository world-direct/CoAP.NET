namespace WorldDirect.CoAP.DTLS;

using System.Net;
using Channel;

public class UdpChannelSender : IUDPSender
{
    private readonly UDPChannel channel;

    public UdpChannelSender(UDPChannel channel)
    {
        this.channel = channel;
    }
    public void SendTo(ReadOnlySpan<byte> payload, EndPoint remote)
    {
        this.channel.Send(payload.ToArray(), remote);
    }
}