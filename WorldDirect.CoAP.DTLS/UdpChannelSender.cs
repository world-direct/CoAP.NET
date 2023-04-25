namespace WorldDirect.CoAP.DTLS;

using System.Net;
using Channel;

/// <summary>
/// Represents a udp sender using a CoAP UDP channel.
/// </summary>
public class UdpChannelSender : IUDPSender
{
    private readonly UDPChannel channel;

    /// <summary>
    /// Initializes a new instance of the <see cref="UdpChannelSender"/> class.
    /// </summary>
    /// <param name="channel">The channel to send the data.</param>
    public UdpChannelSender(UDPChannel channel)
    {
        this.channel = channel;
    }

    /// <inheritdoc />
    public void SendTo(ReadOnlySpan<byte> payload, EndPoint remote)
    {
        this.channel.Send(payload.ToArray(), remote);
    }
}
