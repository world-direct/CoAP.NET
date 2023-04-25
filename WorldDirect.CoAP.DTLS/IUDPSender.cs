namespace WorldDirect.CoAP.DTLS;

using System.Net;

/// <summary>
/// An interface to send UDP data.
/// </summary>
public interface IUDPSender
{
    /// <summary>
    /// Send a message to the remote.
    /// </summary>
    /// <param name="payload">The message to send.</param>
    /// <param name="remote">The remote.</param>
    void SendTo(ReadOnlySpan<byte> payload, EndPoint remote);
}
