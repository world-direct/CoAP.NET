namespace WorldDirect.Dtls;

using System.Net;

/// <summary>
/// Represents a helper class for sending data with the wolfssl library.
/// </summary>
internal class SendDTLSDataContext
{
    private Action<byte[], IPEndPoint> sendCallback;

    /// <summary>
    /// Initializes a new instance of the <see cref="SendDTLSDataContext"/> class.
    /// </summary>
    /// <param name="callback">The callback to call when no data should be sent.</param>
    public SendDTLSDataContext(Action<byte[], IPEndPoint> callback)
    {
        this.sendCallback = callback;
    }

    /// <summary>
    /// Invokes the callback with the specified parameter.
    /// </summary>
    /// <param name="data">The data to send on the UDP socket.</param>
    /// <param name="endpoint">The remote endpoint to send data to.</param>
    public void SendData(byte[] data, IPEndPoint endpoint)
    {
        this.sendCallback(data, endpoint);
    }
}
