namespace WorldDirect.CoAP.DTLS;

using System.Collections.Concurrent;
using System.Net;
using Org.BouncyCastle.Tls;

/// <summary>
/// Represents the udp package buffer of a DTLS connection.
/// </summary>
internal class UdpTransport : DatagramTransport, IDisposable
{
    private bool disposed = false;
    private readonly IUDPSender sender;
    private readonly int maxPacketLength;
    private readonly BlockingCollection<byte[]> messages = new ();
    private readonly TimeSpan timeout;
    private DateTimeOffset lastReceivedDatagram;

    /// <summary>
    /// Initialize a new instance of the <see cref="UdpTransport"/> class.
    /// </summary>
    /// <param name="sender">The implementation of the udp </param>
    /// <param name="remote">The endpoint of the connection.</param>
    /// <param name="maxPacketLength">The maximum length of a dtls package.</param>
    /// <param name="timeout">The duration when the session is not valid anymore without a new datagram.</param>
    public UdpTransport(IUDPSender sender, EndPoint remote, int maxPacketLength, TimeSpan timeout)
    {
        this.Remote = remote;
        this.sender = sender;
        this.maxPacketLength = maxPacketLength;
        this.timeout = timeout;
        this.lastReceivedDatagram = DateTimeOffset.Now;
    }

    /// <summary>
    /// Gets the remote endpoint.
    /// </summary>
    public EndPoint Remote { get; }

    /// <summary>
    /// Get the maximum allowed package length for receiving.
    /// </summary>
    /// <returns>The maximum allowed package length.</returns>
    public int GetReceiveLimit()
    {
        return this.maxPacketLength;
    }

    /// <summary>
    /// Receive a udp package of the remote.
    /// </summary>
    /// <param name="buf">The buffer to insert the package.</param>
    /// <param name="off">The offset where to insert the payload.</param>
    /// <param name="len">The length of the buffer.</param>
    /// <param name="waitMillis">The timeout of the receive operation.</param>
    /// <returns>The amount of received bytes.</returns>
    public int Receive(byte[] buf, int off, int len, int waitMillis)
    {
        return this.Receive(buf.AsSpan(off, len), waitMillis);
    }

    /// <summary>
    /// Receive a udp package of the remote.
    /// </summary>
    /// <param name="buffer">The buffer to insert the package.</param>
    /// <param name="waitMillis">The timeout of the receive operation.</param>
    /// <returns>The amount of received bytes.</returns>
    public int Receive(Span<byte> buffer, int waitMillis)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(nameof(UdpTransport));
        }

        this.CheckTimeout();

        if (this.messages.TryTake(out var rx, TimeSpan.FromMilliseconds(waitMillis)))
        {
            rx.CopyTo(buffer);
            return rx.Length > buffer.Length ? buffer.Length : rx.Length;
        }

        return 0;
    }

    /// <summary>
    /// Get the maximum allowed package length for sending.
    /// </summary>
    /// <returns>The maximum allowed package length.</returns>
    public int GetSendLimit()
    {
        return this.maxPacketLength;
    }

    /// <summary>
    /// Send a package over udp.
    /// </summary>
    /// <param name="buf">The buffer to send from.</param>
    /// <param name="off">The offset of the package in the <paramref name="buf"/>.</param>
    /// <param name="len">The length of the package.</param>
    public void Send(byte[] buf, int off, int len)
    {
        this.Send(buf.AsSpan(off, len));
    }

    /// <summary>
    /// Send a package over udp.
    /// </summary>
    /// <param name="buffer">The message to send.</param>
    public void Send(ReadOnlySpan<byte> buffer)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(nameof(UdpTransport));
        }
        this.CheckTimeout();
        this.sender.SendTo(buffer, this.Remote);
    }

    /// <summary>
    /// Close the connection.
    /// </summary>
    public void Close()
    {
    }

    /// <summary>
    /// Enqueue a received message from the remote.
    /// </summary>
    /// <param name="payload">The received message.</param>
    internal void Enqueue(ReadOnlySpan<byte> payload)
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(nameof(UdpTransport));
        }
        this.messages.Add(payload.ToArray());
        this.lastReceivedDatagram = DateTimeOffset.Now;
    }

    public void Dispose()
    {
        this.disposed = true;
    }

    private void CheckTimeout()
    {
        if (DateTimeOffset.Now - this.lastReceivedDatagram > this.timeout)
        {
            throw new TlsTimeoutException("Did not receive a new package in time");
        }
    }
}
