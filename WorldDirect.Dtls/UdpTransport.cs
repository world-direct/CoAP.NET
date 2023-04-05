namespace WorldDirect.Dtls;

using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Tls;

public class UdpTransport : DatagramTransport
{
    private readonly UdpServer server;
    private readonly ILogger<UdpTransport> logger;
    private SemaphoreSlim sema;
    private readonly ConcurrentQueue<byte[]> receivedQueue;

    public UdpTransport(UdpServer server, IPEndPoint remote, byte[] firstMessage, ILogger<UdpTransport> logger)
    {
        this.server = server;
        this.logger = logger;
        this.Remote = remote;
        this.sema = new SemaphoreSlim(0);
        this.receivedQueue = new ConcurrentQueue<byte[]>();
        this.Enqueue(firstMessage);
        this.server.ReceivedData += ServerReceivedDataForward;
    }

    public event EventHandler? ReceivedData;

    private void ServerReceivedDataForward(object? sender, ReceivedPacketEventArgs e)
    {
        if (e.Remote.Equals(this.Remote))
        {
            this.Enqueue(e.Payload);
            this.ReceivedData?.Invoke(this, EventArgs.Empty);
        }
    }

    private void Enqueue(byte[] payload)
    {
        this.receivedQueue.Enqueue(payload);
        this.logger.LogTrace("Received {bytes} encrypted bytes from {remote}", payload.Length, this.Remote);
        this.sema.Release();
    }

    public IPEndPoint Remote { get; }

    public int GetReceiveLimit()
    {
        return this.server.MaxMessageSize;
    }

    public int Receive(byte[] buf, int off, int len, int waitMillis)
    {
        return this.Receive(buf.AsSpan(off, len), waitMillis);
    }

    public int Receive(Span<byte> buffer, int waitMillis)
    {
        if (this.sema.Wait(waitMillis) && this.receivedQueue.TryDequeue(out var payload))
        {
            payload.CopyTo(buffer);
            return payload.Length;
        }

        return 0;
    }

    public int GetSendLimit()
    {
        return this.server.MaxMessageSize;
    }

    public void Send(byte[] buf, int off, int len)
    {
        this.Send(buf.AsSpan(off, len));
    }

    public void Send(ReadOnlySpan<byte> buffer)
    {
        this.logger.LogTrace("Sending {bytes} encrypted bytes to {remote}", buffer.Length, this.Remote);
        this.server.SendTo(buffer, this.Remote);
    }

    public void Close()
    {
        this.server.ReceivedData -= ServerReceivedDataForward;
    }
}
