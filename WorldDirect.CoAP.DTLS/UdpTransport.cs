namespace WorldDirect.CoAP.DTLS;

using System.Collections.Concurrent;
using System.Net;
using Org.BouncyCastle.Tls;

internal class UdpTransport : DatagramTransport
{
    private readonly IUDPSender sender;
    private readonly int maxPacketLength;
    private readonly ConcurrentQueue<byte[]> messages = new ();
    private readonly SemaphoreSlim sema = new (0);

    public UdpTransport(IUDPSender sender, EndPoint remote, int maxPacketLength)
    {
        this.Remote = remote;
        this.sender = sender;
        this.maxPacketLength = maxPacketLength;
    }

    public EndPoint Remote { get; }

    public int GetReceiveLimit()
    {
        return this.maxPacketLength;
    }

    public int Receive(byte[] buf, int off, int len, int waitMillis)
    {
        return this.Receive(buf.AsSpan(off, len), waitMillis);
    }

    public int Receive(Span<byte> buffer, int waitMillis)
    {
        if (this.sema.Wait(TimeSpan.FromMilliseconds(waitMillis)))
        {
            if (this.messages.TryDequeue(out var rx))
            {
                rx.CopyTo(buffer);
                return rx.Length > buffer.Length ? buffer.Length : rx.Length;
            }
        }

        return 0;
    }

    public int GetSendLimit()
    {
        return this.maxPacketLength;
    }

    public void Send(byte[] buf, int off, int len)
    {
        this.Send(buf.AsSpan(off, len));
    }

    public void Send(ReadOnlySpan<byte> buffer)
    {
        this.sender.SendTo(buffer, this.Remote);
    }

    public void Close()
    {
            
    }

    internal void Enqueue(ReadOnlySpan<byte> payload)
    {
        this.messages.Enqueue(payload.ToArray());
        this.sema.Release();
    }
}
