namespace WorldDirect.Dtls;

using System.Net;
using System.Net.Sockets;

public class UdpServer
{
    private readonly ushort port;
    private Socket? socket;
    private Task? ReceivingTask;
    private CancellationTokenSource? cts;
    public UdpServer(ushort port, int maxMessageSize)
    {
        if (maxMessageSize < 0)
        {
            throw new ArgumentException("MaxMessageSize must be greater 0", nameof(maxMessageSize));
        }
        this.port = port;
        this.MaxMessageSize = maxMessageSize;
    }
    public event EventHandler<ReceivedPacketEventArgs>? ReceivedData;
    public int MaxMessageSize { get; }

    public void Start()
    {
        if (this.socket != null)
        {
            throw new InvalidOperationException("Server already started");
        }

        this.StartHandle();
    }

    public void Stop()
    {
        if (this.socket == null || this.ReceivingTask == null || this.cts == null)
        {
            return;
        }
        this.cts.Cancel();
        this.ReceivingTask.GetAwaiter().GetResult();


    }

    public void SendTo(ReadOnlySpan<byte> payload, IPEndPoint remote)
    {
        if (this.socket == null)
        {
            throw new InvalidOperationException("Server is not running");
        }
        this.socket.SendTo(payload, remote);
    }

    private async Task StartHandle()
    {
        this.socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        this.socket.Bind(new IPEndPoint(IPAddress.Any, this.port));
        this.cts = new CancellationTokenSource();
        this.ReceivingTask = this.HandleAsync(this.cts.Token);
        try
        {
            await this.ReceivingTask.ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Udpserver failed because of {ex}");
        }
        finally
        {
            this.socket.Close();
            this.socket = null;
        }
    }

    private async Task HandleAsync(CancellationToken ct)
    {
        var sock = this.socket!;

        var buffer = new byte[this.MaxMessageSize];
        var remote = new IPEndPoint(IPAddress.Any, 0);
        while (!ct.IsCancellationRequested)
        {
            var result = await sock.ReceiveFromAsync(buffer, SocketFlags.None, remote, ct).ConfigureAwait(false);
            var remoteEndpoint = (IPEndPoint)result.RemoteEndPoint!;
            var payload = buffer.Take(result.ReceivedBytes).ToArray();
            this.ReceivedData?.Invoke(this, new ReceivedPacketEventArgs()
            {
                Payload = payload,
                Remote = remoteEndpoint,
            });
        }

    }
}