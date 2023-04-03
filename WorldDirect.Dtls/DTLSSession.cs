namespace WorldDirect.Dtls;

using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;

public class DTLSSession
{
    private readonly UdpTransport udpTransport;
    private readonly ILogger<DTLSSession> logger;
    private readonly Server server;
    private readonly DtlsServerProtocol protocol;
    private DtlsTransport? dtlsTransport;
    private Task? handshakeTask;

    public DTLSSession(TlsCrypto crypto, UdpTransport udpTransport, ILogger<DTLSSession> logger)
    {
        this.udpTransport = udpTransport;
        this.logger = logger;
        this.server = new Server(crypto);
        this.protocol = new DtlsServerProtocol();

    }

    public event EventHandler? ReceivedData;
    public bool HandshakeCompleted => this.server.IsConnected;

    public IPEndPoint Remote => this.udpTransport.Remote;

    public System.Security.Cryptography.X509Certificates.X509Certificate ClientCertificate =>
        this.server.GetPeerCertificate();

    public void Start()
    {
        if (this.handshakeTask != null)
        {
            throw new InvalidOperationException("Handshake was already started");
        }

        this.Handshake();
    }

    public int Receive(Span<byte> buffer, TimeSpan timeout)
    {
        return this.dtlsTransport!.Receive(buffer, (int)timeout.TotalMilliseconds);
    }

    public void Send(ReadOnlySpan<byte> buffer)
    {
        if (!this.HandshakeCompleted)
        {
            throw new InvalidOperationException($"Handshake not completed with {this.Remote}");
        }
        this.dtlsTransport!.Send(buffer);
    }

    private async Task Handshake()
    {
        var fac = new TaskFactory();
        this.handshakeTask = fac.StartNew(() => this.HandleHandshakeAsync(CancellationToken.None),
            TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            await this.handshakeTask.ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            this.logger.LogError(ex, "Handshake with {remote} failed because of {error}", this.Remote, ex.Message);
        }
    }

    private Task HandleHandshakeAsync(CancellationToken ct)
    {
        this.dtlsTransport = this.protocol.Accept(this.server, this.udpTransport);
        this.logger.LogDebug("Handshake accepted with {remote}", this.Remote);
        this.udpTransport.ReceivedData += (sender, args) =>
        {
            this.ReceivedData?.Invoke(this, args);
        };
        return Task.CompletedTask;
    }
}
