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
    private readonly DTLSServer dtlsServer;
    private readonly DtlsServerProtocol protocol;
    private DtlsTransport? dtlsTransport;
    private Task? handshakeTask;

    public DTLSSession(TlsCrypto crypto, UdpTransport udpTransport, TlsPskIdentityManager? pskManager, ILogger<DTLSSession> logger)
    {
        this.udpTransport = udpTransport;
        this.logger = logger;
        this.dtlsServer = new DTLSServer(crypto, pskManager);
        this.protocol = new DtlsServerProtocol();
        this.HandshakeFailed = false;
    }

    public event EventHandler? ReceivedData;
    public event EventHandler<HandshakeFinishedEventArgs>? HandshakeFinished;

    public bool HandshakeCompleted => this.dtlsServer.IsConnected;
    public bool HandshakeFailed { get; private set; }

    public IPEndPoint Remote => this.udpTransport.Remote;

    public System.Security.Cryptography.X509Certificates.X509Certificate? ClientCertificate =>
        this.dtlsServer.Certificate;

    public string PublicIdentifier => this.dtlsServer.PublicIdentifier;

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
        this.handshakeTask = fac.StartNew(this.HandleHandshake,
            TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            await this.handshakeTask.ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            this.logger.LogDebug(ex, "Handshake with {remote} failed because of {error}", this.Remote, ex.Message);
            this.HandshakeFailed = true;
        }
        finally
        {
            this.HandshakeFinished?.Invoke(this, new HandshakeFinishedEventArgs()
            {
                Result = !this.HandshakeFailed,
                Certificate = this.ClientCertificate,
                PublicIdentifier = this.PublicIdentifier,
            });
        }
    }

    private void HandleHandshake()
    {
        this.dtlsTransport = this.protocol.Accept(this.dtlsServer, this.udpTransport);
        this.logger.LogDebug("Handshake finished with {remote}", this.Remote);
        this.udpTransport.ReceivedData += (sender, args) =>
        {
            this.ReceivedData?.Invoke(this, args);
        };
    }
}
