namespace WorldDirect.CoAP.DTLS;

using System.Data;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Channel;
using Org.BouncyCastle.Tls;
using WorldDirect.CoAP.Log;
using WorldDirect.CoAP.Net;

internal class DTLSSession
{
    private readonly CancellationTokenSource cts;
    private readonly DTLSSessionConfig config;
    private readonly UdpTransport transport;
    private readonly DtlsServerProtocol protocol;
    private readonly DTLSServer dtlsServer;
    private DtlsTransport? dtlsTransport;
    private Task? HandshakeTask;
    private bool HandshakeFailed = false;
    private readonly ILogger logger;

    public DTLSSession(IUDPSender sender, DTLSServer server, EndPoint remote, CancellationTokenSource cts, DTLSSessionConfig config)
    {
        this.cts = cts;
        this.config = config;
        this.transport = new UdpTransport(sender, remote, config.MaxPacketLength);
        this.protocol = new DtlsServerProtocol();
        this.dtlsServer = server;
        this.logger = LogManager.GetLogger(typeof(DTLSSession));
    }

    public EndPoint Remote => this.transport.Remote;

    /// <summary>
    /// An event when a new decrypted payload was received.
    /// </summary>
    public event EventHandler<DTLSDataReceivedEventArgs>? DataReceived;

    /// <summary>
    /// An event when the handshake was finished.
    /// </summary>
    public event EventHandler<HandshakeFinishedEventArgs>? HandshakeFinished;

    /// <summary>
    /// Cancel the task which handles the the received data.
    /// </summary>
    public void Cancel()
    {
        this.cts.Cancel();
    }

    /// <summary>
    /// Start the task which handles the received data.
    /// </summary>
    public void Start()
    {
        // perform handshake asynchronously, would be blocking otherwise
        Task.Run(async () => await this.HandleSession().ConfigureAwait(false));
    }

    /// <summary>
    /// Send the specified plaintext payload encrypted with this session.
    /// </summary>
    /// <param name="payload">The plaintext payload.</param>
    public void Send(ReadOnlySpan<byte> payload)
    {
        this.dtlsTransport?.Send(payload);
    }

    /// <summary>
    /// Enqueue a received dtls message for this session.
    /// </summary>
    /// <param name="payload">The dtls message.</param>
    public void Enqueue(ReadOnlySpan<byte> payload)
    {
        if (this.HandshakeFailed)
        {
            return;
        }
        this.transport.Enqueue(payload);

        // if handshake was was performed successfully, decrypt data directly
        if (dtlsTransport != null)
        {
            var rxBuffer = new byte[this.config.MaxPacketLength];
            var length = this.dtlsTransport!.Receive(rxBuffer, 0);
            if (length < 0)
            {
                throw new InvalidOperationException("Could not read from dtls");
            }
            else if (length > 0)
            {
                if (this.dtlsServer.IsAuthenticated)
                {
                    if (this.dtlsServer.PeerCertificate != null)
                    {
                        var peerCert = new X509Certificate(this.dtlsServer.PeerCertificate.GetEncoded());
                        this.DataReceived?.Invoke(this, new DTLSDataReceivedEventArgs(rxBuffer.Take(length).ToArray(), this.transport.Remote, peerCert));
                    }
                    else if (this.dtlsServer.PskIdentity.Any())
                    {
                        this.DataReceived?.Invoke(this, new DTLSDataReceivedEventArgs(rxBuffer.Take(length).ToArray(), this.transport.Remote, Encoding.ASCII.GetString(this.dtlsServer.PskIdentity)));
                    }
                }
                throw new NotImplementedException($"PSK or unauthenticated communication is not implemented");
            }
            
        }
    }

    private Task HandleSession()
    {
        try
        {
            // perform handshake
            this.dtlsTransport = this.protocol.Accept(this.dtlsServer, this.transport);
            // todo logging
        }
        catch (TlsTimeoutException e)
        {
            this.HandshakeFailed = true;
        }
        catch (TlsFatalAlert e)
        {
            // todo logging
            this.HandshakeFailed = true;
        }
        catch (Exception e)
        {
            // Todo logging
            this.HandshakeFailed = true;
        }
        finally
        {
            this.HandshakeFinished?.Invoke(this, new HandshakeFinishedEventArgs() { Successful = !this.HandshakeFailed });
        }

        return Task.CompletedTask;
    }
}
