namespace WorldDirect.CoAP.DTLS;

using System.Net;
using Channel;
using Org.BouncyCastle.Tls;

internal class HandshakeFinishedEventArgs : EventArgs
{
    public bool Successful { get; set; }
}

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

    public DTLSSession(IUDPSender sender, DTLSServer server, EndPoint remote, CancellationTokenSource cts, DTLSSessionConfig config)
    {
        this.cts = cts;
        this.config = config;
        this.transport = new UdpTransport(sender, remote, config.MaxPacketLength);
        this.protocol = new DtlsServerProtocol();
        this.dtlsServer = server;
    }

    public EndPoint Remote => this.transport.Remote;

    /// <summary>
    /// An event when a new decrypted payload was received.
    /// </summary>
    public event EventHandler<DataReceivedEventArgs>? DataReceived;

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
                this.DataReceived?.Invoke(this, new DataReceivedEventArgs(rxBuffer.Take(length).ToArray(), this.transport.Remote));
            }
            
        }
    }

    private async Task HandleSession()
    {
        try
        {
            // perform handshake
            this.dtlsTransport = this.protocol.Accept(this.dtlsServer, this.transport);
            // todo logging
        }
        catch (TlsTimeoutException e)
        {
            // todo logging handshake timed out
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
    }
}
