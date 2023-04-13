namespace WorldDirect.CoAP.DTLS;

using System.Net;
using Channel;
using Org.BouncyCastle.Tls;

internal class DTLSSession
{
    private readonly CancellationTokenSource cts;
    private readonly DTLSSessionConfig config;
    private Task? HandleTask;
    private readonly UdpTransport transport;
    private readonly DtlsServerProtocol protocol;
    private readonly DTLSServer dtlsServer;
    private DtlsTransport? dtlsTransport;

    public DTLSSession(IUDPSender sender, DTLSServer server, EndPoint remote, CancellationTokenSource cts, DTLSSessionConfig config)
    {
        this.cts = cts;
        this.config = config;
        this.transport = new UdpTransport(sender, remote, config.MaxPacketLength);
        this.protocol = new DtlsServerProtocol();
        this.dtlsServer = server;
    }

    /// <summary>
    /// An event when a new decrypted payload was received.
    /// </summary>
    public event EventHandler<DataReceivedEventArgs>? DataReceived;

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
        this.HandleTask = Task.Run(async () => await this.HandleSession().ConfigureAwait(false));
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
        this.transport.Enqueue(payload);
    }

    private async Task HandleSession()
    {
        try
        {

            await this.HandleSessionAsync(this.cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {

        }
        catch (Exception e)
        {
            // Todo logging
        }
        finally
        {
            // todo logging
            this.HandleTask = null;
        }
    }

    private async Task HandleSessionAsync(CancellationToken ct)
    {
        // accept

        this.dtlsTransport = this.protocol.Accept(this.dtlsServer, this.transport);
        var rxBuffer = new byte[this.config.MaxPacketLength];

        do
        {

            var receivedMessage = await this.transport.WaitForMessageAsync(this.config.SessionTimeout, ct).ConfigureAwait(false);
            if (!receivedMessage)
            {
                return;
            }

            var length = this.dtlsTransport.Receive(rxBuffer, 0);
            if (length <= 0)
            {
                throw new InvalidOperationException("Could not read from dtls");
            }
            this.DataReceived?.Invoke(this, new DataReceivedEventArgs(rxBuffer.Take(length).ToArray(), this.transport.Remote));

        } while (!ct.IsCancellationRequested);
    }
}
