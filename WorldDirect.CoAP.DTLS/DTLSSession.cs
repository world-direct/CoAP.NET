namespace WorldDirect.CoAP.DTLS;

using System;
using System.Data;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Channel;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Tls;
using WorldDirect.CoAP.Log;
using WorldDirect.CoAP.Net;

internal class DTLSSession
{
    private readonly DTLSSessionConfig config;
    private readonly UdpTransport transport;
    private readonly DtlsServerProtocol protocol;
    private readonly DTLSServer dtlsServer;
    private DtlsTransport? dtlsTransport;
    private bool HandshakeFailed = false;
    private readonly ILogger<DTLSSession> logger;

    public DTLSSession(IUDPSender sender, DTLSServer server, EndPoint remote, DTLSSessionConfig config)
    {
        this.config = config;
        this.transport = new UdpTransport(sender, remote, config.MaxPacketLength);
        this.protocol = new DtlsServerProtocol();
        this.dtlsServer = server;
        this.logger = LogManager.GetLogger<DTLSSession>();
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
    /// Start the task which handles the received data.
    /// </summary>
    public void Start()
    {
        // perform handshake asynchronously, would be blocking otherwise
        Task.Factory.StartNew(this.HandleSession, TaskCreationOptions.LongRunning).ConfigureAwait(false);
    }

    /// <summary>
    /// Send the specified plaintext payload encrypted with this session.
    /// </summary>
    /// <param name="payload">The plaintext payload.</param>
    public void Send(ReadOnlySpan<byte> payload)
    {
        lock (this.dtlsTransport!)
        {
            if (payload.Length > this.dtlsServer.MaxFragmentLength)
            {
                this.logger.LogWarning("Cant send message with {Bytes} bytes to {Remote} because buffer of remote is to small.", payload.Length, this.Remote);
                return;
            }
            this.dtlsTransport?.Send(payload);
        }
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
            lock (this.dtlsTransport)
            {
                var rxBuffer = new byte[this.config.MaxPacketLength];
                int length;
                try
                {
                    do
                    {
                        length = this.dtlsTransport!.Receive(rxBuffer, 1);
                        if (length > 0)
                        {
                            this.InvokeDataReceived(rxBuffer.Take(length).ToArray());
                        }
                    } while (length > 0);
                }
                catch (Exception ex)
                {
                    this.logger.LogTrace(ex, "Cant receive {Bytes} decrypted bytes from {Remote}", payload.Length, this.Remote);
                }
            }
        }
    }

    private void InvokeDataReceived(byte[] payload)
    {
        if (this.dtlsServer.IsAuthenticated)
        {
            if (this.dtlsServer.PeerCertificate != null)
            {
                var peerCert = new X509Certificate(this.dtlsServer.PeerCertificate.GetEncoded());
                this.DataReceived?.Invoke(this, new DTLSDataReceivedEventArgs(payload, this.transport.Remote, peerCert));
            }
            else if (this.dtlsServer.PskIdentity.Any())
            {
                this.DataReceived?.Invoke(this, new DTLSDataReceivedEventArgs(payload, this.transport.Remote, Encoding.ASCII.GetString(this.dtlsServer.PskIdentity)));
            }
        }
        else
        {
            throw new NotImplementedException($"Unauthenticated communication is not implemented");
        }
    }

    private void HandleSession()
    {
        try
        {
            // perform handshake
            this.dtlsTransport = this.protocol.Accept(this.dtlsServer, this.transport);
            this.logger.LogInformation("Finished handshake with {Remote} successfully", this.Remote);
        }
        catch (TlsTimeoutException e)
        {
            this.HandshakeFailed = true;
            this.logger.LogError(e, "{Remote} failed handshake because of timeout ({Timeout})", this.Remote, this.config.HandshakeTimeout);
        }
        catch (TlsFatalAlert e)
        {
            this.logger.LogError(e, "{Remote} failed handshake", this.Remote);
            this.HandshakeFailed = true;
        }
        catch (Exception e)
        {
            this.logger.LogError(e, "{Remote} failed handshake", this.Remote);
            this.HandshakeFailed = true;
        }
        finally
        {
            this.HandshakeFinished?.Invoke(this, new HandshakeFinishedEventArgs() { Successful = !this.HandshakeFailed });
        }
    }
}
