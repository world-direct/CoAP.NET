namespace WorldDirect.Dtls
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Http.Headers;
    using System.Net.Sockets;
    using System.Text;
    using System.Threading.Tasks;
    using CoAP.Net;
    using Microsoft.Extensions.Caching.Memory;
    using Microsoft.Extensions.Logging;

    public class DTLSManager : IDTLSStack
    {
        // do not throw SocketError.ConnectionReset by ignoring ICMP Port Unreachable
        private const Int32 SIO_UDP_CONNRESET = -1744830452;
        private DTLSContext context;
        private readonly DTLSConfig config;
        private readonly ILogger<DTLSManager> logger;
        private CancellationTokenSource cts = new ();
        private Socket? socket;
        private Task? receivingTask;
        private bool isRunning;
        private Dictionary<IPEndPoint, DTLSConnection> connections = new();

        public DTLSManager(DTLSConfig config,ILogger<DTLSManager> logger)
        {
            this.config = config;
            this.logger = logger;
        }

        public event EventHandler<DTLSDecryptedDataReceivedEventArgs>? ReceivedData;
        public EndPoint LocalEndPoint => new IPEndPoint(IPAddress.Any, this.config.Port);

        public void Start()
        {
            if (isRunning)
            {
                throw new InvalidOperationException("DTLSManager is already running");
            }
            this.InitializeContext();
            this.socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                socket.IOControl(SIO_UDP_CONNRESET, new Byte[] { 0 }, null);
                this.socket.Bind(this.LocalEndPoint);
            }
            catch (Exception)
            {
                this.socket = null;
                throw;
            }

            cts = new CancellationTokenSource();
            this.isRunning = true;
            this.receivingTask = this.HandleReceiveAsync(cts.Token);
        }

        public void Stop()
        {
            if (!isRunning)
            {
                return;
            }

            this.cts.Cancel();
            this.receivingTask?.GetAwaiter().GetResult();
        }

        public void SendTo(byte[] message, IPEndPoint remote)
        {
            if (this.connections.TryGetValue(remote, out var connection))
            {
                connection.SendData(message);
            }
        }

        private async Task HandleReceiveAsync(CancellationToken ct)
        {
            try
            {
                await this.ReceiveAsync(ct).ConfigureAwait(false);
            }
            finally
            {
                isRunning = false;
            }
        }

        private async Task ReceiveAsync(CancellationToken ct)
        {
            // todo check what happens when a message is received greater than the buffersize
            this.logger.LogInformation("Starting DTLS Socket on {LocalEndpoint}", this.LocalEndPoint);
            while (!ct.IsCancellationRequested)
            {
                var rxBuffer = new byte[this.config.BufferSize];
                IPEndPoint endpoint = new IPEndPoint(IPAddress.Any, 0);
                SocketReceiveFromResult receiveResult;
                try
                {
                    receiveResult = await this.socket.ReceiveFromAsync(rxBuffer, SocketFlags.None, endpoint, ct).ConfigureAwait(false);
                }
                catch (SocketException e)
                {
                    if (e.SocketErrorCode == SocketError.ConnectionReset)
                    {
                        continue;
                    }
                    this.logger.LogError(e, "Stopped receiving of DTLS packets");
                    throw;
                }
                var ipEndpoint = (IPEndPoint)receiveResult.RemoteEndPoint;

                if(!this.connections.TryGetValue(ipEndpoint, out var connection))
                {
                    var connectionContext = this.context.CreateConnectionContext(ipEndpoint);
                    connection = new DTLSConnection(connectionContext);
                    connection.ErrorOccured += OnErrorOccured;
                    connection.HandshakeCompleted += OnHandshakeCompleted;
                    connection.Received += OnDataReceived;
                    this.connections.Add(ipEndpoint, connection);
                    this.logger.LogDebug("Created new dtls connection with {Remote}", ipEndpoint);
                }

                var input = new Memory<byte>(rxBuffer, 0, receiveResult.ReceivedBytes);
                this.logger.LogTrace("Received {Bytes} bytes from {Remote}", input.Length, ipEndpoint);
                connection.HandleInput(input);
            }
        }

        private void InitializeContext()
        {
            try
            {
                this.context = new DTLSContext();
                this.context.SetSendCallback(((memory, point) =>
                {
                    this.logger.LogTrace("Send {Bytes} bytes to {Remote}", memory.Length, point);
                    this.socket.SendTo(memory.ToArray(), point);
                }));
                this.context.RequirePeerCertificate();
                this.context.SetCAFile(this.config.CAFile);
                this.context.SetCertificateFile(this.config.CertificateFile);
                this.context.SetPrivateKeyFile(this.config.PrivateKeyFile);
            }
            catch (Exception e)
            {
                this.logger.LogError(e, "Cant initialize dtls context");
                throw;
            }
        }

        private void OnDataReceived(object? sender, ReceivedDataEventArgs e)
        {
            var connection = (DTLSConnection)sender;
            var dtlsClient = new DTLSClient(connection.Remote);
            dtlsClient.Certificate = connection.Certificate;
            dtlsClient.PublicIdentifier = connection.Certificate.Subject;
            this.ReceivedData?.Invoke(this, new DTLSDecryptedDataReceivedEventArgs(dtlsClient, e.Bytes));
        }

        private void OnHandshakeCompleted(object? sender, HandshakeEventArgs e)
        {
            var connection = (DTLSConnection)sender;
            if (e.Success)
            {
                // todo remove old connections with same certificate
                this.logger.LogDebug("Handshake completed {HandshakeResult} with {Remote}", "successfully", connection.Remote);
            }
            else
            {
                this.logger.LogDebug("Handshake {HandshakeResult} with {Remote}", "failed", connection.Remote);
                this.connections.Remove(connection.Remote);
            }
            
        }

        private void OnErrorOccured(object? sender, DTLSErrorEventArgs e)
        {
            var connection = (DTLSConnection)sender;
            // todo error messages
            this.logger.LogError("DTLSConnection with {Remote} was closed because of error.", connection.Remote);
            this.connections.Remove(connection.Remote);
        }
    }
}
