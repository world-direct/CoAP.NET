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
        private readonly IMemoryCache cache;

        public DTLSManager(DTLSConfig config, IMemoryCache cache, ILogger<DTLSManager> logger)
        {
            this.config = config;
            this.logger = logger;
            this.cache = cache;
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
            if (this.cache.TryGetValue<DTLSConnection>(remote, out var connection))
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

                var connection = this.cache.GetOrCreate(ipEndpoint, entry =>
                {
                    entry.SlidingExpiration = this.config.Timeout;
                    entry.PostEvictionCallbacks.Add(new PostEvictionCallbackRegistration()
                    {
                        EvictionCallback = (key, value, reason, state) =>
                        {
                            var rem = (IPEndPoint)key;
                            this.logger.LogDebug("Removed DTLS Connection to {Remote} because of timeout", rem);
                        },
                        State = this,
                    });
                    var connectionContext = this.context.CreateConnectionContext(ipEndpoint);
                    var conn = new DTLSConnection(connectionContext, this.config.BufferSize);
                    conn.ErrorOccured += OnErrorOccured;
                    conn.HandshakeCompleted += OnHandshakeCompleted;
                    conn.Received += OnDataReceived;
                    this.logger.LogDebug("Created new dtls connection with {Remote}", ipEndpoint);
                    return conn;
                });

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
            dtlsClient.PublicIdentifier = connection.Certificate.GetCommonName();
            this.ReceivedData?.Invoke(this, new DTLSDecryptedDataReceivedEventArgs(dtlsClient, e.Bytes));
        }

        private void OnHandshakeCompleted(object? sender, HandshakeEventArgs e)
        {
            var connection = (DTLSConnection)sender;
            if (e.Success)
            {
                this.logger.LogDebug("Handshake completed {HandshakeResult} with {Remote}", "successfully", connection.Remote);
            }
            else
            {
                this.logger.LogDebug("Handshake {HandshakeResult} with {Remote}", "failed", connection.Remote);
                this.cache.Remove(connection.Remote);
            }
            
        }

        private void OnErrorOccured(object? sender, DTLSErrorEventArgs e)
        {
            var connection = (DTLSConnection)sender;
            if (e.Exception != null)
            {
                this.logger.LogError(e.Exception, "DTLSConnection with {Remote} was closed because of '{Message}'.", connection.Remote, e.Message);
            }
            else
            {
                this.logger.LogError(e.Exception, "DTLSConnection with {Remote} was closed because of '{Message}'.", connection.Remote, e.Message);
            }
            
            this.cache.Remove(connection.Remote);
        }
    }
}
