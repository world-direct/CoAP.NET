namespace WorldDirect.Dtls
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Net.Http.Headers;
    using System.Net.Sockets;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;
    using CoAP.Net;
    using Microsoft.Extensions.Logging;

    public class DTLSConfig
    {
        public ushort Port { get; set; }
        public string CertificateFile { get; set; }
        public string PrivateKeyFile { get; set; }
        public string CAFile { get; set; }

        public int BufferSize { get; set; }
    }

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

        public DTLSManager(DTLSConfig config, ILogger<DTLSManager> logger)
        {
            this.config = config;
            this.logger = logger;
        }

        public void Dispose()
        {
            throw new NotImplementedException();
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

    internal class SendDTLSDataContext
    {
        private Action<Memory<byte>, IPEndPoint> sendCallback;

        public SendDTLSDataContext(Action<Memory<byte>, IPEndPoint> callback)
        {
            this.sendCallback = callback;
        }

        public void SendData(Memory<byte> data, IPEndPoint endpoint)
        {
            this.sendCallback(data, endpoint);
        }
    }

    internal class DTLSContext
    {
        private IntPtr ctx;
        private SendDTLSDataContext sendContext;

        public DTLSContext()
        {
            this.ctx = wolfssl.CTX_dtls_new(wolfssl.useDTLSv1_2_server());
            if (this.ctx == IntPtr.Zero)
            {
                throw new InvalidOperationException("Cant create new DTLS context");
            }
        }

        public void SetSendCallback(Action<Memory<byte>, IPEndPoint> callback)
        {
            this.sendContext = new SendDTLSDataContext(callback);
        }

        public void SetCertificateFile(string path)
        {
            if (!File.Exists(path))
            {
                throw new FileNotFoundException($"{path} for certificate does not exist");
            }
            this.CallErrorAwareCtxFunction(() => wolfssl.CTX_use_certificate_file(this.ctx, path, wolfssl.SSL_FILETYPE_PEM),
                nameof(wolfssl.CTX_use_certificate_file));
        }

        public void SetPrivateKeyFile(string path)
        {
            if (!File.Exists(path))
            {
                throw new FileNotFoundException($"{path} for private key does not exist");
            }
            this.CallErrorAwareCtxFunction(() => wolfssl.CTX_use_PrivateKey_file(this.ctx, path, wolfssl.SSL_FILETYPE_PEM), nameof(wolfssl.CTX_use_PrivateKey_file));
        }

        public void SetCAFile(string path)
        {
            if (!File.Exists(path))
            {
                throw new FileNotFoundException($"{path} for CA does not exist");
            }
            this.CallErrorAwareCtxFunction(() => wolfssl.CTX_load_verify_locations(this.ctx, path, null), nameof(wolfssl.CTX_load_verify_locations));
        }

        public void RequirePeerCertificate()
        {
            this.CallErrorAwareCtxFunction(() => wolfssl.CTX_set_verify(this.ctx, wolfssl.SSL_VERIFY_FAIL_IF_NO_PEER_CERT | wolfssl.SSL_VERIFY_PEER,
                (currentStatus, _) => currentStatus), nameof(wolfssl.CTX_set_verify));
        }

        public DTLSConnectionContext CreateConnectionContext(IPEndPoint remote)
        {
            var ssl = wolfssl.new_ssl(this.ctx);
            if (ssl == IntPtr.Zero)
            {
                throw new InvalidOperationException($"Cant create new dtls session");
            }
            var context = new DTLSConnectionContext(ssl, remote);
            this.CallErrorAwareCtxFunction(() => wolfssl.set_dtls_fd(ssl, this.sendContext, context), nameof(wolfssl.set_dtls_fd));
            return context;
        }


        private void CallErrorAwareCtxFunction(Func<int> functionCall, string name = "")
        {
            if (functionCall() != wolfssl.SUCCESS)
            {
                int err = wolfssl.X509_STORE_CTX_get_error(this.ctx);
                var strError = wolfssl.get_error(err);
                throw new InvalidOperationException($"{name} returned error: {strError}");
            }
        }
    }

    internal class HandshakeFailedException : Exception
    {
        public HandshakeFailedException(string message)
        {
            
        }
    }

    internal class DTLSConnectionContext
    {
        private readonly IntPtr ssl;
        private byte[] availableData = Array.Empty<byte>();
        public DTLSConnectionContext(IntPtr ssl, IPEndPoint remote)
        {
            this.ssl = ssl;
            this.Remote = remote;
        }

        public IPEndPoint Remote { get; }

        public X509Certificate? Certificate { get; private set; }

        public void SendData(byte[] data)
        {
            int ret = wolfssl.write(this.ssl, data, data.Length);
            if (ret < 0)
            {
                var err = wolfssl.get_error_int(this.ssl);
                var errStr = wolfssl.get_error(err);
                throw new InvalidOperationException($"Send to {this.Remote} failed: {errStr}");
            }
        }

        public void ReceivedData(byte[] data)
        {
            this.availableData = data;
        }

        public bool TryDequeueData(out byte[] data)
        {
            if (this.availableData.Length == 0)
            {
                data = Array.Empty<byte>();
                return false;
            }
            data = this.availableData;
            this.availableData = Array.Empty<byte>();
            return true;
        }

        /// <summary>
        /// Tries to finish handshake.
        /// </summary>
        /// <returns>True when handshake finished, false when handshake is ongoing.</returns>
        /// <exception cref="HandshakeFailedException"></exception>
        public bool accept()
        {
            var ret = wolfssl.accept(this.ssl);
            if (ret != wolfssl.SUCCESS)
            {
                var err = wolfssl.get_error_int(this.ssl);
                if (err != -1 * wolfssl.CBIO_ERR_WANT_READ)
                {
                    var errStr = wolfssl.get_error(err);
                    throw new HandshakeFailedException($"Handshake with {this.Remote} failed: {errStr}");
                }

                return false;
            }

            var wolfsslCertificate = wolfssl.get_peer_certificate(this.ssl);
            this.Certificate = new X509Certificate(wolfsslCertificate.Export());
            return true;
        }

        public int TryReadData(byte[] data)
        {
            var ret = wolfssl.read(this.ssl, data, data.Length);
            if (ret < 0)
            {
                var err = wolfssl.get_error_int(this.ssl);
                if (err != -1 * wolfssl.CBIO_ERR_WANT_READ)
                {
                    var errStr = wolfssl.get_error(err);
                    throw new InvalidOperationException($"Receive from {this.Remote} failed: {errStr}");
                }

                return 0;
            }
            return ret;
        }
    }

    internal class HandshakeEventArgs : EventArgs
    {
        public bool Success { get; set; }
    }

    internal class ReceivedDataEventArgs : EventArgs
    {
        public byte[] Bytes { get; set; }
    }

    internal class DTLSErrorEventArgs : EventArgs
    {

    }

    internal class DTLSConnection
    {
        private readonly DTLSConnectionContext context;
        private readonly int bufferSize;
        public event EventHandler<HandshakeEventArgs> HandshakeCompleted;
        public event EventHandler<ReceivedDataEventArgs> Received;
        public event EventHandler<DTLSErrorEventArgs> ErrorOccured;

        private bool handshakeCompleted = false;

        public DTLSConnection(DTLSConnectionContext context, int bufferSize = 1024)
        {
            this.context = context;
            this.bufferSize = bufferSize;
        }

        public IPEndPoint Remote => this.context.Remote;
        public X509Certificate? Certificate => this.context.Certificate;

        public void HandleInput(Memory<byte> input)
        {
            this.context.ReceivedData(input.ToArray());
            if (!this.handshakeCompleted)
            {
                this.PerformHandshake();
            }
            else
            {
                this.ReadData();
            }
        }

        public void SendData(byte[] data)
        {
            this.context.SendData(data);
        }

        private void ReadData()
        {
            var buffer = new byte[this.bufferSize];
            var ret = this.context.TryReadData(buffer);
            if (ret > 0)
            {
                this.Received?.Invoke(this, new ReceivedDataEventArgs() {Bytes = buffer.Take(ret).ToArray(),});
            }

        }

        private void PerformHandshake()
        {
            try
            {
                if (this.context.accept())
                {
                    this.handshakeCompleted = true;
                    this.HandshakeCompleted?.Invoke(this, new HandshakeEventArgs()
                    {
                        Success = true,
                    });
                }
            }
            catch (HandshakeFailedException)
            {
                this.HandshakeCompleted?.Invoke(this, new HandshakeEventArgs()
                {
                    Success = false,
                });
            }
        }
    }
}
