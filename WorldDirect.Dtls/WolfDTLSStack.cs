namespace WorldDirect.Dtls
{
    using System;
    using System.Collections;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
    using System.Reflection.Metadata.Ecma335;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;
    using CoAP.Net;
    using Microsoft.Extensions.Logging;

    internal class WolfDTLSSession : IDisposable
    {
        private SemaphoreSlim semaphore;
        private ConcurrentQueue<byte[]> dataToSend;
        private ConcurrentQueue<byte[]> receivedData;
        private IntPtr sslContext;
        private bool finishedHandshake = false;

        public WolfDTLSSession(Socket outSocket, IPEndPoint endpoint, IntPtr dtlsContext, CancellationToken ct)
        {
            this.semaphore = new SemaphoreSlim(0);
            this.dataToSend = new ConcurrentQueue<byte[]>();
            this.receivedData = new ConcurrentQueue<byte[]>();
            this.Cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            this.client = new DTLSClient(endpoint);
            this.sslContext = wolfssl.new_ssl(dtlsContext);
            if (wolfssl.set_dtls_fd(this.sslContext, outSocket, endpoint, this) != wolfssl.SUCCESS)
            {
                throw new InvalidOperationException("Cant assign connection parameter");
            }
        }

        public async Task WaitForEventAsync(CancellationToken ct)
        {
            await this.semaphore.WaitAsync(ct).ConfigureAwait(false);
        }

        public void EnqueueSendPayload(byte[] payload)
        {
            this.dataToSend.Enqueue(payload);
            this.semaphore.Release();
        }

        public bool TryDequeueSendPayload(out byte[] payload)
        {
            return this.dataToSend.TryDequeue(out payload);
        }

        public void EnqueueReceivedData(byte[] payload)
        {
            this.receivedData.Enqueue(payload);
            this.semaphore.Release();
        }

        public bool TryDequeueReceivedData(out byte[] payload)
        {
            return this.receivedData.TryDequeue(out payload);
        }

        public async Task<byte[]> ReceiveAsync(CancellationToken ct)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(90));
            try
            {
                if (!this.finishedHandshake)
                {
                    throw new InvalidOperationException($"Handshake with {this.client.Remote} was not finished");
                }

                return await this.HandleConnectionUntilDataReceivedAsync(cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException e)
            {
                throw new OperationCanceledException($"DTLS Session with {this.client.Remote} timed out", e, cts.Token);
            }

        }

        public async Task StopAsync()
        {
            this.Cts.Cancel();
            try
            {

                await this.SessionHandling.ConfigureAwait(false);
            }
            catch (Exception)
            {
                // catched in another wait statement
            }
        }

        private async Task<byte[]> HandleConnectionUntilDataReceivedAsync(CancellationToken ct)
        {
            var rxBuf = new byte[2048];
            while (!ct.IsCancellationRequested)
            {
                await this.WaitForEventAsync(ct).ConfigureAwait(false);
                var ret = wolfssl.read(this.sslContext, rxBuf, rxBuf.Length);
                if (ret < 0)
                {
                    var err = wolfssl.get_error_int(this.sslContext);
                    if (err != -1 * wolfssl.CBIO_ERR_WANT_READ)
                    {
                        var errStr = wolfssl.get_error(err);
                        throw new InvalidOperationException($"Receive from {this.client.Remote} failed: {errStr}");
                    }
                }
                else
                {
                    //Console.WriteLine($"Received {ret} udp payload bytes from {this.client.Remote}");
                    return rxBuf.Take(ret).ToArray();
                }

                if (this.TryDequeueSendPayload(out var txBuf))
                {
                    //Console.WriteLine($"Sending {txBuf.Length} udp payload to {this.client.Remote}");
                    ret = wolfssl.write(this.sslContext, txBuf, txBuf.Length);
                    if (ret < 0)
                    {
                        var err = wolfssl.get_error_int(this.sslContext);
                        if (err != -1 * wolfssl.CBIO_ERR_WANT_READ)
                        {
                            var errStr = wolfssl.get_error(err);
                            throw new InvalidOperationException($"Send to {this.client.Remote} failed: {errStr}");
                        }
                    }
                }
            }

            throw new OperationCanceledException($"DTLS session to {this.client.Remote} cancellation was requested");
        }

        public async Task HandshakeAsync(CancellationToken ct)
        {
            
            if (this.finishedHandshake)
            {
                return;
            }
            int ret = wolfssl.FAILURE;
            while (!ct.IsCancellationRequested && ret != wolfssl.SUCCESS)
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(90));
                await this.WaitForEventAsync(cts.Token).ConfigureAwait(false);

                ret = wolfssl.accept(this.sslContext);
                if (ret != wolfssl.SUCCESS)
                {
                    var err = wolfssl.get_error_int(this.sslContext);
                    if (err != -1 * wolfssl.CBIO_ERR_WANT_READ)
                    {
                        var errStr = wolfssl.get_error(err);
                        throw new InvalidOperationException($"Handshake with {this.client.Remote} failed: {errStr}");
                    }
                }
            }

            this.finishedHandshake = true;
            var clientCertificate = wolfssl.get_peer_certificate(this.sslContext);
            this.client.Certificate = new X509Certificate(clientCertificate.Export());
            this.client.PublicIdentifier = this.client.Certificate.Subject;
        }

        public DTLSClient client { get; }
        public Task SessionHandling { get; set; }
        public CancellationTokenSource Cts { get; }

        public void Dispose()
        {
            /*if (!this.SessionHandling.IsCompleted)
            {
                if (!this.Cts.IsCancellationRequested)
                {
                    this.Cts.Cancel();
                }
                this.SessionHandling.GetAwaiter().GetResult();
            }*/
            if (this.sslContext != IntPtr.Zero)
            {
                wolfssl.free(this.sslContext);
                this.sslContext = IntPtr.Zero;
            }
        }
    }

    public class DTLSConfig
    {
        public ushort Port { get; set; }
        public string CertificateFile { get; set; }
        public string PrivateKeyFile { get; set; }
        public string CAFile { get; set; }
    }

    public class WolfDTLSStack : IDTLSStack
    {
        private static void wolfSSLLog(int lvl, StringBuilder msg)
        {
            Console.WriteLine(msg);
        }

        static WolfDTLSStack()
        {
            wolfssl.Init();
            wolfssl.SetLogging(wolfSSLLog);
        }

        // do not throw SocketError.ConnectionReset by ignoring ICMP Port Unreachable
        private const Int32 SIO_UDP_CONNRESET = -1744830452;

        public event EventHandler<DTLSDecryptedDataReceivedEventArgs> ReceivedData;
        private readonly DTLSConfig config;
        private readonly ILogger<WolfDTLSStack> logger;
        private IntPtr ctx;
        private Socket? socket;

        private Task? receivingTask;
        private CancellationTokenSource? cts;

        private ConcurrentDictionary<IPEndPoint, WolfDTLSSession> sessions;

        public WolfDTLSStack(DTLSConfig config, ILogger<WolfDTLSStack> logger)
        {
            this.config = config;
            this.logger = logger;
            this.sessions = new ConcurrentDictionary<IPEndPoint, WolfDTLSSession>();
        }

        public EndPoint LocalEndPoint => new IPEndPoint(IPAddress.Any, this.config.Port);

        public void Start()
        {
            if (this.cts != null)
            {
                throw new InvalidOperationException("DTLSStack already started");
            }
            this.InitializeContext();
            this.cts = new CancellationTokenSource();
            this.socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                socket.IOControl(SIO_UDP_CONNRESET, new Byte[] { 0 }, null);
                this.socket.Bind(new IPEndPoint(IPAddress.Any, this.config.Port));
            }
            catch (Exception)
            {
                this.cts = null;
                this.socket = null;
                throw;
            }

            //Console.WriteLine($"Started DTLS socket on port {this.config.Port}");
            this.receivingTask = this.ReceiveAsync(this.cts.Token);
        }

        public void Stop()
        {
            throw new NotImplementedException();
        }

        public void SendTo(byte[] message, IPEndPoint remote)
        {
            if (socket == null)
            {
                throw new InvalidOperationException("DTLSStack is not running");
            }

            var session = this.sessions[remote];
            session.EnqueueSendPayload(message);
        }

        private async Task ReceiveAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                var rxBuffer = new byte[2048];
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

                var payload = rxBuffer.Take(receiveResult.ReceivedBytes).ToArray();
                var remoteIpEndpoint = (IPEndPoint)receiveResult.RemoteEndPoint;
                WolfDTLSSession? session;
                if (!this.sessions.TryGetValue(remoteIpEndpoint, out session))
                {
                    this.logger.LogDebug("New client connected {Remote}", remoteIpEndpoint);
                    session = new WolfDTLSSession(this.socket, remoteIpEndpoint, this.ctx, ct);
                    this.StartSessionAsync(session, this.HandleSessionAsync(session, session.Cts.Token)).ConfigureAwait(false);
                }

                this.logger.LogTrace("Received {Bytes} bytes from {Remote}", payload.Length, remoteIpEndpoint);
                session.EnqueueReceivedData(payload);
            }
        }

        private async Task HandleSessionAsync(WolfDTLSSession session, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                await session.HandshakeAsync(ct);
                
                var oldSession = this.sessions.Select(s => s.Value).FirstOrDefault(s => s.client.PublicIdentifier == session.client.PublicIdentifier);
                if (oldSession != null)
                {
                    this.logger.LogDebug("Removing session with {OldRemote} because new client connected with its identity on {Remote}", oldSession.client.Remote, session.client.Remote);
                    await oldSession.StopAsync().ConfigureAwait(false);
                    this.sessions.Remove(oldSession.client.Remote, out var _);
                }

                var receivedData = await session.ReceiveAsync(ct).ConfigureAwait(false);
                this.ReceivedData?.Invoke(this, new DTLSDecryptedDataReceivedEventArgs(session.client, receivedData));
            }
        }

        private async Task StartSessionAsync(WolfDTLSSession session, Task sessionHandling)
        {
            try
            {
                session.SessionHandling = sessionHandling;
                await sessionHandling.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                this.logger.LogDebug("DTLSSession with {Remote} will be closed", session.client.Remote);
            }
            catch (Exception e)
            {
                this.logger.LogError(e, "DTLSSession of {Remote} will be closed because of error", session.client.Remote);
            }
            finally
            {
                // Console.WriteLine($"Removed DTLS session with {session.client.Remote}");
                this.logger.LogDebug("Remove DTLS Session with {Remote}", session.client.Remote);
                this.sessions.TryRemove(session.client.Remote, out var _);
            }
        }

        private void InitializeContext()
        {
            try
            {
                this.ctx = wolfssl.CTX_dtls_new(wolfssl.useDTLSv1_2_server());
                if (this.ctx == IntPtr.Zero)
                {
                    throw new NullReferenceException("Cant create context");
                }

                if (!File.Exists(this.config.CertificateFile))
                {
                    throw new FileNotFoundException($"Certificate file {this.config.CertificateFile} does not exist");
                }

                if (!File.Exists(this.config.PrivateKeyFile))
                {
                    throw new FileNotFoundException($"Private key file {this.config.PrivateKeyFile} does not exist");
                }

                if (!File.Exists(this.config.CAFile))
                {
                    throw new FileNotFoundException($"Certificate file {this.config.CAFile} does not exist");
                }

                this.CallErrorAwareCtxFunction(() => wolfssl.CTX_use_certificate_file(this.ctx, this.config.CertificateFile, wolfssl.SSL_FILETYPE_PEM),
                    nameof(wolfssl.CTX_use_certificate_file));
                this.CallErrorAwareCtxFunction(() => wolfssl.CTX_use_PrivateKey_file(this.ctx, this.config.PrivateKeyFile, wolfssl.SSL_FILETYPE_PEM), nameof(wolfssl.CTX_use_PrivateKey_file));
                this.CallErrorAwareCtxFunction(() => wolfssl.CTX_load_verify_locations(this.ctx, this.config.CAFile, null), nameof(wolfssl.CTX_load_verify_locations));
                this.CallErrorAwareCtxFunction(() => wolfssl.CTX_set_verify(this.ctx, wolfssl.SSL_VERIFY_FAIL_IF_NO_PEER_CERT | wolfssl.SSL_VERIFY_PEER, (_, _) => wolfssl.SUCCESS), nameof(wolfssl.CTX_set_verify));
            }
            catch (Exception)
            {
                this.CleanContext();
                throw;
            }
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

        private void CleanContext()
        {
            if (this.ctx != IntPtr.Zero)
            {
                wolfssl.CTX_free(this.ctx);
                this.ctx = IntPtr.Zero;
            }
        }

        public void Dispose()
        {
            /*socket?.Dispose();
            receivingTask?.Dispose();
            cts?.Dispose();*/
        }
    }
}
