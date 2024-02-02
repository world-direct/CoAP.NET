namespace WorldDirect.CoAP.DTLS
{
    using System;
    using System.Net;
    using System.Text;
    using Channel;
    using LazyCache;
    using Microsoft.Extensions.Caching.Memory;
    using Microsoft.Extensions.Internal;
    using Microsoft.Extensions.Logging;
    using Org.BouncyCastle.Asn1.Nist;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Tls.Crypto.Impl.BC;
    using WorldDirect.CoAP.Log;

    /// <summary>
    /// Handles all dtls related traffic.
    /// </summary>
    public class DTLSSessionManager
    {
        private readonly IAppCache cache;
        private readonly IUDPSender sender;
        private readonly DTLSServerConfig dtlsServerConfig;
        private readonly DTLSSessionConfig config;
        private readonly ILogger<DTLSSessionManager> log = LogManager.GetLogger<DTLSSessionManager>();

        /// <summary>
        /// Initializes a new instance of the <see cref="DTLSSessionManager"/> class.
        /// </summary>
        /// <param name="cache">A cache to store the sessions.</param>
        /// <param name="sender">An object to send udp packets.</param>
        /// <param name="dtlsServerConfig">The configuration of the dtls server.</param>
        /// <param name="config">The configuration for the sessions.</param>
        public DTLSSessionManager(IAppCache cache, IUDPSender sender, DTLSServerConfig dtlsServerConfig, DTLSSessionConfig config)
        {
            this.cache = cache;
            this.sender = sender;
            this.dtlsServerConfig = dtlsServerConfig;
            this.config = config;
        }

        /// <summary>
        /// An event to notify listener a new decrypted udp packet was received.
        /// </summary>
        public event EventHandler<DTLSDataReceivedEventArgs>? DataReceived;

        /// <summary>
        /// Send a udp packet encrypted to the remote endpoint.
        /// </summary>
        /// <param name="packet">The packet to encrypt and send.</param>
        /// <param name="endPoint">The remote endpoint.</param>
        public void SendTo(ReadOnlySpan<byte> packet, EndPoint endPoint)
        {
            // cache.TryGetValue does not work (always returns false with null object...)
            var session = this.cache.Get<DTLSSession>(GetKey(endPoint));
            if (session != null)
            {
                session.Send(packet);
                return;
            }

            this.log.LogWarning("Tried to send data to {Remote} but no session available", endPoint);
        }

        /// <summary>
        /// Stops the manager.
        /// </summary>
        public void Stop()
        {
            
        }

        /// <summary>
        /// A udp packet was received for a session.
        /// </summary>
        /// <param name="packet">The received packet.</param>
        /// <param name="endPoint">The endpoint who sent the packet.</param>
        internal void ReceivedUdpPacket(ReadOnlySpan<byte> packet, EndPoint endPoint)
        {
            var session = this.cache.GetOrAdd(GetKey(endPoint), entry =>
            {
                entry.SlidingExpiration = config.SessionTimeout;
                var callback = new PostEvictionCallbackRegistration()
                {
                    EvictionCallback = OnEviction,
                    State = this
                };
                entry.PostEvictionCallbacks.Add(callback);
                entry.Priority = CacheItemPriority.NeverRemove;

                var s = new DTLSSession(this.sender, new DTLSServer(this.dtlsServerConfig), endPoint, this.config);
                s.DataReceived += DecryptedReceived;
                s.HandshakeFinished += HandshakeFinished;
                this.log.LogDebug("Start DTLS connection with {Remote}", endPoint);
                s.Start();
                DTLSMetrics.Log.SessionAdded();
                return s;
            });
            this.log.LogTrace("Received {Bytes} encrypted Bytes from {Remote}", packet.Length, endPoint);
            session.Enqueue(packet);
        }

        private void HandshakeFinished(object? sender, HandshakeFinishedEventArgs e)
        {
            var session = (sender as DTLSSession)!;
            if (!e.Successful)
            {
                DTLSMetrics.Log.HandshakeFailed();
                this.cache.Remove(session.Remote.ToString());
            }
        }

        private void DecryptedReceived(object? _, DTLSDataReceivedEventArgs e)
        {
            this.DataReceived?.Invoke(this, e);
        }

        private static string GetKey(EndPoint remote)
        {
            return $"dtlssession_{remote}";
        }

        private static void OnEviction(object key, object value, EvictionReason reason, object state)
        {
            var manager = (DTLSSessionManager)state;
            var obj = value as DTLSSession;
            manager.log.LogDebug("Session with {Remote} timed out", obj.Remote);
            DTLSMetrics.Log.SessionRemoved();
        }
    }
}
