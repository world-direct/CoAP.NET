namespace WorldDirect.CoAP.DTLS
{
    using System;
    using System.Net;
    using System.Text;
    using Channel;
    using Microsoft.Extensions.Caching.Memory;
    using Microsoft.Extensions.Internal;
    using Org.BouncyCastle.Asn1.Nist;
    using Org.BouncyCastle.Asn1.X509;

    /// <summary>
    /// Handles all dtls related traffic.
    /// </summary>
    public class DTLSSessionManager
    {
        // todo X509Certificate dotnet forwarding
        private readonly IMemoryCache cache;
        private readonly IUDPSender sender;
        private readonly IDTLSFactory factory;
        private readonly DTLSSessionConfig config;
        private readonly CancellationTokenSource cts;

        /// <summary>
        /// Initializes a new instance of the <see cref="DTLSSessionManager"/> class.
        /// </summary>
        /// <param name="cache">A cache to store the sessions.</param>
        /// <param name="config">The configuration for the sessions.</param>
        public DTLSSessionManager(IMemoryCache cache, IUDPSender sender, IDTLSFactory factory, DTLSSessionConfig config)
        {
            this.cache = cache;
            this.sender = sender;
            this.factory = factory;
            this.config = config;
            this.cts = new CancellationTokenSource();
        }

        /// <summary>
        /// An event to notify listener a new decrypted udp packet was received.
        /// </summary>
        public event EventHandler<DataReceivedEventArgs>? DataReceived;

        /// <summary>
        /// Send a udp packet encrypted to the remote endpoint.
        /// </summary>
        /// <param name="packet">The packet to encrypt and send.</param>
        /// <param name="endPoint">The remote endpoint.</param>
        public void SendTo(ReadOnlySpan<byte> packet, EndPoint endPoint)
        {
            if(this.cache.TryGetValue<DTLSSession>(endPoint, out var session))
            {
                session.Send(packet);
            }
        }

        public void Stop()
        {
            this.cts.Cancel();
        }

        /// <summary>
        /// A udp packet was received for a session.
        /// </summary>
        /// <param name="packet">The received packet.</param>
        /// <param name="endPoint">The endpoint who sent the packet.</param>
        internal void ReceivedUdpPacket(ReadOnlySpan<byte> packet, EndPoint endPoint)
        {
            var session = this.cache.GetOrCreate(endPoint, entry =>
            {
                entry.SlidingExpiration = config.SessionTimeout;
                var callback = new PostEvictionCallbackRegistration()
                {
                    EvictionCallback = OnEviction,
                };
                entry.PostEvictionCallbacks.Add(callback);

                var s = new DTLSSession(this.sender, this.factory.CreateServer(), endPoint, CancellationTokenSource.CreateLinkedTokenSource(this.cts.Token), this.config);
                s.DataReceived += DecryptedReceived;
                s.HandshakeFinished += HandshakeFinished;
                s.Start();
                return s;
            });

            session.Enqueue(packet);
        }

        private void HandshakeFinished(object? sender, HandshakeFinishedEventArgs e)
        {
            var session = (sender as DTLSSession)!;
            if (!e.Successful)
            {
                this.cache.Remove(session.Remote);
            }
        }

        private void DecryptedReceived(object? _, DataReceivedEventArgs e)
        {
            this.DataReceived?.Invoke(this, e);
        }

        private static void OnEviction(object key, object value, EvictionReason reason, object state)
        {
            var obj = value as DTLSSession;
            obj?.Cancel();
        }
    }
}
