namespace WorldDirect.CoAP.DTLS
{
    using System.Net;
    using Channel;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Caching.Memory;
    using Microsoft.Extensions.Logging;
    using WorldDirect.CoAP.Log;

    /// <summary>
    /// Represents the dtls channel for a coap communication.
    /// </summary>
    public class DTLSChannel : IChannel
    {
        private readonly UDPChannel channel;
        private readonly DTLSSessionManager sessionManager;
        private readonly ILogger<DTLSChannel> logger = LogManager.GetLogger<DTLSChannel>();

        /// <summary>
        /// Initializes a new instance of the <see cref="DTLSChannel"/> class.
        /// </summary>
        /// <param name="channel">The underlying udp channel used to send/receive data.</param>
        /// <param name="cache">The cache to store dtls sessions.</param>
        /// <param name="dtlsConfig">The configuration of the dtls server.</param>
        /// <param name="sessionTimeout">The timeout after which a session is deleted.</param>
        public DTLSChannel(UDPChannel channel, IMemoryCache cache, DTLSServerConfig dtlsConfig, TimeSpan sessionTimeout)
        {
            this.channel = channel;
            this.channel.DataReceived += DtlsReceived;
            var config = new DTLSSessionConfig() { MaxPacketLength = channel.ReceivePacketSize, SessionTimeout = sessionTimeout, HandshakeTimeout = dtlsConfig.HandshakeTimeout,};
            this.sessionManager = new DTLSSessionManager(cache, new UdpChannelSender(channel), dtlsConfig, config);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DTLSChannel"/> class.
        /// </summary>
        /// <param name="channel">The underlying udp channel used to send/receive data.</param>
        /// <param name="cache">The cache to store dtls sessions.</param>
        /// <param name="dtlsConfig">The configuration of the dtls server.</param>
        public DTLSChannel(UDPChannel channel, IMemoryCache cache, DTLSServerConfig dtlsConfig)
        : this(channel, cache, dtlsConfig, TimeSpan.FromMinutes(2))
        {
        }

        private void DtlsReceived(object? sender, DataReceivedEventArgs e)
        {
            Task.Factory.StartNew(() => this.sessionManager.ReceivedUdpPacket(e.Data, e.EndPoint)).ConfigureAwait(false);
        }

        /// <inheritdoc />
        public void Dispose()
        {
            this.Stop();
        }

        /// <inheritdoc />
        public EndPoint LocalEndPoint => this.channel.LocalEndPoint;

        /// <inheritdoc />
        public event EventHandler<DataReceivedEventArgs>? DataReceived;

        /// <summary>
        /// An event to forward dtls relevant data with a received message.
        /// </summary>
        public event EventHandler<DTLSDataReceivedEventArgs>? DtlsDataReceived;

        /// <inheritdoc />
        public void Start()
        {
            this.channel.Start();
            this.sessionManager.DataReceived += DecryptedForwarding;
        }

        /// <inheritdoc />
        public void Stop()
        {
            this.channel.Stop();
            this.sessionManager.Stop();
        }

        /// <inheritdoc />
        public void Send(byte[] data, EndPoint ep)
        {
            try
            {
                this.logger.LogTrace("Sending {Bytes} decrypted bytes to {Remote}", data.Length, ep);
                this.sessionManager.SendTo(data, ep);
            }
            catch (Exception e)
            {
                this.logger.LogError(e, "Could not send data to {Remote}", ep);
            }
        }

        private void DecryptedForwarding(object? sender, DTLSDataReceivedEventArgs e)
        {
            this.logger.LogTrace("Received {Bytes} decrypted bytes from {Remote}", e.Data.Length, e.EndPoint);
            this.DataReceived?.Invoke(this, e);
            this.DtlsDataReceived?.Invoke(this, e);
        }
    }
}
