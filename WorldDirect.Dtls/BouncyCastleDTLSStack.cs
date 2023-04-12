namespace WorldDirect.Dtls
{
    using System;
    using System.Net;
    using System.Text;
    using CoAP.Net;
    using Microsoft.Extensions.Caching.Memory;
    using Microsoft.Extensions.Logging;
    using WorldDirect.CoAP.Server;

    public class BouncyCastleDTLSStack : IDTLSStack
    {
        private readonly DTLSConfig config;
        private readonly ILogger<BouncyCastleDTLSStack> logger;
        private readonly DTLSSessionManager sessionManager;

        public BouncyCastleDTLSStack(DTLSConfig config, IMemoryCache cache, IServiceProvider serviceProvider, ILogger<BouncyCastleDTLSStack> logger)
        {
            this.config = config;
            this.logger = logger;
            this.sessionManager = new DTLSSessionManager(config.Port, config.Timeout, cache, serviceProvider);
            this.sessionManager.ReceivedData += SessionManagerReceivedData;
        }

        private void SessionManagerReceivedData(object? sender, ReceivedAuthenticatedPacketEventArgs e)
        {
            var client = new DTLSClient(e.Remote);
            client.PublicIdentifier = e.PublicIdentifier;
            this.logger.LogTrace("Received {bytes} decrypted bytes from {remote}", e.Payload.Length, e.Remote);
            this.ReceivedData?.Invoke(this, new DTLSDecryptedDataReceivedEventArgs(client, e.Payload));
        }

        public event EventHandler<DTLSDecryptedDataReceivedEventArgs>? ReceivedData;
        public EndPoint LocalEndPoint { get; }
        public void Start()
        {
            this.sessionManager.Start();
        }

        public void Stop()
        {
            this.sessionManager.Stop();
        }

        public void SendTo(byte[] message, IPEndPoint remote)
        {
            this.logger.LogTrace("Sends {bytes} decrypted bytes to {remote}", message.Length, remote);
            this.sessionManager.SendTo(message, remote);
        }
    }
}
