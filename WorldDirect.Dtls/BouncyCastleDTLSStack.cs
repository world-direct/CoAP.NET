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
        private readonly DTLSServer server;

        public BouncyCastleDTLSStack(DTLSConfig config, IMemoryCache cache, IServiceProvider serviceProvider, ILogger<BouncyCastleDTLSStack> logger)
        {
            this.config = config;
            this.logger = logger;
            this.server = new DTLSServer(config.Port, config.Timeout, cache, serviceProvider);
            this.server.ReceivedData += Server_ReceivedData;
        }

        private void Server_ReceivedData(object? sender, ReceivedDTLSPacketEventArgs e)
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
            this.server.Start();
        }

        public void Stop()
        {
            this.server.Stop();
        }

        public void SendTo(byte[] message, IPEndPoint remote)
        {
            this.logger.LogTrace("Sends {bytes} decrypted bytes to {remote}", message.Length, remote);
            this.server.SendTo(message, remote);
        }
    }
}
