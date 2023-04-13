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

    public class DTLSChannel : IChannel
    {
        private readonly UDPChannel channel;
        private readonly DTLSSessionManager sessionManager;

        public DTLSChannel(UDPChannel channel, IMemoryCache cache, IDTLSFactory factory)
        {
            this.channel = channel;
            this.channel.DataReceived += DtlsReceived;
            // todo configure sessiontimeout
            var config = new DTLSSessionConfig() {MaxPacketLength = channel.ReceivePacketSize, SessionTimeout = TimeSpan.FromMinutes(3),};
            this.sessionManager = new DTLSSessionManager(cache, new UdpChannelSender(channel), factory, config);
        }

        private void DtlsReceived(object? sender, DataReceivedEventArgs e)
        {
            this.sessionManager.ReceivedUdpPacket(e.Data, e.EndPoint);
        }

        public void Dispose()
        {
            this.Stop();
        }

        public EndPoint LocalEndPoint => this.channel.LocalEndPoint;
        public event EventHandler<DataReceivedEventArgs>? DataReceived;
        public void Start()
        {
            this.channel.Start();
            this.sessionManager.DataReceived += DecryptedForwarding;
        }

        public void Stop()
        {
            this.channel.Stop();
            this.sessionManager.Stop();
        }

        public void Send(byte[] data, EndPoint ep)
        {
            this.sessionManager.SendTo(data, ep);
        }

        private void DecryptedForwarding(object? sender, DataReceivedEventArgs e)
        {
            this.DataReceived?.Invoke(this, e);
        }
    }
}
