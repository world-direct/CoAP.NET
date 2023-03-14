namespace WorldDirect.CoAP.Channel
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Text;
    using Net;

    public class DTLSChannel: IChannel
    {
        private readonly IDTLSStack stack;
        public void Dispose()
        {
            stack.Dispose();
        }

        public EndPoint LocalEndPoint => this.stack.LocalEndPoint;

        public event EventHandler<DataReceivedEventArgs> DataReceived;

        public DTLSChannel(IDTLSStack stack)
        {
            this.stack = stack;
            this.stack.ReceivedData += ReceivedUdpData;
        }

        private void ReceivedUdpData(object sender, DTLSDecryptedDataReceivedEventArgs e)
        {
            this.DataReceived?.Invoke(this, new DataReceivedEventArgs(e.Payload, e.Remote.Remote));
        }

        public void Start()
        {
            this.stack.Start();
        }

        public void Stop()
        {
            this.stack.Stop();
        }

        public void Send(byte[] data, EndPoint ep)
        {
            this.stack.SendTo(data, ep as IPEndPoint);
        }
    }
}
