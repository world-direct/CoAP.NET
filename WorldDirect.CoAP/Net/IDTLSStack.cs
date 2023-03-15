namespace WorldDirect.CoAP.Net
{
    using System;
    using System.Net;
    using System.Security.Cryptography.X509Certificates;

    public class DTLSDecryptedDataReceivedEventArgs
    {
        public DTLSDecryptedDataReceivedEventArgs(DTLSClient remote, byte[] payload)
        {
            this.Remote = remote;
            this.Payload = payload;
        }
        public DTLSClient Remote { get; }
        public byte[] Payload { get; }
    }

    public class DTLSClient
    {
        public DTLSClient(IPEndPoint remote)
        {
            this.Remote = remote;
            this.Certificate = null;
            this.PublicIdentifier = string.Empty;
        }

        public IPEndPoint Remote { get; private set; }

        public X509Certificate Certificate { get; set; }

        public string PublicIdentifier { get; set; }
    }

    public interface IDTLSStack
    {
        //public event EventHandler ClientConnected;
        //public event EventHandler ClientDisconnected;
        event EventHandler<DTLSDecryptedDataReceivedEventArgs> ReceivedData;

        EndPoint LocalEndPoint { get; }

        void Start();
        void Stop();

        void SendTo(byte[] message, IPEndPoint remote);
    }
}
