namespace WorldDirect.Dtls
{
    public class DTLSConfig
    {
        public ushort Port { get; set; }
        public string CertificateFile { get; set; }
        public string PrivateKeyFile { get; set; }
        public string CAFile { get; set; }

        public int BufferSize { get; set; }
        public TimeSpan Timeout { get; set; }
    }
}


