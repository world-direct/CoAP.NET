namespace WorldDirect.Dtls
{
    /// <summary>
    /// Represents configuration of a DTLS server.
    /// </summary>
    public class DTLSConfig
    {
        /// <summary>
        /// Gets or sets the port to use.
        /// </summary>
        public ushort Port { get; set; }

        /// <summary>
        /// Gets or sets the path to the certificate.
        /// </summary>
        public string CertificateFile { get; set; }

        /// <summary>
        /// Gets or sets the path to the private key file.
        /// </summary>
        public string PrivateKeyFile { get; set; }

        /// <summary>
        /// Gets or sets the path to the Certificate Authority file.
        /// </summary>
        public string CAFile { get; set; }

        /// <summary>
        /// Gets or sets the maximum buffer size.
        /// </summary>
        public int BufferSize { get; set; }

        /// <summary>
        /// Gets or sets the timeout of a dtls session.
        /// </summary>
        public TimeSpan Timeout { get; set; }
    }
}


