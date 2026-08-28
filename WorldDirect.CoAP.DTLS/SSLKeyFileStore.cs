namespace WorldDirect.CoAP.DTLS
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Logging;

    /// <summary>
    /// Represents the key file store used for decrypting TLS traffic.
    /// </summary>
    public class SSLKeyFileStore : IKeyStore
    {
        private readonly string fileName;
        private readonly ILogger<SSLKeyFileStore> logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="SSLKeyFileStore"/> class.
        /// </summary>
        /// <param name="fileName">The filename to save the keys to.</param>
        public SSLKeyFileStore(string fileName, ILogger<SSLKeyFileStore> logger)
        {
            this.fileName = fileName;
            this.logger = logger;
        }

        /// <inheritdoc />
        public void Store(DTLS12KeyFileData data)
        {
            try
            {
                using var file = File.Open(this.fileName, FileMode.Append);
                using var stream = new StreamWriter(file);
                stream.WriteLine($"CLIENT_RANDOM {Convert.ToHexString(data.ClientRandom)} {Convert.ToHexString(data.PreMasterSecret)}");
            }
            catch (Exception ex)
            {
                this.logger.LogError(ex, $"Could not append session key to {this.fileName}");
            }
        }
    }
}
