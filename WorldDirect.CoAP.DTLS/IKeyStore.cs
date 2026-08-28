namespace WorldDirect.CoAP.DTLS
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    /// <summary>
    /// Provides an interface to store session keys.
    /// </summary>
    public interface IKeyStore
    {
        /// <summary>
        /// Store the data.
        /// </summary>
        /// <param name="data">The data to write.</param>
        void Store(DTLS12KeyFileData data);
    }
}
