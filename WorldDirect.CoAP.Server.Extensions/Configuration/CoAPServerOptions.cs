namespace WorldDirect.CoAP.Server.Extensions.Configuration
{
    using System.Collections.Generic;

    public class CoAPServerOptions
    {

        internal CoAPServerOptions(IEnumerable<ListenOption> listenOptions)
        {
            this.ListenOptions = listenOptions;
        }

        public IEnumerable<ListenOption> ListenOptions { get; }

        public int MaxMessageSize { get; set; } = 1024;
    }
}
