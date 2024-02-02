namespace WorldDirect.CoAP
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Text;

    internal static class Tracing
    {
        public static readonly string ClientActivityName = "WorldDirect.CoAP.Client";
        public static readonly string ServerActivityName = "WorldDirect.CoAP.Server";
        /// <summary>
        /// The activity source for the tracing client events.
        /// </summary>
        internal static readonly ActivitySource ClientSource = new ActivitySource(ClientActivityName, "1.0.0");

        /// <summary>
        /// The activity source for the tracing events.
        /// </summary>
        internal static readonly ActivitySource ServerSource = new ActivitySource(ServerActivityName, "1.0.0");
    }
}
