namespace WorldDirect.CoAP
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Text;

    internal static class Tracing
    {
        /// <summary>
        /// The activity source for the tracing client events.
        /// </summary>
        internal static readonly ActivitySource ClientSource = new ActivitySource("WorldDirect.CoAP.Client", "1.0.0");

        /// <summary>
        /// The activity source for the tracing events.
        /// </summary>
        internal static readonly ActivitySource ServerSource = new ActivitySource("WorldDirect.CoAP.Server", "1.0.0");
    }
}
