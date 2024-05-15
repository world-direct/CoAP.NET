namespace WorldDirect.CoAP
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Text;

    public static class Tracing
    {
        public static readonly string ActivityName = "WorldDirect.CoAP";
        /// <summary>
        /// The activity source for the tracing client events.
        /// </summary>
        internal static readonly ActivitySource ClientSource = new ActivitySource(ActivityName, "1.0.0");

        /// <summary>
        /// The activity source for the tracing events.
        /// </summary>
        internal static readonly ActivitySource ServerSource = new ActivitySource(ActivityName, "1.0.0");
    }
}
