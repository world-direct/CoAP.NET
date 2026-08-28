namespace WorldDirect.CoAP.Hosting.Hosting
{
    using OpenTelemetry.Trace;

    /// <summary>
    /// Extensions for the <see cref="TracerProviderBuilder"/>.
    /// </summary>
    public static class TraceProviderBuilderExtensions
    {
        /// <summary>
        /// Add the coap instrumentation to tracing.
        /// </summary>
        /// <param name="builder">The trace builder.</param>
        /// <returns>The trace builder.</returns>
        public static TracerProviderBuilder AddCoAPInstrumentation(this TracerProviderBuilder builder)
        {
            builder.AddSource(Tracing.ActivityName);
            return builder;
        }
    }
}
