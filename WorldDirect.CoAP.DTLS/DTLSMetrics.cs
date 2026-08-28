namespace WorldDirect.CoAP.DTLS
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.Tracing;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    [EventSource(Name = "WorldDirect.CoAP.DTLS")]
    public sealed class DTLSMetrics : EventSource
    {
        /// <summary>
        /// The provider to collect DTLS metrics.
        /// </summary>
        public static readonly DTLSMetrics Log = new ();

        private PollingCounter? activeSessionsCounter;
        private PollingCounter? failedHandshakesCounter;

        private long activeSessions;
        private long failedHandshakes;

        private DTLSMetrics()
        {

        }

        public void SessionAdded()
        {
            Interlocked.Increment(ref this.activeSessions);
        }

        public void SessionRemoved()
        {
            Interlocked.Decrement(ref this.activeSessions);
        }

        public void HandshakeFailed()
        {
            Interlocked.Increment(ref this.failedHandshakes);
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="T:System.Diagnostics.Tracing.EventSource" /> class and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing"><see langword="true" /> to release both managed and unmanaged resources; <see langword="false" /> to release only unmanaged resources.</param>
        protected override void Dispose(bool disposing)
        {
            this.activeSessionsCounter?.Dispose();
            this.activeSessionsCounter = null;

            this.failedHandshakesCounter?.Dispose();
            this.failedHandshakesCounter = null;
        }

        /// <summary>
        /// Called when the current event source is updated by the controller.
        /// </summary>
        /// <param name="command">The arguments for the event.</param>
        protected override void OnEventCommand(EventCommandEventArgs command)
        {
            if (command.Command == EventCommand.Enable)
            {
                this.activeSessionsCounter ??= new PollingCounter("dtls-active-sessions", this, () => Volatile.Read(ref this.activeSessions))
                {
                    DisplayName = "Active DTLS Sessions"
                };

                this.failedHandshakesCounter ??= new PollingCounter("dtls-failed-handshakes", this, () => Volatile.Read(ref this.failedHandshakes))
                {
                    DisplayName = "Failed DTLS Handshakes"
                };
            }
        }
    }
}
