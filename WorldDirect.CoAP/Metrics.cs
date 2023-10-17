namespace WorldDirect.CoAP
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.Tracing;
    using System.Text;
    using System.Threading;

    [EventSource(Name = "WorldDirect.CoAP")]
    internal sealed class Metrics : EventSource
    {
        /// <summary>
        /// The provider to collect CoAP metrics.
        /// </summary>
        public static readonly Metrics Log = new Metrics();

        private IncrementingPollingCounter sendingBytesRate;
        private IncrementingPollingCounter receivedBytesRate;
        private long totalTransmittedBytes;
        private long totalReceivedBytes;

        public void BytesTransmitted(int bytes)
        {
            Interlocked.Add(ref this.totalTransmittedBytes, bytes);
        }

        public void BytesReceived(int bytes)
        {
            Interlocked.Add(ref this.totalReceivedBytes, bytes);
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="T:System.Diagnostics.Tracing.EventSource" /> class and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing"><see langword="true" /> to release both managed and unmanaged resources; <see langword="false" /> to release only unmanaged resources.</param>
        protected override void Dispose(bool disposing)
        {
            this.sendingBytesRate?.Dispose();
            this.sendingBytesRate = null;

            this.receivedBytesRate?.Dispose();
            this.receivedBytesRate = null;

            base.Dispose(disposing);
        }

        /// <summary>
        /// Called when the current event source is updated by the controller.
        /// </summary>
        /// <param name="command">The arguments for the event.</param>
        protected override void OnEventCommand(EventCommandEventArgs command)
        {
            if (command.Command == EventCommand.Enable)
            {
                this.sendingBytesRate ??= new IncrementingPollingCounter("udp-sent-bytes-rate", this, () => Volatile.Read(ref this.totalTransmittedBytes))
                {
                    DisplayName = "UDP Sent bytes",
                    DisplayUnits = "bytes/s",
                };

                this.receivedBytesRate ??= new IncrementingPollingCounter("udp-received-bytes-rate", this, () => Volatile.Read(ref this.totalReceivedBytes))
                {
                    DisplayName = "UDP Received bytes",
                    DisplayUnits = "bytes/s",
                };
            }
        }
    }
}
