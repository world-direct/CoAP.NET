namespace WorldDirect.CoAP.Net
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Net;
    using System.Text;
    using System.Threading;
    using System.Transactions;
    using Log;
    using Microsoft.Extensions.Logging;

    internal struct MessageIdState
    {

        public DateTime LastUsed { get; set; }
        public int Id { get; set; }

        public void Inc()
        {
            this.Id = (this.Id + 1) % (1 << 16);
            this.LastUsed = DateTime.Now;
        }

        public static MessageIdState Create()
        {
            return new MessageIdState() {Id = new Random((int)DateTimeOffset.Now.Ticks).Next() % (1 << 16), LastUsed = DateTime.Now,};
        }
    }

    public class MessageIdProvider : IDisposable
    {
        private Timer _timer;
        private ICoapConfig _config;
        private ConcurrentDictionary<EndPoint, MessageIdState> state = new ConcurrentDictionary<EndPoint, MessageIdState>();

        public MessageIdProvider(ICoapConfig config)
        {
            this._config = config;
        }

        public int Get(EndPoint ep)
        {
            var cur = this.state.AddOrUpdate(ep, (_) => MessageIdState.Create(), (endpoint, current) =>
            {
                current.Inc();
                return current;
            });

            return cur.Id;
        }

        public void Start()
        {
            _timer = new Timer(Clean, null, TimeSpan.FromMilliseconds(_config.MarkAndSweepInterval), TimeSpan.FromMilliseconds(_config.MarkAndSweepInterval));
        }

        public void Stop()
        {
            Dispose();
            Clear();
        }

        public void Dispose()
        {
            _timer?.Dispose();
        }

        private void Clean(object _)
        {
            DateTime oldestAllowed = DateTime.Now.AddMilliseconds(-_config.ExchangeLifetime);
            foreach (var kvp in this.state)
            {
                if (kvp.Value.LastUsed < oldestAllowed)
                {
                    this.state.TryRemove(kvp.Key, out var _);
                }
            }
        }

        private void Clear()
        {
            this.state.Clear();
        }
    }
}
