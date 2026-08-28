/*
 * Copyright (c) 2011-2014, Longxiang He <helongxiang@smeshlink.com>,
 * SmeshLink Technology Co.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY.
 * 
 * This file is part of the CoAP.NET, a CoAP framework in C#.
 * Please see README for more information.
 */

namespace WorldDirect.CoAP.Deduplication
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Net;
    using System.Threading;
    using Log;
    using Microsoft.Extensions.Logging;
    using Net;

    class SweepDeduplicator : IDeduplicator
    {
        static readonly ILogger<SweepDeduplicator> log = LogManager.GetLogger<SweepDeduplicator>();

        private ConcurrentDictionary<Exchange.KeyID, Exchange> _incomingMessages = new ConcurrentDictionary<Exchange.KeyID, Exchange>();
        private ConcurrentDictionary<Exchange.KeyID, Exchange> _outgoingMessages = new ConcurrentDictionary<Exchange.KeyID, Exchange>();
        
        private Timer _timer;
        private ICoapConfig _config;

        public SweepDeduplicator(ICoapConfig config)
        {
            _config = config;
        }

        private void Sweep(object state)
        {
            log.LogTrace("Start Mark-And-Sweep with " + (_incomingMessages.Count + _outgoingMessages.Count) + " entries");

            this.Sweep(this._incomingMessages);
            this.Sweep(this._outgoingMessages);
        }

        private void Sweep(ConcurrentDictionary<Exchange.KeyID, Exchange> dict)
        {
            DateTime oldestAllowed = DateTime.Now.AddMilliseconds(-_config.ExchangeLifetime);
            List<Exchange.KeyID> keysToRemove = new List<Exchange.KeyID>();
            foreach (KeyValuePair<Exchange.KeyID, Exchange> pair in dict)
            {
                if (pair.Value.Timestamp < oldestAllowed)
                {
                    log.LogTrace("Mark-And-Sweep removes " + pair.Key);
                    keysToRemove.Add(pair.Key);
                }
            }
            if (keysToRemove.Count > 0)
            {
                Exchange ex;
                foreach (Exchange.KeyID key in keysToRemove)
                {
                    dict.TryRemove(key, out ex);
                }
            }
        }

        /// <inheritdoc/>
        public void Start()
        {
            _timer = new Timer(Sweep, null, TimeSpan.FromMilliseconds(_config.MarkAndSweepInterval), TimeSpan.FromMilliseconds(_config.MarkAndSweepInterval));
        }

        /// <inheritdoc/>
        public void Stop()
        {
            Dispose();
            Clear();
        }

        /// <inheritdoc/>
        public void Clear()
        {
            _incomingMessages.Clear();
        }

        /// <inheritdoc/>
        public Exchange FindPrevious(Exchange.KeyID key, Exchange exchange)
        {

            Exchange prev = null;
            if (exchange.Origin == Origin.Local)
            {
                _outgoingMessages.AddOrUpdate(key, exchange, (k, v) =>
                {
                    prev = v;
                    return exchange;
                });
            }
            else
            {
                _incomingMessages.AddOrUpdate(key, exchange, (k, v) =>
                {
                    prev = v;
                    return exchange;
                });
            }
            return prev;
        }

        /// <inheritdoc/>
        public Exchange Find(Exchange.KeyID key)
        {
            Exchange prev;
            _outgoingMessages.TryGetValue(key, out prev);
            return prev;
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            _timer?.Dispose();
        }
    }
}
