﻿/*
 * Copyright (c) 2011-2014, Longxiang He <helongxiang@smeshlink.com>,
 * SmeshLink Technology Co.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY.
 * 
 * This file is part of the CoAP.NET, a CoAP framework in C#.
 * Please see README for more information.
 */

using System;
using System.Collections.Concurrent;
using System.Threading;
using WdIoT.Platform.Coap.Net;

namespace WdIoT.Platform.Coap.Deduplication
{
    class CropRotation : IDeduplicator, IDisposable
    {
        private ConcurrentDictionary<Exchange.KeyID, Exchange>[] _maps;
        private Int32 _first;
        private Int32 _second;
        private Timer _timer;
        private ICoapConfig _coapConfig;

        public CropRotation(ICoapConfig config)
        {
            _maps = new ConcurrentDictionary<Exchange.KeyID, Exchange>[3];
            _maps[0] = new ConcurrentDictionary<Exchange.KeyID, Exchange>();
            _maps[1] = new ConcurrentDictionary<Exchange.KeyID, Exchange>();
            _maps[2] = new ConcurrentDictionary<Exchange.KeyID, Exchange>();
            _first = 0;
            _second = 1;
            _coapConfig = config;
        }

        private void Rotation(object state)
        {
            Int32 third = _first;
            _first = _second;
            _second = (_second + 1) % 3;
            _maps[third].Clear();
        }

        /// <inheritdoc/>
        public void Start()
        {
            _timer = new Timer(Rotation, null, _coapConfig.CropRotationPeriod, _coapConfig.CropRotationPeriod);
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
            _maps[0].Clear();
            _maps[1].Clear();
            _maps[2].Clear();
        }

        /// <inheritdoc/>
        public Exchange FindPrevious(Exchange.KeyID key, Exchange exchange)
        {
            Int32 f = _first, s = _second;
            Exchange prev = null;
            
            _maps[f].AddOrUpdate(key, exchange, (k, v) =>
            {
                prev = v;
                return exchange;
            });
            if (prev != null || f == s)
                return prev;

            prev = _maps[s].AddOrUpdate(key, exchange, (k, v) =>
            {
                prev = v;
                return exchange;
            });
            return prev;
        }

        /// <inheritdoc/>
        public Exchange Find(Exchange.KeyID key)
        {
            Int32 f = _first, s = _second;
            Exchange prev;
            if (_maps[f].TryGetValue(key, out prev) || f == s)
                return prev;
            _maps[s].TryGetValue(key, out prev);
            return prev;
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            _timer?.Dispose();
        }
    }
}
