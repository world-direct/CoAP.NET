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

using WdIoT.Platform.Coap.Net;

namespace WdIoT.Platform.Coap.Deduplication
{
    /// <summary>
    /// A dummy implementation that does no deduplication.
    /// </summary>
    class NoopDeduplicator : IDeduplicator
    {
        /// <inheritdoc/>
        public void Start()
        {
            // do nothing
        }

        /// <inheritdoc/>
        public void Stop()
        {
            // do nothing
        }

        /// <inheritdoc/>
        public void Clear()
        {
            // do nothing
        }

        /// <inheritdoc/>
        public Exchange FindPrevious(Exchange.KeyID key, Exchange exchange)
        {
            return null;
        }

        /// <inheritdoc/>
        public Exchange Find(Exchange.KeyID key)
        {
            return null;
        }
    }
}
