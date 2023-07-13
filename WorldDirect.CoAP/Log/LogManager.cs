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

namespace WorldDirect.CoAP.Log
{
    using System;
    using Microsoft.Extensions.Logging;

    /// <summary>
    /// Log manager.
    /// </summary>
    public static class LogManager
    {

        static LogManager()
        {
            
        }

        public static IServiceProvider Provider { get; set; }

        /// <summary>
        /// Gets a logger for the given type.
        /// </summary>
        public static ILogger<T> GetLogger<T>()
        {
            return (ILogger<T>)Provider?.GetService(typeof(ILogger<T>));
        }

        public static ILogger GetLogger()
        {
            return (ILogger)Provider?.GetService(typeof(ILogger));
        }
    }
}
