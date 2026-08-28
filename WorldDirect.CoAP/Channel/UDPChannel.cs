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

namespace WorldDirect.CoAP.Channel
{
    using System;
    using System.Collections.Concurrent;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
    using Log;
    using Microsoft.Extensions.Logging;

    /// <summary>
    /// Channel via UDP protocol.
    /// </summary>
    public partial class UDPChannel : IChannel
    {

        private readonly ILogger<UDPChannel> log = LogManager.GetLogger<UDPChannel>();

        /// <summary>
        /// Default size of buffer for receiving packet.
        /// </summary>
        public const Int32 DefaultReceivePacketSize = 4096;
        private Int32 _receiveBufferSize;
        private Int32 _sendBufferSize;
        private Int32 _receivePacketSize = DefaultReceivePacketSize;
        private Int32 _port;
        private System.Net.EndPoint _localEP;
        private UDPSocket _socket;
        private UDPSocket _socketBackup;
        private Int32 _running;
        private readonly object sendLock;
        private bool _writing;
        private readonly ConcurrentQueue<RawData> _sendingQueue = new ConcurrentQueue<RawData>();

        /// <inheritdoc/>
        public event EventHandler<DataReceivedEventArgs> DataReceived;

        /// <summary>
        /// Initializes a UDP channel with a random port.
        /// </summary>
        public UDPChannel()
            : this(0)
        {
        }

        /// <summary>
        /// Initializes a UDP channel with the given port, both on IPv4 and IPv6.
        /// </summary>
        public UDPChannel(Int32 port)
        {
            _port = port;
            this.sendLock = new object();
        }

        /// <summary>
        /// Initializes a UDP channel with the specific endpoint.
        /// </summary>
        public UDPChannel(System.Net.EndPoint localEP)
        {
            this.sendLock = new object();
            _localEP = localEP;
        }

        /// <inheritdoc/>
        public System.Net.EndPoint LocalEndPoint
        {
            get
            {
                return _socket == null
                    ? (_localEP ?? new IPEndPoint(IPAddress.IPv6Any, _port))
                    : _socket.Socket.LocalEndPoint;
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="Socket.ReceiveBufferSize"/>.
        /// </summary>
        public Int32 ReceiveBufferSize
        {
            get { return _receiveBufferSize; }
            set { _receiveBufferSize = value; }
        }

        /// <summary>
        /// Gets or sets the <see cref="Socket.SendBufferSize"/>.
        /// </summary>
        public Int32 SendBufferSize
        {
            get { return _sendBufferSize; }
            set { _sendBufferSize = value; }
        }

        /// <summary>
        /// Gets or sets the size of buffer for receiving packet.
        /// The default value is <see cref="DefaultReceivePacketSize"/>.
        /// </summary>
        public Int32 ReceivePacketSize
        {
            get { return _receivePacketSize; }
            set { _receivePacketSize = value; }
        }

        /// <summary>
        /// Gets or sets the packet size that should be reported and logged to investigate how large messages are created.
        /// The default value is 1500.
        /// </summary>
        public Int32 ReceivePacketSizeToReport { get; set; } = 1500;

        /// <inheritdoc/>
        public void Start()
        {
            if (System.Threading.Interlocked.CompareExchange(ref _running, 1, 0) > 0)
                return;

            if (_localEP == null)
            {
                try
                {
                    _socket = SetupUDPSocket(AddressFamily.InterNetworkV6, _receivePacketSize + 1); // +1 to check for > ReceivePacketSize
                }
                catch (SocketException e)
                {
                    if (e.SocketErrorCode == SocketError.AddressFamilyNotSupported)
                        _socket = null;
                    else
                        throw e;
                }

                if (_socket == null)
                {
                    // IPv6 is not supported, use IPv4 instead
                    _socket = SetupUDPSocket(AddressFamily.InterNetwork, _receivePacketSize + 1);
                    _socket.Socket.Bind(new IPEndPoint(IPAddress.Any, _port));
                }
                else
                {
                    try
                    {
                        // Enable IPv4-mapped IPv6 addresses to accept both IPv6 and IPv4 connections in a same socket.
                        _socket.Socket.SetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)27, 0);
                    }
                    catch
                    {
                        // IPv4-mapped address seems not to be supported, set up a separated socket of IPv4.
                        _socketBackup = SetupUDPSocket(AddressFamily.InterNetwork, _receivePacketSize + 1);
                    }

                    _socket.Socket.Bind(new IPEndPoint(IPAddress.IPv6Any, _port));
                    if (_socketBackup != null)
                        _socketBackup.Socket.Bind(new IPEndPoint(IPAddress.Any, _port));
                }
            }
            else
            {
                _socket = SetupUDPSocket(_localEP.AddressFamily, _receivePacketSize + 1);
                _socket.Socket.Bind(_localEP);
            }

            if (_receiveBufferSize > 0)
            {
                _socket.Socket.ReceiveBufferSize = _receiveBufferSize;
                if (_socketBackup != null)
                    _socketBackup.Socket.ReceiveBufferSize = _receiveBufferSize;
            }
            if (_sendBufferSize > 0)
            {
                _socket.Socket.SendBufferSize = _sendBufferSize;
                if (_socketBackup != null)
                    _socketBackup.Socket.SendBufferSize = _sendBufferSize;
            }

            BeginReceive();
        }

        /// <inheritdoc/>
        public void Stop()
        {
            if (System.Threading.Interlocked.Exchange(ref _running, 0) == 0)
                return;

            if (_socket != null)
            {
                _socket.Dispose();
                _socket = null;
            }
            if (_socketBackup != null)
            {
                _socketBackup.Dispose();
                _socketBackup = null;
            }
        }

        /// <inheritdoc/>
        public void Send(Byte[] data, System.Net.EndPoint ep)
        {
            RawData raw = new RawData();
            raw.Data = data;
            raw.EndPoint = ep;

            lock (this.sendLock)
            {
                _sendingQueue.Enqueue(raw);

                if (this._writing)
                {
                    return;
                }

                this._writing = true;
            }

            BeginSend();
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            Stop();
        }

        private void BeginReceive()
        {
            if (_running <= 0)
            {
                return;
            }

            BeginReceive(_socket);

            if (_socketBackup != null)
                BeginReceive(_socketBackup);
        }

        private void EndReceive(UDPSocket socket, Byte[] buffer, Int32 offset, Int32 count, System.Net.EndPoint ep)
        {
            if (count > 0)
            {
                Metrics.Log.BytesReceived(count);
                Byte[] bytes = new Byte[count];
                Buffer.BlockCopy(buffer, 0, bytes, 0, count);

                if (ep.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    IPEndPoint ipep = (IPEndPoint)ep;
                    if (IPAddressExtensions.IsIPv4MappedToIPv6(ipep.Address))
                        ep = new IPEndPoint(IPAddressExtensions.MapToIPv4(ipep.Address), ipep.Port);
                }

                try
                {
                    DateTimeOffset start = DateTimeOffset.Now;
                    log.LogTrace($"UDP-FireDataReceived START");
                    FireDataReceived(bytes, ep);
                    log.LogTrace("UDP-FireDataReceived END ({Duration})", DateTimeOffset.Now - start);
                }
                catch (Exception e)
                {
                    log.LogError($"FireDataReceived error occurred: {e.ToString()}", e);
                }
            }
        }

        private void FireDataReceived(Byte[] data, System.Net.EndPoint ep)
        {
            EventHandler<DataReceivedEventArgs> h = DataReceived;
            if (h != null)
                h(this, new DataReceivedEventArgs(data, ep));
        }

        private void BeginSend()
        {
            if (_running == 0)
                return;

            bool messageDequeued;
            do
            {
                messageDequeued = this._sendingQueue.TryDequeue(out var raw);

                if (!messageDequeued)
                {
                    lock (this.sendLock)
                    {
                        messageDequeued = this._sendingQueue.TryDequeue(out raw);
                        if (!messageDequeued)
                        {
                            this._writing = false;
                            continue;
                        }
                    }
                }

                var socket = _socket;
                var remoteEndPoint = (IPEndPoint)(raw).EndPoint;

                if (remoteEndPoint.AddressFamily == AddressFamily.InterNetwork)
                {
                    if (_socketBackup != null)
                    {
                        // use the separated socket of IPv4 to deal with IPv4 conversions.
                        socket = _socketBackup;
                    }
                    else if (_socket.Socket.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        remoteEndPoint = new IPEndPoint(IPAddressExtensions.MapToIPv6(remoteEndPoint.Address), remoteEndPoint.Port);
                    }
                }

                Metrics.Log.BytesTransmitted(raw.Data.Length);
                BeginSend(socket, raw.Data, remoteEndPoint);

            } while (messageDequeued);
        }

        private UDPSocket SetupUDPSocket(AddressFamily addressFamily, Int32 bufferSize)
        {
            UDPSocket socket = NewUDPSocket(addressFamily, bufferSize);

            // do not throw SocketError.ConnectionReset by ignoring ICMP Port Unreachable
            const Int32 SIO_UDP_CONNRESET = -1744830452;
            try
            {
                socket.Socket.IOControl(SIO_UDP_CONNRESET, new Byte[] { 0 }, null);
            }
            catch (Exception)
            {
                // ignore
            }
            return socket;
        }

        partial class UDPSocket : IDisposable
        {
            public readonly Socket Socket;
        }

        class RawData
        {
            public Byte[] Data;
            public System.Net.EndPoint EndPoint;
        }
    }
}
