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
    using System.Net;
    using System.Net.Sockets;
    using System.Transactions;
    using Microsoft.Extensions.Logging;

    public partial class UDPChannel
    {
        private UDPSocket NewUDPSocket(AddressFamily addressFamily, Int32 bufferSize)
        {
            return new UDPSocket(addressFamily, bufferSize, SocketAsyncEventArgs_Completed);
        }

        private void BeginReceive(UDPSocket socket)
        {
            if (_running == 0)
                throw new InvalidOperationException("The socket has not been started.");

            if (socket.ReadBuffer.RemoteEndPoint == null)
            {
                socket.ReadBuffer.RemoteEndPoint = socket.Socket.Connected ?
                    socket.Socket.RemoteEndPoint :
                    new IPEndPoint(
                        socket.Socket.AddressFamily == AddressFamily.InterNetwork ?
                        IPAddress.Any : IPAddress.IPv6Any, 0);
            }

            var completedSynchronous = true;
            while (completedSynchronous)
            {
                try
                {
                    completedSynchronous = !socket.Socket.ReceiveFromAsync(socket.ReadBuffer);

                    if (completedSynchronous)
                    {
                        ProcessReceive(socket.ReadBuffer, false);
                    }
                }
                catch (Exception e)
                {
                    _socket?.Dispose();
                }
            }
        }

        private void BeginSend(UDPSocket socket, Byte[] data, System.Net.EndPoint destination)
        {
            socket.SetWriteBuffer(data, 0, data.Length);
            socket.WriteBuffer.RemoteEndPoint = destination;

            var completedSynchronous = !socket.Socket.SendToAsync(socket.WriteBuffer);

            if (destination is IPEndPoint ep)
            {
                log.LogDebug(message: $"Sending packet to {ep.Address.MapToIPv4()}:{ep.Port}. Processing package {(completedSynchronous ? "asynchronous" : "synchronous")}");
            }

            if (completedSynchronous)
            {
                ProcessSend(socket.WriteBuffer, false);
            }
        }

        private void ProcessReceive(SocketAsyncEventArgs e, bool requeue)
        {
            UDPSocket socket = (UDPSocket)e.UserToken;

            if (e.SocketError == SocketError.Success)
            {
                EndReceive(socket, e.Buffer, e.Offset, e.BytesTransferred, e.RemoteEndPoint);
            }
            else if (e.SocketError != SocketError.OperationAborted
                && e.SocketError != SocketError.Interrupted)
            {
                throw new SocketException((Int32)e.SocketError);
            }

            if (requeue)
            {
                this.BeginReceive(socket);
            }
        }

        private void ProcessSend(SocketAsyncEventArgs e, bool requeue)
        {
            if (requeue)
            {
                this.BeginSend();
            }
        }

        void SocketAsyncEventArgs_Completed(Object sender, SocketAsyncEventArgs e)
        {
            switch (e.LastOperation)
            {
                case SocketAsyncOperation.ReceiveFrom:
                    ProcessReceive(e, true);
                    break;
                case SocketAsyncOperation.SendTo:
                    ProcessSend(e, true);
                    break;
            }
        }

        partial class UDPSocket
        {
            public readonly SocketAsyncEventArgs ReadBuffer;
            public readonly SocketAsyncEventArgs WriteBuffer;
            readonly Byte[] _writeBuffer;
            private Boolean _isOuterBuffer;

            public UDPSocket(AddressFamily addressFamily, Int32 bufferSize,
                EventHandler<SocketAsyncEventArgs> completed)
            {
                Socket = new Socket(addressFamily, SocketType.Dgram, ProtocolType.Udp);
                ReadBuffer = new SocketAsyncEventArgs();
                ReadBuffer.SetBuffer(new Byte[bufferSize], 0, bufferSize);
                ReadBuffer.Completed += completed;
                ReadBuffer.UserToken = this;

                _writeBuffer = new Byte[bufferSize];
                WriteBuffer = new SocketAsyncEventArgs();
                WriteBuffer.SetBuffer(_writeBuffer, 0, bufferSize);
                WriteBuffer.Completed += completed;
                WriteBuffer.UserToken = this;
            }

            public void SetWriteBuffer(Byte[] data, Int32 offset, Int32 count)
            {
                if (count > _writeBuffer.Length)
                {
                    WriteBuffer.SetBuffer(data, offset, count);
                    _isOuterBuffer = true;
                }
                else
                {
                    if (_isOuterBuffer)
                    {
                        WriteBuffer.SetBuffer(_writeBuffer, 0, _writeBuffer.Length);
                        _isOuterBuffer = false;
                    }
                    Buffer.BlockCopy(data, offset, _writeBuffer, 0, count);
                    WriteBuffer.SetBuffer(0, count);
                }
            }

            public void Dispose()
            {
                Socket.Dispose();
                ReadBuffer.Dispose();
                WriteBuffer.Dispose();
            }
        }
    }
}
