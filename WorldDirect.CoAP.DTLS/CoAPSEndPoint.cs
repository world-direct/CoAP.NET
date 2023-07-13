/*
 * Copyright (c) 2011-2015, Longxiang He <helongxiang@smeshlink.com>,
 * SmeshLink Technology Co.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY.
 * 
 * This file is part of the CoAP.NET, a CoAP framework in C#.
 * Please see README for more information.
 */

namespace WorldDirect.CoAP.Net
{
    using System;
    using System.Net;
    using System.Runtime.Serialization;
    using System.Threading;
    using Channel;
    using Codec;
    using DTLS;
    using Log;
    using Microsoft.Extensions.Caching.Memory;
    using Microsoft.Extensions.Logging;
    using Org.BouncyCastle.Tls;
    using Stack;
    using Threading;

    /// <summary>
    /// EndPoint encapsulates the dtlsStack that executes the CoAP protocol.
    /// </summary>
    public partial class CoAPSEndpoint : IEndPoint, IOutbox
    {

        readonly ICoapConfig _config;
        readonly CoapStack _coapStack;
        private IMessageDeliverer _deliverer;
        private IMatcher _matcher;
        private Int32 _running;
        private IExecutor _executor;
        private DTLSChannel channel;
        private ILogger<CoAPSEndpoint> log = LogManager.GetLogger<CoAPSEndpoint>();

        /// <inheritdoc/>
        public string Scheme => CoapConstants.SecureUriScheme;

        /// <inheritdoc/>
        public event EventHandler<MessageEventArgs<Request>> SendingRequest;
        /// <inheritdoc/>
        public event EventHandler<MessageEventArgs<Response>> SendingResponse;
        /// <inheritdoc/>
        public event EventHandler<MessageEventArgs<EmptyMessage>> SendingEmptyMessage;
        /// <inheritdoc/>
        public event EventHandler<MessageEventArgs<Request>> ReceivingRequest;
        /// <inheritdoc/>
        public event EventHandler<MessageEventArgs<Response>> ReceivingResponse;
        /// <inheritdoc/>
        public event EventHandler<MessageEventArgs<EmptyMessage>> ReceivingEmptyMessage;

        /// <summary>
        /// Instantiates a new endpoint with the
        /// specified channel and configuration.
        /// </summary>
        public CoAPSEndpoint(IMemoryCache cache, IDTLSFactory factory, ICoapConfig config)
        {
            _config = config;
            _matcher = new Matcher(this._config);
            _coapStack = new CoapStack(this._config);
            UDPChannel channel = new UDPChannel(new IPEndPoint(IPAddress.Any, 5684));
            channel.ReceiveBufferSize = this._config.ChannelReceiveBufferSize;
            channel.SendBufferSize = this._config.ChannelSendBufferSize;
            channel.ReceivePacketSize = this._config.ChannelReceivePacketSize;
            this.channel = new DTLSChannel(channel, cache, factory);
            this.channel.DtlsDataReceived += Channel_DataReceived;
        }

        public CoAPSEndpoint(IMemoryCache cache, IDTLSFactory factory, UDPChannel channel, ICoapConfig config)
        {
            _config = config;
            _matcher = new Matcher(this._config);
            _coapStack = new CoapStack(this._config);
            this.channel = new DTLSChannel(channel, cache, factory);
            this.channel.DtlsDataReceived += Channel_DataReceived;
        }


        /// <inheritdoc/>
        public ICoapConfig Config
        {
            get { return _config; }
        }

        public IExecutor Executor
        {
            get { return _executor; }
            set
            {
                _executor = value ?? Executors.NoThreading;
                _coapStack.Executor = _executor;
            }
        }

        /// <inheritdoc/>
        public System.Net.EndPoint LocalEndPoint => this.channel.LocalEndPoint;

        /// <inheritdoc/>
        public IMessageDeliverer MessageDeliverer
        {
            set { _deliverer = value; }
            get
            {
                if (_deliverer == null)
                    _deliverer = new ClientMessageDeliverer();
                return _deliverer;
            }
        }

        /// <inheritdoc/>
        public IOutbox Outbox
        {
            get { return this; }
        }

        /// <inheritdoc/>
        public Boolean Running
        {
            get { return _running > 0; }
        }

        /// <inheritdoc/>
        public void Start()
        {
            if (System.Threading.Interlocked.CompareExchange(ref _running, 1, 0) > 0)
                return;

            if (_executor == null)
                Executor = Executors.Default;
            
            try
            {
                _matcher.Start();
                this.channel.Start();
            }
            catch
            {
                log.LogWarning("Cannot start secure endpoint at " + this.channel.LocalEndPoint);
                Stop();
                throw;
            }
            log.LogDebug("Starting secure endpoint bound to " + this.channel.LocalEndPoint);
        }

        /// <inheritdoc/>
        public void Stop()
        {
            if (System.Threading.Interlocked.Exchange(ref _running, 0) == 0)
                return;

            log.LogDebug("Stopping secure endpoint bound to " + this.LocalEndPoint);
            this.channel.Stop();
            _matcher.Stop();
            _matcher.Clear();
        }

        /// <inheritdoc/>
        public void Clear()
        {
            _matcher.Clear();
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (Running)
                Stop();
            IDisposable d = _matcher as IDisposable;
            if (d != null)
                d.Dispose();
        }

        /// <inheritdoc/>
        public void SendRequest(Request request)
        {
            _executor.Start(() => _coapStack.SendRequest(request));
        }

        /// <inheritdoc/>
        public void SendResponse(Exchange exchange, Response response)
        {
            _executor.Start(() => _coapStack.SendResponse(exchange, response));
        }

        /// <inheritdoc/>
        public void SendEmptyMessage(Exchange exchange, EmptyMessage message)
        {
            _executor.Start(() => _coapStack.SendEmptyMessage(exchange, message));
        }


        private void Channel_DataReceived(object? sender, DTLSDataReceivedEventArgs e)
        {
            IMessageDecoder decoder = Spec.NewMessageDecoder(e.Data);
            if (decoder.IsRequest)
            {
                Request request;
                try
                {
                    request = decoder.DecodeRequest();
                    request.EndPoint = this;
                }
                catch (Exception)
                {
                    if (decoder.IsReply)
                    {
                        log.LogWarning("Message format error caused by " + e.EndPoint);
                    }
                    else
                    {
                        // manually build RST from raw information
                        EmptyMessage rst = new EmptyMessage(MessageType.RST);
                        rst.Destination = e.EndPoint;
                        rst.ID = decoder.ID;

                        Fire(SendingEmptyMessage, rst);
                        this.channel.Send(Serialize(rst), e.EndPoint);

                        log.LogWarning("Message format error caused by " + e.EndPoint + " and reseted.");
                    }
                    return;
                }

                request.Source = e.EndPoint;

                Fire(ReceivingRequest, request);

                if (!request.IsCancelled)
                {
                    Exchange exchange = _matcher.ReceiveRequest(request);
                    if (exchange != null)
                    {
                        exchange.EndPoint = this;
                        exchange.Set(nameof(DTLSClientAuthentication), e.ClientAuthentication);
                        _coapStack.ReceiveRequest(exchange, request);
                    }
                }
            }
            else if (decoder.IsResponse)
            {
                Response response = decoder.DecodeResponse();
                response.Source = e.EndPoint;

                Fire(ReceivingResponse, response);

                if (!response.IsCancelled)
                {
                    Exchange exchange = _matcher.ReceiveResponse(response);
                    if (exchange != null)
                    {
                        response.RTT = (DateTime.Now - exchange.Timestamp).TotalMilliseconds;
                        exchange.EndPoint = this;
                        _coapStack.ReceiveResponse(exchange, response);
                    }
                    else if (response.Type != MessageType.ACK)
                    {
                        log.LogDebug("Rejecting unmatchable response from " + e.EndPoint);
                        Reject(response);
                    }
                }
            }
            else if (decoder.IsEmpty)
            {
                EmptyMessage message = decoder.DecodeEmptyMessage();
                message.Source = e.EndPoint;

                Fire(ReceivingEmptyMessage, message);

                if (!message.IsCancelled)
                {
                    // CoAP Ping
                    if (message.Type == MessageType.CON || message.Type == MessageType.NON)
                    {
                        log.LogDebug("Responding to ping by " + e.EndPoint);
                        Reject(message);
                    }
                    else
                    {
                        Exchange exchange = _matcher.ReceiveEmptyMessage(message);
                        if (exchange != null)
                        {
                            exchange.EndPoint = this;
                            _coapStack.ReceiveEmptyMessage(exchange, message);
                        }
                    }
                }
            }
            else
            {
                log.LogDebug("Silently ignoring non-CoAP message from " + e.EndPoint);
            }
        }

        private void Reject(Message message)
        {
            EmptyMessage rst = EmptyMessage.NewRST(message);

            Fire(SendingEmptyMessage, rst);

            if (!rst.IsCancelled)
                this.channel.Send(Serialize(rst), rst.Destination);
        }

        private Byte[] Serialize(EmptyMessage message)
        {
            Byte[] bytes = message.Bytes;
            if (bytes == null)
            {
                bytes = Spec.NewMessageEncoder().Encode(message);
                message.Bytes = bytes;
            }
            return bytes;
        }

        private Byte[] Serialize(Request request)
        {
            Byte[] bytes = request.Bytes;
            if (bytes == null)
            {
                bytes = Spec.NewMessageEncoder().Encode(request);
                request.Bytes = bytes;
            }
            return bytes;
        }

        private Byte[] Serialize(Response response)
        {
            Byte[] bytes = response.Bytes;
            if (bytes == null)
            {
                bytes = Spec.NewMessageEncoder().Encode(response);
                response.Bytes = bytes;
            }
            return bytes;
        }

        private void Fire<T>(EventHandler<MessageEventArgs<T>> handler, T msg) where T : Message
        {
            if (handler != null)
                handler(this, new MessageEventArgs<T>(msg));
        }

        void IOutbox.SendRequest(Exchange exchange, Request request)
        {
            _matcher.SendRequest(exchange, request);

            Fire(SendingRequest, request);

            if (!request.IsCancelled)
                this.channel.Send(Serialize(request), request.Destination);
        }

        void IOutbox.SendResponse(Exchange exchange, Response response)
        {
            _matcher.SendResponse(exchange, response);

            Fire(SendingResponse, response);

            if (!response.IsCancelled)
                this.channel.Send(Serialize(response), response.Destination);
        }

        void IOutbox.SendEmptyMessage(Exchange exchange, EmptyMessage message)
        {
            _matcher.SendEmptyMessage(exchange, message);

            Fire(SendingEmptyMessage, message);

            if (!message.IsCancelled)
                this.channel.Send(Serialize(message), message.Destination);
        }
    }
}
