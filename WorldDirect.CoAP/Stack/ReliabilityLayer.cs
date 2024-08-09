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

namespace WorldDirect.CoAP.Stack
{
    using System;
    using System.Diagnostics;
    using System.Threading;
    using Log;
    using Microsoft.Extensions.Logging;
    using Net;

    /// <summary>
    /// The reliability layer
    /// </summary>
    public class ReliabilityLayer : AbstractLayer
    {
        static readonly ILogger<ReliabilityLayer> log = LogManager.GetLogger<ReliabilityLayer>();
        static readonly Object TransmissionContextKey = "TransmissionContext";

        private readonly Random _rand = new Random();
        private ICoapConfig _config;

        /// <summary>
        /// Constructs a new reliability layer.
        /// </summary>
        public ReliabilityLayer(ICoapConfig config)
        {
            _config = config;
        }

        /// <summary>
        /// // Schedules a retransmission for confirmable messages.
        /// </summary>
        public override void SendRequest(INextLayer nextLayer, Exchange exchange, Request request)
        {
            if (request.Type == MessageType.Unknown)
                request.Type = MessageType.CON;

            if (request.Type == MessageType.CON)
            {
                PrepareRetransmission(exchange, request, ctx => SendRequest(nextLayer, exchange, request));
            }

            base.SendRequest(nextLayer, exchange, request);
        }

        /// <summary>
        /// Makes sure that the response type is correct. The response type for a NON
	    /// can be NON or CON. The response type for a CON should either be an ACK
	    /// with a piggy-backed response or, if an empty ACK has already be sent, a
        /// CON or NON with a separate response.
        /// </summary>
        public override void SendResponse(INextLayer nextLayer, Exchange exchange, Response response)
        {
            MessageType mt = response.Type;
            if (mt == MessageType.Unknown)
            {
                MessageType reqType = exchange.CurrentRequest.Type;
                if (reqType == MessageType.CON)
                {
                    if (exchange.CurrentRequest.IsAcknowledged)
                    {
                        // send separate response
                        response.Type = MessageType.CON;
                    }
                    else
                    {
                        exchange.CurrentRequest.IsAcknowledged = true;
                        // send piggy-backed response
                        response.Type = MessageType.ACK;
                        response.ID = exchange.CurrentRequest.ID;
                    }
                }
                else
                {
                    // send NON response
                    response.Type = MessageType.NON;
                }
            }
            else if (mt == MessageType.ACK || mt == MessageType.RST)
            {
                response.ID = exchange.CurrentRequest.ID;
            }

            if (response.Type == MessageType.CON)
            {
                    log.LogTrace("Scheduling retransmission for " + response);
                PrepareRetransmission(exchange, response, ctx => SendResponse(nextLayer, exchange, response));
            }

            base.SendResponse(nextLayer, exchange, response);
        }

        /// <summary>
        /// When we receive a duplicate of a request, we stop it here and do not
	    /// forward it to the upper layer. If the server has already sent a response,
	    /// we send it again. If the request has only been acknowledged (but the ACK
	    /// has gone lost or not reached the client yet), we resent the ACK. If the
        /// request has neither been responded, acknowledged or rejected yet, the
	    /// server has not yet decided what to do with the request and we cannot do
	    /// anything.
        /// </summary>
        public override void ReceiveRequest(INextLayer nextLayer, Exchange exchange, Request request)
        {
            if (request.Duplicate)
            {
                // Request is a duplicate, so resend ACK, RST or response
                if (exchange.CurrentResponse != null)
                {
                        log.LogTrace("Respond with the current response to the duplicate request");
                    base.SendResponse(nextLayer, exchange, exchange.CurrentResponse);
                }
                else if (exchange.CurrentRequest != null)
                {
                    if (exchange.CurrentRequest.IsAcknowledged)
                    {
                            log.LogTrace("The duplicate request was acknowledged but no response computed yet. Retransmit ACK.");
                        EmptyMessage ack = EmptyMessage.NewACK(request);
                        SendEmptyMessage(nextLayer, exchange, ack);
                    }
                    else if (exchange.CurrentRequest.IsRejected)
                    {
                            log.LogTrace("The duplicate request was rejected. Reject again.");
                        EmptyMessage rst = EmptyMessage.NewRST(request);
                        SendEmptyMessage(nextLayer, exchange, rst);
                    }
                    else
                    {
                            log.LogTrace("The server has not yet decided what to do with the request. We ignore the duplicate.");
                        // The server has not yet decided, whether to acknowledge or
                        // reject the request. We know for sure that the server has
                        // received the request though and can drop this duplicate here.
                    }
                }
                else
                {
                    // Lost the current request. The server has not yet decided what to do.
                }
            }
            else
            {
                // Request is not a duplicate
                exchange.CurrentRequest = request;
                base.ReceiveRequest(nextLayer, exchange, request);
            }
        }

        /// <summary>
        /// When we receive a Confirmable response, we acknowledge it and it also
	    /// counts as acknowledgment for the request. If the response is a duplicate,
        /// we stop it here and do not forward it to the upper layer.
        /// </summary>
        public override void ReceiveResponse(INextLayer nextLayer, Exchange exchange, Response response)
        {
            if (response.Duplicate)
            {
                log.LogTrace("Response is duplicate, ignore it.");
                return;
            }

            TransmissionContext ctx = (TransmissionContext)exchange.Remove(TransmissionContextKey);
            if (ctx != null)
            {
                exchange.CurrentRequest.IsAcknowledged = true;
                ctx.Cancel();
            }

            if (response.Type == MessageType.CON && !exchange.Request.IsCancelled)
            {
                    log.LogTrace("Response is confirmable, send ACK.");
                EmptyMessage ack = EmptyMessage.NewACK(response);
                SendEmptyMessage(nextLayer, exchange, ack);
            }

            base.ReceiveResponse(nextLayer, exchange, response);
        }

        /// <summary>
        /// If we receive an ACK or RST, we mark the outgoing request or response
        /// as acknowledged or rejected respectively and cancel its retransmission.
        /// </summary>
        public override void ReceiveEmptyMessage(INextLayer nextLayer, Exchange exchange, EmptyMessage message)
        {
            switch (message.Type)
            {
                case MessageType.ACK:
                    if (exchange.Origin == Origin.Local)
                        exchange.CurrentRequest.IsAcknowledged = true;
                    else
                        exchange.CurrentResponse.IsAcknowledged = true;
                    break;
                case MessageType.RST:
                    if (exchange.Origin == Origin.Local)
                        exchange.CurrentRequest.IsRejected = true;
                    else
                        exchange.CurrentResponse.IsRejected = true;
                    break;
                default:
                        log.LogTrace("Empty messgae was not ACK nor RST: " + message);
                    break;
            }

            TransmissionContext ctx = (TransmissionContext)exchange.Remove(TransmissionContextKey);
            if (ctx != null)
                ctx.Cancel();

            base.ReceiveEmptyMessage(nextLayer, exchange, message);
        }

        private void PrepareRetransmission(Exchange exchange, Message msg, Action<TransmissionContext> retransmit)
        {
            TransmissionContext ctx = exchange.GetOrAdd<TransmissionContext>(
                TransmissionContextKey, _ => new TransmissionContext(_config, exchange, msg, retransmit));
            
            if (ctx.FailedTransmissionCount > 0)
            {
                ctx.CurrentTimeout = (Int32)(ctx.CurrentTimeout * _config.AckTimeoutScale);
            }
            else if (ctx.CurrentTimeout == 0)
            {
                ctx.CurrentTimeout = InitialTimeout(_config.AckTimeout, _config.AckRandomFactor);
            }
            log.LogTrace("Scheduling retransmission in {RetryIn}", TimeSpan.FromMilliseconds(ctx.CurrentTimeout));

            ctx.Start();
        }

        private Int32 InitialTimeout(Int32 initialTimeout, Double factor)
        {
            return (Int32)(initialTimeout + initialTimeout * (factor - 1D) * _rand.NextDouble());
        }

        class TransmissionContext : IDisposable
        {
            readonly ICoapConfig _config;
            readonly Exchange _exchange;
            readonly Message _message;
            private Int32 _currentTimeout;
            private Int32 _failedTransmissionCount;
            private Timer _timer;
            private Action<TransmissionContext> _retransmit;
            private ExecutionContext? _context;

            public TransmissionContext(ICoapConfig config, Exchange exchange, Message message, Action<TransmissionContext> retransmit)
            {
                _context = ExecutionContext.Capture()?.CreateCopy();
                _config = config;
                _exchange = exchange;
                _message = message;
                _retransmit = retransmit;
                _currentTimeout = message.AckTimeout;
            }

            public Int32 FailedTransmissionCount
            {
                get { return _failedTransmissionCount; }
                set { _failedTransmissionCount = value; }
            }

            public Int32 CurrentTimeout
            {
                get { return _currentTimeout; }
                set { _currentTimeout = value; }
            }

            public void Start()
            {
                _timer?.Dispose();

                if (_currentTimeout > 0)
                {
                    _timer = new Timer(timer_Elapsed, null, _currentTimeout, Timeout.Infinite);
                }
            }

            public void Cancel()
            {
                Timer t = System.Threading.Interlocked.Exchange(ref _timer, null);

                // avoid race condition of multiple responses (e.g., notifications)
                if (t == null)
                    return;

                try
                {
                    t.Dispose();
                }
                catch (ObjectDisposedException)
                {
                    // ignore
                }
            }

            public void Dispose()
            {
                Cancel();
            }

            void timer_Elapsed(object state)
            {
                if(this._context != null)
                    ExecutionContext.Run(this._context, this.OnExecutionContext, this);
                else
                    this.OnExecutionContext(state);
            }

            void OnExecutionContext(object _)
            {
                /*
			     * Do not retransmit a message if it has been acknowledged,
			     * rejected, canceled or already been retransmitted for the maximum
			     * number of times.
			     */
                Int32 failedCount = ++_failedTransmissionCount;

                if (_message.IsAcknowledged)
                {
                    log.LogTrace("Timeout: message already acknowledged, cancel retransmission of " + _message);
                    return;
                }
                else if (_message.IsRejected)
                {
                    log.LogTrace("Timeout: message already rejected, cancel retransmission of " + _message);
                    return;
                }
                else if (_message.IsCancelled)
                {
                    log.LogTrace("Timeout: canceled (ID=" + _message.ID + "), do not retransmit");
                    return;
                }
                else if (failedCount <= (_message.MaxRetransmit != 0 ? _message.MaxRetransmit : _config.MaxRetransmit))
                {
                    log.LogDebug("Timeout: retransmit message for the {retry}. time.", failedCount);

                    _message.FireRetransmitting();

                    // message might have canceled
                    if (!_message.IsCancelled)
                        _retransmit(this);
                }
                else
                {
                    log.LogDebug("Retransmission limit reached.");
                    _exchange.TimedOut = true;
                    _message.IsTimedOut = true;
                    _exchange.Remove(TransmissionContextKey);
                    Cancel();
                }
            }
        }
    }
}
