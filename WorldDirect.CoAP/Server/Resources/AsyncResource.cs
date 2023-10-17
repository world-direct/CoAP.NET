namespace WorldDirect.CoAP.Server.Resources
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Log;
    using Microsoft.Extensions.Logging;

    public class AsyncResource: Server.Resources.Resource, IDisposable
    {
        private ConcurrentDictionary<Guid, Task> _tasks = new ConcurrentDictionary<Guid, Task>();
        private CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly ILogger<AsyncResource> _logger;
        private bool _disposed = false;

        public AsyncResource(string name) : base(name)
        {
            this._logger = LogManager.GetLogger<AsyncResource>();
        }

        public AsyncResource(string name, bool visible) : base(name, visible)
        {
            this._logger = LogManager.GetLogger<AsyncResource>();
        }

        protected sealed override void DoGet(CoapExchange exchange)
        {
            var guid = Guid.NewGuid();
            var t = this.GetAsync(exchange, guid, this._cts.Token);
            this._tasks.AddOrUpdate(guid, t, (g, _) => t);
        }

        protected sealed override void DoPost(CoapExchange exchange)
        {
            var guid = Guid.NewGuid();
            var t = this.PostAsync(exchange, guid, this._cts.Token);
            this._tasks.AddOrUpdate(guid, t, (g, _) => t);
        }

        protected sealed override void DoPut(CoapExchange exchange)
        {
            var guid = Guid.NewGuid();
            var t = this.PutAsync(exchange, guid, this._cts.Token);
            this._tasks.AddOrUpdate(guid, t, (g, _) => t);
        }

        protected sealed override void DoDelete(CoapExchange exchange)
        {
            var guid = Guid.NewGuid();
            var t = this.DeleteAsync(exchange, guid, this._cts.Token);
            this._tasks.AddOrUpdate(guid, t, (g, _) => t);
        }



        private async Task GetAsync(CoapExchange exchange, Guid taskId, CancellationToken ct)
        {
            try
            {
                await this.DoGetAsync(exchange, ct).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                this._logger.LogError(e, "Unhandled exception in GET {Resource}", this.Name);
            }
            finally
            {
                this._tasks.TryRemove(taskId, out _);
            }
        }

        private async Task PostAsync(CoapExchange exchange, Guid taskId, CancellationToken ct)
        {
            try
            {
                await this.DoPostAsync(exchange, ct).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                this._logger.LogError(e, "Unhandled exception in POST {Resource}", this.Name);
            }
            finally
            {
                this._tasks.TryRemove(taskId, out _);
            }
        }

        private async Task PutAsync(CoapExchange exchange, Guid taskId, CancellationToken ct)
        {
            try
            {
                await this.DoPutAsync(exchange, ct).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                this._logger.LogError(e, "Unhandled exception in PUT {Resource}", this.Name);
            }
            finally
            {
                this._tasks.TryRemove(taskId, out _);
            }
        }

        private async Task DeleteAsync(CoapExchange exchange, Guid taskId, CancellationToken ct)
        {
            try
            {
                await this.DoDeleteAsync(exchange, ct).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                this._logger.LogError(e, "Unhandled exception in DELETE {Resource}", this.Name);
            }
            finally
            {
                this._tasks.TryRemove(taskId, out _);
            }
        }

        protected virtual Task DoGetAsync(CoapExchange exchange, CancellationToken ct)
        {
            exchange.Respond(StatusCode.MethodNotAllowed);
            return Task.CompletedTask;
        }


        protected virtual Task DoPostAsync(CoapExchange exchange, CancellationToken ct)
        {
            exchange.Respond(StatusCode.MethodNotAllowed);
            return Task.CompletedTask;
        }

        protected virtual Task DoPutAsync(CoapExchange exchange, CancellationToken ct)
        {
            exchange.Respond(StatusCode.MethodNotAllowed);
            return Task.CompletedTask;
        }

        protected virtual Task DoDeleteAsync(CoapExchange exchange, CancellationToken ct)
        {
            exchange.Respond(StatusCode.MethodNotAllowed);
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            // Dispose of unmanaged resources.
            Dispose(true);
            // Suppress finalization.
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (disposing)
            {
                _cts?.Cancel();
                _cts?.Dispose();
            }

            _disposed = true;
        }
    }
}
