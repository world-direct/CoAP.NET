// Copyright (c) World-Direct eBusiness solutions GmbH. All rights reserved.

namespace WorldDirect.CoAP.Hosting.Hosting.Services
{
    using System;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Hosting;
    using Microsoft.Extensions.Logging;

    /// <summary>
    /// Represents a <seealso cref="IHostedService"/> that is vital for the application.
    /// If the services crashes, an application shutdown is initiated.
    /// </summary>
    /// <seealso cref="IHostedService" />
    public abstract class VitalBackgroundService : IHostedService
    {
        private readonly CancellationTokenSource cts = new CancellationTokenSource();
        private readonly IHostApplicationLifetime lifetime;
        private readonly ILogger logger;
        private bool disposed = false;
        private Task? service;

        /// <summary>
        /// Initializes a new instance of the <see cref="VitalBackgroundService"/> class.
        /// </summary>
        /// <param name="lifetime">The lifetime manage of the application.</param>
        /// <param name="logger">The logger to log events of interest.</param>
        protected VitalBackgroundService(IHostApplicationLifetime lifetime, ILogger logger)
        {
            this.lifetime = lifetime;
            this.logger = logger;
        }

        /// <summary>
        /// Triggered when the application host is ready to start the service.
        /// </summary>
        /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
        /// <returns>A task that completes after the service has started.</returns>
        public Task StartAsync(CancellationToken cancellationToken)
        {
            logger.LogInformation("{ServiceName} starting.", GetType().Name);

            // Store the task we're executing
            service = RunServiceAsync(cts.Token);

            // If the task is completed then return it, this will bubble cancellation and failure to the caller
            if (service.IsCompleted)
            {
                return service;
            }

            logger.LogInformation("{ServiceName} started.", GetType().Name);

            // Otherwise it's running
            return Task.CompletedTask;
        }

        /// <summary>
        /// Triggered when the application host is performing a graceful shutdown.
        /// </summary>
        /// <param name="cancellationToken">Indicates that the shutdown process should no longer be graceful.</param>
        /// <returns>A <see cref="Task"/> that completes after the service has been stopped.</returns>
        public async Task StopAsync(CancellationToken cancellationToken)
        {
            logger.LogDebug("{ServiceName} stopping.", GetType().Name);

            // Stop called without start
            if (service != null)
            {
                try
                {
                    // Signal cancellation to the executing method
                    cts.Cancel();
                }
                finally
                {
                    // Wait until the task completes or the stop token triggers
                    await Task.WhenAny(service, Task.Delay(Timeout.Infinite, cancellationToken)).ConfigureAwait(false);
                }
            }

            logger.LogDebug("{ServiceName} stopped.", GetType().Name);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        public void Dispose()
        {
            if (disposed)
            {
                return;
            }

            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// This method is called when the <see cref="IHostedService"/> starts. The implementation should return a task that represents
        /// the lifetime of the long running operation(s) being performed.
        /// </summary>
        /// <param name="ct">Triggered when <see cref="IHostedService.StopAsync(CancellationToken)"/> is called.</param>
        /// <returns>A <see cref="Task"/> that represents the long running operations.</returns>
        protected abstract Task ExecuteAsync(CancellationToken ct);

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                cts?.Dispose();
            }

            disposed = true;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "No exception should escape.")]
        private async Task RunServiceAsync(CancellationToken cancellationToken)
        {
            try
            {
                await Task.Yield();
                await ExecuteAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception e)
            {
                logger.LogError(e, "{ServiceName} crashed. Shutdown application.", GetType().Name);
                lifetime.StopApplication();
            }
        }
    }
}
