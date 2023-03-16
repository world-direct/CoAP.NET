namespace WorldDirect.Dtls;

using System.Net;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Represents a wolfssl SSL connection context.
/// </summary>
internal class DTLSConnectionContext: IDisposable
{
    private IntPtr ssl;
    private byte[] availableData = Array.Empty<byte>();

    /// <summary>
    /// Initializes a new instance of the <see cref="DTLSConnectionContext"/> class.
    /// </summary>
    /// <param name="ssl">A pointer to a wolfssl ssl structure.</param>
    /// <param name="remote">The remote endpoint associated with this context.</param>
    public DTLSConnectionContext(IntPtr ssl, IPEndPoint remote)
    {
        this.ssl = ssl;
        this.Remote = remote;
    }

    /// <summary>
    /// Gets the remote endpoint.
    /// </summary>
    public IPEndPoint Remote { get; }

    /// <summary>
    /// Gets the certificate of the remote endpoint.
    /// </summary>
    /// <remarks>Is null when handshake is ongoing.</remarks>
    public X509Certificate? Certificate { get; private set; }

    /// <summary>
    /// Encrypts data and sends it to the remote.
    /// </summary>
    /// <param name="data">The data to encrypt and send.</param>
    /// <exception cref="InvalidOperationException">Thrown when a error occurs in the wolfssl library.</exception>
    public void SendData(byte[] data)
    {
        int ret = wolfssl.write(this.ssl, data, data.Length);
        if (ret < 0)
        {
            var err = wolfssl.get_error_int(this.ssl);
            var errStr = wolfssl.get_error(err);
            throw new InvalidOperationException($"Send to {this.Remote} failed: {errStr}");
        }
    }

    /// <summary>
    /// Called after a udp package was received from the remote. Updates the current buffer with the specified data.
    /// </summary>
    /// <remarks>The buffer is needed because of the callbacks of wolfssl.</remarks>
    /// <param name="data">The data to forward to wolfssl.</param>
    public void ReceivedData(byte[] data)
    {
        this.availableData = data;
    }

    /// <summary>
    /// Checks whether data is in the buffer and writes it on the <paramref name="data"/> parameter if available.
    /// </summary>
    /// <remarks>Should only be used by the wolfssl callback.</remarks>
    /// <param name="data">The buffered data if available.</param>
    /// <returns></returns>
    public bool TryDequeueData(out byte[] data)
    {
        data = this.availableData;
        this.availableData = Array.Empty<byte>();
        return data.Length > 0;
    }

    /// <summary>
    /// Tries to finish handshake.
    /// </summary>
    /// <returns>True when handshake finished, false when handshake is ongoing.</returns>
    /// <exception cref="HandshakeFailedException">Thrown when the handshake failed because of error.</exception>
    public bool Accept()
    {
        var ret = wolfssl.accept(this.ssl);
        if (ret != wolfssl.SUCCESS)
        {
            var err = wolfssl.get_error_int(this.ssl);
            if (err != -1 * wolfssl.CBIO_ERR_WANT_READ)
            {
                var errStr = wolfssl.get_error(err);
                throw new HandshakeFailedException($"Handshake with {this.Remote} failed: {errStr}");
            }

            return false;
        }

        var wolfsslCertificate = wolfssl.get_peer_certificate(this.ssl);
        this.Certificate = new X509Certificate(wolfsslCertificate.Export());
        return true;
    }

    /// <summary>
    /// Checks whether unencrypted data is available. Copies data onto buffer if available.
    /// </summary>
    /// <param name="data">A buffer to copy onto.</param>
    /// <returns>The amount of received bytes.</returns>
    /// <exception cref="InvalidOperationException">Thrown when an error occurs with wolfssl.</exception>
    public int TryReadData(byte[] data)
    {
        var ret = wolfssl.read(this.ssl, data, data.Length);
        if (ret < 0)
        {
            var err = wolfssl.get_error_int(this.ssl);
            if (err != -1 * wolfssl.CBIO_ERR_WANT_READ)
            {
                var errStr = wolfssl.get_error(err);
                throw new InvalidOperationException($"Receive from {this.Remote} failed: {errStr}");
            }

            return 0;
        }
        return ret;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (this.ssl != IntPtr.Zero)
        {
            wolfssl.free(this.ssl);
            this.ssl = IntPtr.Zero;
        }
    }
}
