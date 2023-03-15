namespace WorldDirect.Dtls;

using System.Net;
using System.Security.Cryptography.X509Certificates;

internal class DTLSConnectionContext: IDisposable
{
    private IntPtr ssl;
    private byte[] availableData = Array.Empty<byte>();
    public DTLSConnectionContext(IntPtr ssl, IPEndPoint remote)
    {
        this.ssl = ssl;
        this.Remote = remote;
    }

    public IPEndPoint Remote { get; }

    public X509Certificate? Certificate { get; private set; }

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

    public void ReceivedData(byte[] data)
    {
        this.availableData = data;
    }

    public bool TryDequeueData(out byte[] data)
    {
        if (this.availableData.Length == 0)
        {
            data = Array.Empty<byte>();
            return false;
        }
        data = this.availableData;
        this.availableData = Array.Empty<byte>();
        return true;
    }

    /// <summary>
    /// Tries to finish handshake.
    /// </summary>
    /// <returns>True when handshake finished, false when handshake is ongoing.</returns>
    /// <exception cref="HandshakeFailedException"></exception>
    public bool accept()
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

    public void Dispose()
    {
        if (this.ssl != IntPtr.Zero)
        {
            wolfssl.free(this.ssl);
            this.ssl = IntPtr.Zero;
        }
    }
}
