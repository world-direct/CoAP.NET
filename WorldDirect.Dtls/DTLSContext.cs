namespace WorldDirect.Dtls;

using System.Net;

internal class DTLSContext: IDisposable
{
    private IntPtr ctx;
    private SendDTLSDataContext sendContext;

    public DTLSContext()
    {
        this.ctx = wolfssl.CTX_dtls_new(wolfssl.useDTLSv1_2_server());
        if (this.ctx == IntPtr.Zero)
        {
            throw new InvalidOperationException("Cant create new DTLS context");
        }
    }

    public void SetSendCallback(Action<Memory<byte>, IPEndPoint> callback)
    {
        this.sendContext = new SendDTLSDataContext(callback);
    }

    public void SetCertificateFile(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"{path} for certificate does not exist");
        }
        this.CallErrorAwareCtxFunction(() => wolfssl.CTX_use_certificate_file(this.ctx, path, wolfssl.SSL_FILETYPE_PEM),
            nameof(wolfssl.CTX_use_certificate_file));
    }

    public void SetPrivateKeyFile(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"{path} for private key does not exist");
        }
        this.CallErrorAwareCtxFunction(() => wolfssl.CTX_use_PrivateKey_file(this.ctx, path, wolfssl.SSL_FILETYPE_PEM), nameof(wolfssl.CTX_use_PrivateKey_file));
    }

    public void SetCAFile(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"{path} for CA does not exist");
        }
        this.CallErrorAwareCtxFunction(() => wolfssl.CTX_load_verify_locations(this.ctx, path, null), nameof(wolfssl.CTX_load_verify_locations));
    }

    public void RequirePeerCertificate()
    {
        this.CallErrorAwareCtxFunction(() => wolfssl.CTX_set_verify(this.ctx, wolfssl.SSL_VERIFY_FAIL_IF_NO_PEER_CERT | wolfssl.SSL_VERIFY_PEER,
            (currentStatus, _) => currentStatus), nameof(wolfssl.CTX_set_verify));
    }

    public DTLSConnectionContext CreateConnectionContext(IPEndPoint remote)
    {
        var ssl = wolfssl.new_ssl(this.ctx);
        if (ssl == IntPtr.Zero)
        {
            throw new InvalidOperationException($"Cant create new dtls session");
        }
        var context = new DTLSConnectionContext(ssl, remote);
        this.CallErrorAwareCtxFunction(() => wolfssl.set_dtls_fd(ssl, this.sendContext, context), nameof(wolfssl.set_dtls_fd));
        return context;
    }


    private void CallErrorAwareCtxFunction(Func<int> functionCall, string name = "")
    {
        if (functionCall() != wolfssl.SUCCESS)
        {
            int err = wolfssl.X509_STORE_CTX_get_error(this.ctx);
            var strError = wolfssl.get_error(err);
            throw new InvalidOperationException($"{name} returned error: {strError}");
        }
    }

    public void Dispose()
    {
        if (this.ctx != IntPtr.Zero)
        {
            wolfssl.CTX_free(this.ctx);
            this.ctx = IntPtr.Zero;
        }
    }
}
