namespace WorldDirect.Dtls;

using System.Net;

/// <summary>
/// Represents a wolf ssl context.
/// </summary>
internal class DTLSContext: IDisposable
{
    private IntPtr ctx;
    private SendDTLSDataContext sendContext;

    /// <summary>
    /// Initializes a new instance of the <see cref="DTLSContext"/> class.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when a wolfssl context cant be created.</exception>
    public DTLSContext()
    {
        this.ctx = wolfssl.CTX_dtls_new(wolfssl.useDTLSv1_2_server());
        if (this.ctx == IntPtr.Zero)
        {
            throw new InvalidOperationException("Cant create new DTLS context");
        }
    }

    /// <summary>
    /// Set the callback which is called when UDP messages should be send.
    /// </summary>
    /// <param name="callback">The callback to use.</param>
    public void SetSendCallback(Action<byte[], IPEndPoint> callback)
    {
        this.sendContext = new SendDTLSDataContext(callback);
    }

    /// <summary>
    /// Set the path to the certificate file.
    /// </summary>
    /// <param name="path">Path to the certificate file.</param>
    /// <exception cref="FileNotFoundException">Thrown when the file does not exist.</exception>
    /// <exception cref="InvalidOperationException">Thrown when an error occurs in wolfssl.</exception>
    public void SetCertificateFile(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"{path} for certificate does not exist");
        }
        this.CallErrorAwareCtxFunction(() => wolfssl.CTX_use_certificate_file(this.ctx, path, wolfssl.SSL_FILETYPE_PEM),
            nameof(wolfssl.CTX_use_certificate_file));
    }

    /// <summary>
    /// Set the path to the private key file.
    /// </summary>
    /// <param name="path">Path to the private key file.</param>
    /// <exception cref="FileNotFoundException">Thrown when the file does not exist.</exception>
    /// <exception cref="InvalidOperationException">Thrown when an error occurs in wolfssl.</exception>
    public void SetPrivateKeyFile(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"{path} for private key does not exist");
        }
        this.CallErrorAwareCtxFunction(() => wolfssl.CTX_use_PrivateKey_file(this.ctx, path, wolfssl.SSL_FILETYPE_PEM), nameof(wolfssl.CTX_use_PrivateKey_file));
    }

    /// <summary>
    /// Set the path to the Certificate Authority file.
    /// </summary>
    /// <param name="path">Path to the CA file.</param>
    /// <exception cref="FileNotFoundException">Thrown when the file does not exist.</exception>
    /// <exception cref="InvalidOperationException">Thrown when an error occurs in wolfssl.</exception>
    public void SetCAFile(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"{path} for CA does not exist");
        }
        this.CallErrorAwareCtxFunction(() => wolfssl.CTX_load_verify_locations(this.ctx, path, null), nameof(wolfssl.CTX_load_verify_locations));
    }

    /// <summary>
    /// Require a client certificate if it connects.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when an error occurs in wolfssl.</exception>
    public void RequirePeerCertificate()
    {
        this.CallErrorAwareCtxFunction(() => wolfssl.CTX_set_verify(this.ctx, wolfssl.SSL_VERIFY_FAIL_IF_NO_PEER_CERT | wolfssl.SSL_VERIFY_PEER,
            (currentStatus, _) => currentStatus), nameof(wolfssl.CTX_set_verify));
    }

    /// <summary>
    /// Creates a new dtls connection context for a new connected client.
    /// </summary>
    /// <param name="remote">The remote endpoint of the newly connected client.</param>
    /// <returns>The created DTLSConnectionContext.</returns>
    /// <exception cref="InvalidOperationException">Thrown when an error occurs in wolfssl.</exception>
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

    /// <inheritdoc/>
    public void Dispose()
    {
        if (this.ctx != IntPtr.Zero)
        {
            wolfssl.CTX_free(this.ctx);
            this.ctx = IntPtr.Zero;
        }
    }
}
