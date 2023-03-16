namespace WorldDirect.Dtls;

using System.Net;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Represents a DTLS connection with a dtls client.
/// </summary>
internal class DTLSConnection
{
    private readonly DTLSConnectionContext context;
    private readonly int bufferSize;
    public event EventHandler<HandshakeEventArgs>? HandshakeCompleted;
    public event EventHandler<ReceivedDataEventArgs>? Received;
    public event EventHandler<DTLSErrorEventArgs>? ErrorOccured;

    private bool handshakeCompleted = false;

    /// <summary>
    /// Initializes a new instance of the <see cref="DTLSConnection"/> class.
    /// </summary>
    /// <param name="context">The connectioncontext to use.</param>
    /// <param name="bufferSize">The buffersize to use for receiving data.</param>
    public DTLSConnection(DTLSConnectionContext context, int bufferSize)
    {
        this.context = context;
        this.bufferSize = bufferSize;
    }

    /// <summary>
    /// Gets the remote IP Endpoint.
    /// </summary>
    public IPEndPoint Remote => this.context.Remote;

    /// <summary>
    /// Gets the certificate received while handshaking.
    /// </summary>
    public X509Certificate? Certificate => this.context.Certificate;

    /// <summary>
    /// Handle the received UDP payload.
    /// </summary>
    /// <param name="input">The bytes of the UDP message.</param>
    public void HandleInput(Memory<byte> input)
    {
        this.context.ReceivedData(input.ToArray());
        if (!this.handshakeCompleted)
        {
            this.PerformHandshake();
        }
        else
        {
            this.ReadData();
        }
    }

    /// <summary>
    /// Send data encrypted to the remote endpoint.
    /// </summary>
    /// <param name="data">The bytes to send.</param>
    public void SendData(byte[] data)
    {
        if (!this.handshakeCompleted)
        {
            return;
        }
        try
        {
            this.context.SendData(data);
        }
        catch (Exception ex)
        {
            this.OnErrorOccured("Could not send data", ex);
        }
    }

    private void ReadData()
    {
        var buffer = new byte[this.bufferSize];
        int ret = 0;
        try
        {
            ret = this.context.TryReadData(buffer);
        }
        catch (Exception ex)
        {
            this.OnErrorOccured("Could not read data", ex);
        }
        if (ret > 0)
        {
            this.Received?.Invoke(this, new ReceivedDataEventArgs() {Bytes = buffer.Take(ret).ToArray(),});
        }
    }

    private void PerformHandshake()
    {
        try
        {
            if (this.context.Accept())
            {
                this.handshakeCompleted = true;
                this.HandshakeCompleted?.Invoke(this, new HandshakeEventArgs() {Success = true,});
            }
        }
        catch (HandshakeFailedException)
        {
            this.HandshakeCompleted?.Invoke(this, new HandshakeEventArgs() {Success = false,});
        }
        catch (Exception e)
        {
            this.OnErrorOccured("Could not finish handshake", e);
        }
    }

    private void OnErrorOccured(string message, Exception? e = null)
    {
        this.ErrorOccured?.Invoke(this, new DTLSErrorEventArgs(message, e));
    }
}
