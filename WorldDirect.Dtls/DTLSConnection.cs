namespace WorldDirect.Dtls;

using System.Net;
using System.Security.Cryptography.X509Certificates;

internal class DTLSConnection
{
    private readonly DTLSConnectionContext context;
    private readonly int bufferSize;
    public event EventHandler<HandshakeEventArgs> HandshakeCompleted;
    public event EventHandler<ReceivedDataEventArgs> Received;
    public event EventHandler<DTLSErrorEventArgs> ErrorOccured;

    private bool handshakeCompleted = false;

    public DTLSConnection(DTLSConnectionContext context, int bufferSize)
    {
        this.context = context;
        this.bufferSize = bufferSize;
    }

    public IPEndPoint Remote => this.context.Remote;
    public X509Certificate? Certificate => this.context.Certificate;

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

    public void SendData(byte[] data)
    {
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
            if (this.context.accept())
            {
                this.handshakeCompleted = true;
                this.HandshakeCompleted?.Invoke(this, new HandshakeEventArgs() {Success = true,});
            }
        }
        catch (HandshakeFailedException)
        {
            this.HandshakeCompleted?.Invoke(this, new HandshakeEventArgs() {Success = false,});
        }
        catch (InvalidOperationException e)
        {
            this.OnErrorOccured("Could not finish handshake", e);
        }
    }

    private void OnErrorOccured(string message, Exception? e = null)
    {
        this.ErrorOccured?.Invoke(this, new DTLSErrorEventArgs(message, e));
    }
}
