namespace WorldDirect.Dtls;

using System.Net;

internal class SendDTLSDataContext
{
    private Action<Memory<byte>, IPEndPoint> sendCallback;

    public SendDTLSDataContext(Action<Memory<byte>, IPEndPoint> callback)
    {
        this.sendCallback = callback;
    }

    public void SendData(Memory<byte> data, IPEndPoint endpoint)
    {
        this.sendCallback(data, endpoint);
    }
}