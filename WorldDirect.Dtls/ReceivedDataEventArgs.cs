namespace WorldDirect.Dtls;

internal class ReceivedDataEventArgs : EventArgs
{
    public byte[] Bytes { get; set; }
}