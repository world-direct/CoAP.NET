namespace WorldDirect.Dtls;

/// <summary>
/// Represents the event args used to notify new data was received.
/// </summary>
internal class ReceivedDataEventArgs : EventArgs
{
    /// <summary>
    /// Gets or sets the payload.
    /// </summary>
    public byte[] Bytes { get; set; }
}
