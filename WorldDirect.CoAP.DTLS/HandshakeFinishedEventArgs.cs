namespace WorldDirect.CoAP.DTLS;

/// <summary>
/// Represents event args when a handshake is completed.
/// </summary>
internal class HandshakeFinishedEventArgs : EventArgs
{
    /// <summary>
    /// Gets or sets a flag indicating the success of a handshake.
    /// </summary>
    public bool Successful { get; set; }
}
