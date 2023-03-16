namespace WorldDirect.Dtls;

/// <summary>
/// Represents event args after a dtls handshake.
/// </summary>
internal class HandshakeEventArgs : EventArgs
{
    /// <summary>
    /// Gets or sets whether the handshake was successful.
    /// </summary>
    public bool Success { get; set; }
}
