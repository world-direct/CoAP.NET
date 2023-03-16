namespace WorldDirect.Dtls;

/// <summary>
/// Represents an exception happen when the handshake was failed.
/// </summary>
internal class HandshakeFailedException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="HandshakeFailedException"/> class.
    /// </summary>
    /// <param name="message">The message.</param>
    public HandshakeFailedException(string message)
        : base(message)
    {
            
    }
}
