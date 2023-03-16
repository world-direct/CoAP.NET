namespace WorldDirect.Dtls;

/// <summary>
/// Event args when the dtls session throw an error.
/// </summary>
internal class DTLSErrorEventArgs : EventArgs
{
    /// <summary>
    /// Gets the message of the error.
    /// </summary>
    public string Message { get; }

    /// <summary>
    /// Gets the optional exception.
    /// </summary>
    public Exception? Exception { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="DTLSErrorEventArgs"/> class.
    /// </summary>
    /// <param name="message">The message of the error.</param>
    public DTLSErrorEventArgs(string message)
    : this(message, null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DTLSErrorEventArgs"/> class.
    /// </summary>
    /// <param name="message">The message of the error.</param>
    /// <param name="exception">The exception of the error.</param>
    public DTLSErrorEventArgs(string message, Exception? exception)
    {
        Message = message;
        Exception = exception;
    }
}
