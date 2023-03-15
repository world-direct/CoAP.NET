namespace WorldDirect.Dtls;

internal class DTLSErrorEventArgs : EventArgs
{
    public string Message { get; }

    public Exception? Exception { get; }

    public DTLSErrorEventArgs(string message)
    : this(message, null)
    {
    }

    public DTLSErrorEventArgs(string message, Exception? exception)
    {
        Message = message;
        Exception = exception;
    }
}
