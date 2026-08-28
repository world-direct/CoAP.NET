namespace WorldDirect.CoAP.DTLS;

/// <summary>
/// Represents the configuration of a dtls session.
/// </summary>
public class DTLSSessionConfig
{
    /// <summary>
    /// Gets or sets the timeout of a session.
    /// </summary>
    public TimeSpan SessionTimeout { get; set; }

    /// <summary>
    /// Gets or sets the maximum packet length of a udp payload.
    /// </summary>
    public int MaxPacketLength { get; set; }

    /// <summary>
    /// Gets or sets the maximum duration of a handshake.
    /// </summary>
    public TimeSpan HandshakeTimeout { get; set; }
}
