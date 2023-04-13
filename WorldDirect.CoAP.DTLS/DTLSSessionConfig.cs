namespace WorldDirect.CoAP.DTLS;

public class DTLSSessionConfig
{
    public TimeSpan SessionTimeout { get; set; }

    public int MaxPacketLength { get; set; }
}