namespace WorldDirect.Dtls;

using Org.BouncyCastle.Tls;

public class PskManager : TlsPskIdentityManager
{
    public byte[] GetHint()
    {
        // not needed in server mode
        return null;
    }

    public byte[] GetPsk(byte[] identity)
    {
        return new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, };
    }
}