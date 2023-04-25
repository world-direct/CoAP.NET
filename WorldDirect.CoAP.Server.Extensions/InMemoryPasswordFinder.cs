namespace WorldDirect.CoAP.Server.Extensions;

using Org.BouncyCastle.OpenSsl;

internal class InMemoryPasswordFinder : IPasswordFinder
{
    private readonly string password;
    public InMemoryPasswordFinder(string password)
    {
        this.password = password;
    }
    public char[] GetPassword()
    {
        return this.password.ToCharArray();
    }
}