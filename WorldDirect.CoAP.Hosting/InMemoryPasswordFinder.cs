namespace WorldDirect.CoAP.Hosting;

using Org.BouncyCastle.OpenSsl;

/// <summary>
/// A helper class for decrypting of files.
/// </summary>
internal class InMemoryPasswordFinder : IPasswordFinder
{
    private readonly string password;
    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryPasswordFinder"/> class.
    /// </summary>
    /// <param name="password">The password.</param>
    public InMemoryPasswordFinder(string password)
    {
        this.password = password;
    }

    /// <inheritdoc />
    public char[] GetPassword()
    {
        return this.password.ToCharArray();
    }
}
