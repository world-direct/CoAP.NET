namespace WorldDirect.CoAP.DTLS;

using System.Reflection;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

/// <summary>
/// Represents the necessary information to write a ssl keylog file for (D)TLS 1.2 to decrypt communication.
/// </summary>
public struct DTLS12KeyFileData
{
    /// <summary>
    /// Create the data from a <see cref="TlsSecret"/>.
    /// </summary>
    /// <remarks>Helper because data of a tls secret cant be extracted easily.</remarks>
    /// <param name="clientRandom">The client random of the clients first handshake message.</param>
    /// <param name="secret">The pre master secret.</param>
    /// <returns>The created data if it was possible or null on failure.</returns>
    public static DTLS12KeyFileData? FromSecret(byte[]? clientRandom, TlsSecret? secret)
    {
        if (clientRandom == null || secret == null)
        {
            return null;
        }

        // cant use extract of MasterSecret -> the secret would be lost.
        if (secret.GetType() == typeof(BcTlsSecret))
        {
            var fieldInfo = typeof(BcTlsSecret).GetField("m_data", BindingFlags.NonPublic | BindingFlags.Instance);
            if (fieldInfo == null)
            {
                return null;
            }
            var secretData = (byte[]?)fieldInfo.GetValue(secret);
            if (secretData == null)
            {
                return null;
            }
            return new DTLS12KeyFileData(clientRandom, secretData);
        }

        return null;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DTLS12KeyFileData"/> class.
    /// </summary>
    /// <param name="clientRandom">The client random of the clients first handshake message.</param>
    /// <param name="preMasterSecret">The pre master secret.</param>
    public DTLS12KeyFileData(byte[] clientRandom, byte[] preMasterSecret)
    {
        this.ClientRandom = clientRandom;
        this.PreMasterSecret = preMasterSecret;
    }

    /// <summary>
    /// Gets or sets the client random of the first handshake message.
    /// </summary>
    public byte[] ClientRandom { get; set; }

    /// <summary>
    /// Gets or sets the pre master secret.
    /// </summary>
    public byte[] PreMasterSecret { get; set; }
}