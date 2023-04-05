namespace WorldDirect.Dtls;

using System.Collections.Concurrent;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;


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

public class DTLSServer
{
    private readonly TimeSpan sessionTimeout;
    private readonly IMemoryCache cache;
    private readonly IServiceProvider serviceProvider;
    private readonly BcTlsCrypto crypto = new BcTlsCrypto();
    private readonly UdpServer server;
    private readonly ILogger<DTLSServer> logger;
    private readonly TlsPskIdentityManager pskManager = new PskManager();

    public DTLSServer(ushort port, TimeSpan sessionTimeout, IMemoryCache cache, IServiceProvider serviceProvider)
    {
        this.sessionTimeout = sessionTimeout;
        this.cache = cache;
        this.serviceProvider = serviceProvider;
        this.server = new UdpServer(port, 1024);
        this.server.ReceivedData += ServerReceivedData;
        this.logger = serviceProvider.GetRequiredService<ILogger<DTLSServer>>();
    }

    public event EventHandler<ReceivedDTLSPacketEventArgs>? ReceivedData;

    private void ServerReceivedData(object? sender, ReceivedPacketEventArgs e)
    {
        this.cache.GetOrCreate(e.Remote, entry =>
        {
            entry.SlidingExpiration = this.sessionTimeout;
            entry.PostEvictionCallbacks.Add(new PostEvictionCallbackRegistration()
            {
                EvictionCallback = (key, value, reason, state) =>
                {
                    var rem = (IPEndPoint)key;
                    this.logger.LogDebug("Removed DTLS Connection to {remote} because of timeout", rem);
                },
                State = this,
            });
            this.logger.LogDebug("New DtlsSession created with {remote}", e.Remote);
            var newTransport = new UdpTransport(this.server, e.Remote, e.Payload, this.serviceProvider.GetRequiredService<ILogger<UdpTransport>>());
            var newSession = new DTLSSession(this.crypto, newTransport, this.pskManager, this.serviceProvider.GetRequiredService<ILogger<DTLSSession>>());
            newSession.ReceivedData += SessionReceivedData;
            newSession.HandshakeFinished += SessionHandshakeCompleted;
            newSession.Start();
            return newSession;
        });
    }

    private void SessionHandshakeCompleted(object? sender, HandshakeFinishedEventArgs e)
    {
        var session = (DTLSSession)sender!;
        if (!e.Result)
        {
            this.cache.Remove(session.Remote);
        }
    }

    private void SessionReceivedData(object? sender, EventArgs args)
    {
        var buffer = new byte[this.server.MaxMessageSize];
        DTLSSession session = (DTLSSession)sender;
        var len = session.Receive(buffer, TimeSpan.FromMilliseconds(1));
        if (len == 0)
        {
            // WHAT TO DO?
            throw new NotImplementedException("happens this because of a close request from client?");
        }
        this.ReceivedData?.Invoke(this, new ReceivedDTLSPacketEventArgs()
        {
            PublicIdentifier = session.PublicIdentifier,
            Payload = buffer.Take(len).ToArray(),
            Remote = session.Remote,
        });
    }

    public void SendTo(ReadOnlySpan<byte> payload, IPEndPoint remote)
    {
        if (this.cache.TryGetValue<DTLSSession>(remote, out var session))
        {
            session.Send(payload);
        }
    }

    public void Start()
    {
        this.server.Start();
    }

    public void Stop()
    {
        this.server.Stop();
    }


}
