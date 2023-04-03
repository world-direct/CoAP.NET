namespace WorldDirect.Dtls;

using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

public class ReceivedDTLSPacketEventArgs
{
    public byte[] Payload { get; set; }
    public IPEndPoint Remote { get; set; }
    public X509Certificate Certificate { get; set; }
}

public class DTLSServer
{
    private readonly IServiceProvider serviceProvider;
    private readonly BcTlsCrypto crypto = new BcTlsCrypto();
    private readonly UdpServer server;

    private readonly ConcurrentDictionary<IPEndPoint, DTLSSession> sessions =
        new();

    public DTLSServer(ushort port, IServiceProvider serviceProvider)
    {
        this.serviceProvider = serviceProvider;
        this.server = new UdpServer(port, 1024);
        this.server.ReceivedData += Server_ReceivedData;
    }

    public event EventHandler<ReceivedDTLSPacketEventArgs>? ReceivedData;

    private void Server_ReceivedData(object? sender, ReceivedPacketEventArgs e)
    {
        if (!this.sessions.ContainsKey(e.Remote))
        {
            Console.WriteLine($"New DtlsSession created with {e.Remote}");
            var newTransport = new UdpTransport(this.server, e.Remote, e.Payload, this.serviceProvider.GetRequiredService<ILogger<UdpTransport>>());
            var newSession = new DTLSSession(this.crypto, newTransport, this.serviceProvider.GetRequiredService<ILogger<DTLSSession>>());
            this.sessions[e.Remote] = newSession;
            newSession.ReceivedData += (sender, args) =>
            {
                var buffer = new byte[this.server.MaxMessageSize];
                DTLSSession session = (DTLSSession)sender;
                var len = session.Receive(buffer, TimeSpan.FromMilliseconds(1));
                this.ReceivedData?.Invoke(this, new ReceivedDTLSPacketEventArgs()
                {
                    Certificate = session.ClientCertificate,
                    Payload = buffer.Take(len).ToArray(),
                    Remote = session.Remote,
                });
            };
            newSession.Start();
        }
    }

    public void SendTo(ReadOnlySpan<byte> payload, IPEndPoint remote)
    {
        if (this.sessions.TryGetValue(remote, out var session))
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
