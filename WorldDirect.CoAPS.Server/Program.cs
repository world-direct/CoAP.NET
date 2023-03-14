// See https://aka.ms/new-console-template for more information


using System.Security.Cryptography.X509Certificates;
using WorldDirect.Dtls;

var dtlsconfig = new DTLSConfig() {CAFile = "ca-cert.pem", CertificateFile = "server-cert.pem", Port = 11111, PrivateKeyFile = "server-key.pem"};
var dtlsStack = new WolfDTLSStack(dtlsconfig);
dtlsStack.ReceivedData += (sender, data) =>
{
    Task.Run(async () =>
    {
        Console.WriteLine(data.Remote.Certificate.Subject);
        await Task.Delay(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
        dtlsStack.SendTo(data.Payload, data.Remote.Remote);
    });
};


dtlsStack.Start();

Console.ReadKey();
