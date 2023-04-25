namespace WorldDirect.CoAP.Server.Extensions;

using DTLS;

internal class DTLSFactory : IDTLSFactory
{
    private readonly DTLSServerBuilder builder;

    public DTLSFactory(DTLSServerBuilder builder)
    {
        this.builder = builder;
    }
    public DTLSServer CreateServer()
    {
        return this.builder.Build();
    }
}