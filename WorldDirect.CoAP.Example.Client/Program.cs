using System;

namespace WorldDirect.CoAP.Example.Client
{
    using System.IO;
    using System.Threading;
    using System.Threading.Tasks;

    class Program
    {
        static async Task Main(string[] args)
        {
            NLog.LogManager.GetCurrentClassLogger().Debug("Hello");

            await Task.Delay(5000).ConfigureAwait(false);

            //await DoPut().ConfigureAwait(false);

            while (true)
            {
                try
                {
                    await DoPut().ConfigureAwait(false);
                    //await DoGet().ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }

            Console.ReadLine();
        }


        private static async Task DoGet()
        {
            var req = Request.NewGet();
            req.URI = new Uri("coap://localhost");
            req.TimedOut += (sender, args) =>
            {
                Console.WriteLine("Get Timeout");
            };

            var client = new CoapClient();
            var response = await client.SendAsync(req, CancellationToken.None);
            Console.WriteLine($"Get completed: {response.ResponseText}");
        }

        private static async Task DoPut()
        {
            var client = new CoapClient();
            var req = Request.NewPut();

            req.TimedOut += (sender, eventArgs) =>
            {
                Console.WriteLine("PUT Timeout");
            };

            req.MaxRetransmit = 2;
            req.URI = new Uri("coap://localhost/image");
            var payload = File.ReadAllBytes("C:\\dev\\src\\spikes\\FirmwareDeployer\\FirmwareDeployer\\bin\\Debug\\netcoreapp3.1\\aligned.bin");
            req.SetPayload(payload, MediaType.ApplicationOctetStream);

            var rsp = await client.SendAsync(req, CancellationToken.None).ConfigureAwait(false);
            Console.WriteLine($"PUT completed: {rsp.StatusCode}");
        }
    }
}
