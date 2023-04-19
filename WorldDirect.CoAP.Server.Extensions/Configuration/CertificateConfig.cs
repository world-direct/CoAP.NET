namespace WorldDirect.CoAP.Server.Extensions.Configuration
{
    using Microsoft.Extensions.Configuration;

    public class CertificateConfig
    {
        public CertificateConfig(IConfiguration configuration)
        {
            this.Configuration = configuration;
            this.Path = configuration[nameof(this.Path)];
            this.KeyPath = configuration[nameof(this.KeyPath)];
            this.Password = configuration[nameof(this.Password)];
            this.Subject = configuration[nameof(this.Subject)];
            this.Store = configuration[nameof(this.Store)];
            this.Location = configuration[nameof(this.Location)] == null ? "CurrentUser" : configuration[nameof(this.Location)];
            this.AllowInvalid = configuration[nameof(this.AllowInvalid)] != null && bool.Parse(configuration[nameof(this.AllowInvalid)]);
        }

        public IConfiguration Configuration { get; }

        public bool IsFile => !string.IsNullOrEmpty(this.Path);
        public string? Path { get; set; }
        public string? KeyPath { get; set; }
        public string? Password { get; set; }


        public bool IsFromStore => !string.IsNullOrEmpty(this.Subject);
        public string? Subject { get; set; }
        public string? Store { get; set; }
        public string? Location { get; set; }
        public bool AllowInvalid { get; set; }
    }
}
