namespace WorldDirect.CoAP.Hosting.Configuration
{
    public class CertificateOption
    {
        public bool IsFile => !string.IsNullOrEmpty(this.Path);
        public string? Path { get; set; }
        public string? KeyPath { get; set; }
        public string? Password { get; set; }


        public bool IsFromStore => !string.IsNullOrEmpty(this.Subject);
        public string? Subject { get; set; }
        public string? Store { get; set; }
        public string Location { get; set; } = "CurrentUser";
        public bool AllowInvalid { get; set; }
    }
}
