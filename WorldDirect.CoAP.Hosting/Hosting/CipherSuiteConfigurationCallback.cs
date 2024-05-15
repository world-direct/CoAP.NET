namespace WorldDirect.CoAP.Hosting.Hosting;

/// <summary>
/// The delegate to add cipher suites to a DTLS server.
/// </summary>
/// <param name="cipherSuites">The currently enabled cipher suites.</param>
public delegate void CipherSuiteConfigurationCallback(ISet<int> cipherSuites);
