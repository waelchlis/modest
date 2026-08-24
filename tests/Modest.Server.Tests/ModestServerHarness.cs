using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Modest.Core.Est;
using Modest.Server.Authentication;
using Modest.Server.Configuration;

namespace Modest.Server.Tests;

/// <summary>Knobs a test can turn before the host is built.</summary>
public sealed class HarnessOptions
{
    /// <summary>Which issuer the host registers.</summary>
    public IssuanceMode Mode { get; set; } = IssuanceMode.InternalCa;

    /// <summary>Value of <c>Issuance:Reenrollment:RequireMatchingIdentity</c>.</summary>
    public bool RequireMatchingIdentity { get; set; } = true;

    /// <summary>
    /// Value of <c>Est:MaxRequestBodyBytes</c>. Kept small so the 413 test does not have to push a
    /// 64 KiB body through a real socket to prove a limit that is configurable anyway.
    /// </summary>
    public int MaxRequestBodyBytes { get; set; } = 4096;

    /// <summary>Configuration entries applied last, overriding everything above.</summary>
    public Dictionary<string, string?> Configuration { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// An issuer registered after the real one, replacing it.
    /// </summary>
    /// <remarks>
    /// Two rows of the status table cannot be reached through either shipping issuer: no v1 issuer
    /// ever returns <c>Pending</c>, and none can be made to throw from outside without breaking it.
    /// The protocol layer implements both paths regardless — the 202 exists so an asynchronous issuer
    /// needs no interface change, and the 500 is the last line of defence against a leaked stack
    /// trace — so both are tested by putting a deliberately awkward issuer behind the same pipeline.
    /// Everything above the issuance boundary is still the real thing.
    /// </remarks>
    public Modest.Core.Issuance.ICertificateIssuer? IssuerOverride { get; set; }
}

/// <summary>
/// Runs <c>Modest.Server</c> the way it runs in production — real Kestrel, real TLS, real sockets —
/// and hands tests an <see cref="HttpClient"/> pointed at it.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately not <c>WebApplicationFactory</c>. Two things this suite exists to check cannot
/// survive the in-memory <c>TestServer</c>: route isolation between the two listeners is decided by
/// <c>context.Connection.LocalPort</c>, which has no meaning without real ports, and client
/// certificate authentication needs an actual TLS handshake. So the host is composed from the same
/// public <see cref="ModestHost"/> helpers <c>Program.cs</c> calls, and only the configuration
/// differs.
/// </para>
/// <para>
/// The server certificate is not validated against a trust store; the client checks the exact
/// certificate Kestrel was configured with instead. Installing a test root into the machine store
/// would be both slower and a side effect on the developer's machine, and the property under test is
/// "TLS is genuinely in front of this listener", which a thumbprint pin establishes just as well.
/// </para>
/// </remarks>
public sealed class ModestServerHarness : IAsyncDisposable
{
    /// <summary>The username in the host's configured Basic credential list.</summary>
    public const string BasicUsername = "est-operator";

    /// <summary>
    /// The password behind that credential. Distinctive on purpose: the audit-log test searches the
    /// entire captured log for it, and a common word would produce a meaningless assertion.
    /// </summary>
    public const string BasicPassword = "Corr3ct-Horse-Battery-Staple!";

    private readonly WebApplication _app;
    private readonly ConcurrentDictionary<string, HttpClient> _clients = new(StringComparer.Ordinal);
    private readonly string _tempPath;
    private bool _disposed;

    private ModestServerHarness(
        WebApplication app,
        HarnessOptions options,
        FakeUpstreamCa? upstream,
        CapturingLoggerProvider logs,
        string tempPath,
        int estPort,
        int opsPort)
    {
        _app = app;
        _tempPath = tempPath;
        Options = options;
        Upstream = upstream;
        Logs = logs;
        EstPort = estPort;
        OpsPort = opsPort;
    }

    /// <summary>The options this harness was built with.</summary>
    public HarnessOptions Options { get; }

    /// <summary>The stub issuance API, when running in delegated mode.</summary>
    public FakeUpstreamCa? Upstream { get; }

    /// <summary>Everything the host logged since it started.</summary>
    public CapturingLoggerProvider Logs { get; }

    /// <summary>Port of the TLS EST listener.</summary>
    public int EstPort { get; }

    /// <summary>Port of the plain-HTTP operations listener.</summary>
    public int OpsPort { get; }

    /// <summary>Base address of the EST listener.</summary>
    public Uri EstBaseAddress =>
        new(string.Create(CultureInfo.InvariantCulture, $"https://127.0.0.1:{EstPort}"));

    /// <summary>Base address of the operations listener.</summary>
    public Uri OpsBaseAddress =>
        new(string.Create(CultureInfo.InvariantCulture, $"http://127.0.0.1:{OpsPort}"));

    /// <summary>Builds, configures and starts a host.</summary>
    public static async Task<ModestServerHarness> StartAsync(Action<HarnessOptions>? configure = null)
    {
        var options = new HarnessOptions();
        configure?.Invoke(options);

        string tempPath = Path.Combine(
            Path.GetTempPath(),
            "modest-server-tests",
            Guid.NewGuid().ToString("n", CultureInfo.InvariantCulture));
        Directory.CreateDirectory(tempPath);

        FakeUpstreamCa? upstream = options.Mode == IssuanceMode.HttpDelegate
            ? FakeUpstreamCa.StartIssuing()
            : null;

        try
        {
            int estPort = ReserveFreePort();
            int opsPort = ReserveFreePort();

            Dictionary<string, string?> settings =
                BuildConfiguration(options, tempPath, upstream, estPort, opsPort);

            var logs = new CapturingLoggerProvider();

            // ContentRootPath points at an empty scratch directory so the host does not pick up the
            // appsettings.json that the Modest.Server project reference drops into the test output.
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                ContentRootPath = tempPath,
                EnvironmentName = Environments.Production,
                ApplicationName = typeof(ModestHost).Assembly.GetName().Name,
            });

            builder.Configuration.AddInMemoryCollection(settings);

            builder.Logging.ClearProviders();
            builder.Logging.AddProvider(logs);
            builder.Logging.SetMinimumLevel(LogLevel.Debug);

            ModestHost.ConfigureServices(builder);

            if (options.IssuerOverride is not null)
            {
                // Registered after ConfigureServices, so the last registration is the one resolved.
                builder.Services.AddSingleton(options.IssuerOverride);
            }

            ModestHost.ConfigureKestrel(builder);

            WebApplication app = ModestHost.BuildApp(builder);
            await app.StartAsync().ConfigureAwait(false);

            return new ModestServerHarness(app, options, upstream, logs, tempPath, estPort, opsPort);
        }
        catch
        {
            upstream?.Dispose();
            TryDelete(tempPath);
            throw;
        }
    }

    private static Dictionary<string, string?> BuildConfiguration(
        HarnessOptions options,
        string tempPath,
        FakeUpstreamCa? upstream,
        int estPort,
        int opsPort)
    {
        (string caPfxPath, string caPasswordPath) = TestPki.Ca.WriteIssuerPfx(tempPath, TestPki.PfxPassword);

        string rootPemPath = Path.Combine(tempPath, "root.pem");
        File.WriteAllText(rootPemPath, TestPki.Ca.Root.ExportCertificatePem());

        string chainPemPath = TestPki.Ca.WriteChainPem(tempPath);

        string serverPfxPath = Path.Combine(tempPath, "tls.pfx");
        string serverPasswordPath = Path.Combine(tempPath, "tls.pass");
        File.WriteAllBytes(serverPfxPath, TestPki.ServerPfx);
        File.WriteAllText(serverPasswordPath, TestPki.PfxPassword);

        (string hash, string salt, int iterations) =
            StaticConfigBasicCredentialValidator.CreateVerifier(BasicPassword, iterations: 10_000);

        var settings = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            // Kestrel's own URL configuration must not add a third listener behind the two the
            // host configures explicitly.
            ["urls"] = string.Empty,

            ["Logging:LogLevel:Default"] = "Debug",
            ["Logging:LogLevel:Microsoft.AspNetCore"] = "Warning",

            ["Kestrel:Est:Port"] = Str(estPort),
            ["Kestrel:Est:CertificatePath"] = serverPfxPath,
            ["Kestrel:Est:CertificatePasswordFile"] = serverPasswordPath,
            ["Kestrel:Ops:Port"] = Str(opsPort),

            ["Est:MaxRequestBodyBytes"] = Str(options.MaxRequestBodyBytes),

            ["Authentication:AllowClientCertificate"] = "true",
            ["Authentication:AllowHttpBasic"] = "true",
            ["Authentication:AllowUntrustedClientCertificates"] = "false",
            ["Authentication:ClientCertificateTrustStorePath"] = chainPemPath,
            ["Authentication:BasicCredentials:0:Username"] = BasicUsername,
            ["Authentication:BasicCredentials:0:PasswordHash"] = hash,
            ["Authentication:BasicCredentials:0:Salt"] = salt,
            ["Authentication:BasicCredentials:0:Iterations"] = Str(iterations),

            ["Issuance:Mode"] = options.Mode.ToString(),
            ["Issuance:Reenrollment:RequireMatchingIdentity"] =
                options.RequireMatchingIdentity ? "true" : "false",

            ["Issuance:InternalCa:CertificatePath"] = caPfxPath,
            ["Issuance:InternalCa:CertificatePasswordFile"] = caPasswordPath,
            ["Issuance:InternalCa:AdditionalChainCertificatePaths:0"] = rootPemPath,
            ["Issuance:InternalCa:MinimumRsaKeySizeBits"] = "2048",

            ["Issuance:HttpDelegate:BaseAddress"] = upstream?.BaseAddress ?? "http://127.0.0.1:1",
            ["Issuance:HttpDelegate:IssuePath"] = FakeUpstreamCa.IssuePath,
            ["Issuance:HttpDelegate:StaticCaChainPath"] = chainPemPath,
            ["Issuance:HttpDelegate:TimeoutSeconds"] = "10",

            // No retries: the only failing-upstream test asserts a status mapping, and exponential
            // backoff would add seconds to the suite to re-prove Polly works.
            ["Issuance:HttpDelegate:MaxRetryAttempts"] = "0",
        };

        foreach (KeyValuePair<string, string?> entry in options.Configuration)
        {
            settings[entry.Key] = entry.Value;
        }

        return settings;

        static string Str(int value) => value.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Reserves a port by binding it and letting it go again.
    /// </summary>
    /// <remarks>
    /// Bound on <see cref="IPAddress.Any"/> rather than loopback because the host calls
    /// <c>ListenAnyIP</c>; a port free on loopback alone would not be enough.
    /// </remarks>
    private static int ReserveFreePort()
    {
        var listener = new TcpListener(IPAddress.Any, 0);
        listener.Start();
        try
        {
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally
        {
            listener.Stop();
        }
    }

    /// <summary>Encodes an HTTP Basic <c>Authorization</c> header value.</summary>
    public static string BasicHeader(string username, string password) =>
        "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));

    /// <summary>The <c>Authorization</c> header for the host's one configured credential.</summary>
    public static string ValidBasicHeader() => BasicHeader(BasicUsername, BasicPassword);

    /// <summary>
    /// A client for the EST listener, optionally presenting a TLS client certificate.
    /// </summary>
    /// <remarks>
    /// One client per certificate, never shared: connection pooling would otherwise reuse a TLS
    /// connection established with somebody else's certificate, and the mutual-TLS tests would be
    /// asserting on whichever request happened to open the connection.
    /// </remarks>
    public HttpClient EstClient(X509Certificate2? clientCertificate = null)
    {
        string key = clientCertificate?.Thumbprint ?? "<none>";
        return _clients.GetOrAdd(key, _ => CreateEstClient(clientCertificate));
    }

    /// <summary>A plain-HTTP client for the operations listener.</summary>
    public HttpClient OpsClient() =>
        _clients.GetOrAdd(
            "<ops>",
            static _ => new HttpClient { Timeout = TimeSpan.FromSeconds(30) });

    private static HttpClient CreateEstClient(X509Certificate2? clientCertificate)
    {
        string expectedThumbprint = TestPki.ServerCertificate.Thumbprint;

        var sslOptions = new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                certificate is not null &&
                string.Equals(
                    certificate.GetCertHashString(),
                    expectedThumbprint,
                    StringComparison.OrdinalIgnoreCase),
        };

        if (clientCertificate is not null)
        {
            sslOptions.ClientCertificates = new X509CertificateCollection { clientCertificate };

            // Explicit selection rather than letting the stack filter by acceptableIssuers: Kestrel
            // sends no issuer hints, and an empty hint list makes some platforms send nothing at all.
            sslOptions.LocalCertificateSelectionCallback = (_, _, _, _, _) => clientCertificate;
        }

        var handler = new SocketsHttpHandler
        {
            SslOptions = sslOptions,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        };

        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
    }

    /// <summary>Issues a GET against the EST listener.</summary>
    public Task<HttpResponseMessage> GetEstAsync(
        string path,
        string? authorization = null,
        X509Certificate2? clientCertificate = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, new Uri(EstBaseAddress, path));
        if (authorization is not null)
        {
            request.Headers.TryAddWithoutValidation("Authorization", authorization);
        }

        return EstClient(clientCertificate).SendAsync(request);
    }

    /// <summary>
    /// Posts an enrollment body to the EST listener.
    /// </summary>
    /// <param name="contentType">
    /// Null sends no <c>Content-Type</c> header at all, which is a distinct case from sending the
    /// wrong one and has its own row in the status table.
    /// </param>
    public Task<HttpResponseMessage> PostEstAsync(
        string path,
        string body,
        string? contentType = EstMediaTypes.Pkcs10,
        string? authorization = null,
        X509Certificate2? clientCertificate = null)
    {
        var content = new StringContent(body, Encoding.ASCII);
        content.Headers.ContentType =
            contentType is null ? null : MediaTypeHeaderValue.Parse(contentType);

        var request = new HttpRequestMessage(HttpMethod.Post, new Uri(EstBaseAddress, path))
        {
            Content = content,
        };

        if (authorization is not null)
        {
            request.Headers.TryAddWithoutValidation("Authorization", authorization);
        }

        return EstClient(clientCertificate).SendAsync(request);
    }

    /// <summary>Issues a GET against the plain-HTTP operations listener.</summary>
    public Task<HttpResponseMessage> GetOpsAsync(string path) =>
        OpsClient().GetAsync(new Uri(OpsBaseAddress, path));

    /// <summary>Posts to the plain-HTTP operations listener.</summary>
    public Task<HttpResponseMessage> PostOpsAsync(
        string path, string body, string? contentType = EstMediaTypes.Pkcs10, string? authorization = null)
    {
        var content = new StringContent(body, Encoding.ASCII);
        content.Headers.ContentType =
            contentType is null ? null : MediaTypeHeaderValue.Parse(contentType);

        var request = new HttpRequestMessage(HttpMethod.Post, new Uri(OpsBaseAddress, path))
        {
            Content = content,
        };

        if (authorization is not null)
        {
            request.Headers.TryAddWithoutValidation("Authorization", authorization);
        }

        return OpsClient().SendAsync(request);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        foreach (HttpClient client in _clients.Values)
        {
            client.Dispose();
        }

        _clients.Clear();

        try
        {
            await _app.StopAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        await _app.DisposeAsync().ConfigureAwait(false);

        Upstream?.Dispose();
        TryDelete(_tempPath);
    }

    private static void TryDelete(string path)
    {
        try
        {
            Directory.Delete(path, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
