using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Modest.Core.Issuance;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Modest.Issuance.HttpDelegate.Tests;

/// <summary>
/// Stands up the issuer exactly the way production does: a real <see cref="ServiceCollection"/>, the
/// real <c>AddHttpDelegateIssuer</c> extension, and an <see cref="IConfiguration"/> pointing at a
/// live WireMock server.
/// </summary>
/// <remarks>
/// Deliberately not a hand-built <c>HttpClient</c>. The Basic-auth header, the base address, the
/// per-attempt timeout and the retry policy are all produced by the DI extension, and each of them
/// is something this suite asserts on — an approximation of the wiring would only prove the
/// approximation correct.
/// </remarks>
public sealed class IssuerHarness : IDisposable
{
    /// <summary>The upstream password used unless a test overrides it. Distinctive so log searches are unambiguous.</summary>
    public const string DefaultPassword = "Sup3rSecret-Upstream-Passw0rd";

    /// <summary>The upstream username used unless a test overrides it.</summary>
    public const string DefaultUsername = "modest-gateway";

    /// <summary>The issuance path used unless a test overrides it.</summary>
    public const string DefaultIssuePath = "/api/v1/issue";

    private readonly ServiceProvider _provider;
    private bool _disposed;

    private IssuerHarness(
        ServiceProvider provider,
        WireMockServer? server,
        CapturingLoggerProvider logs,
        string tempPath,
        string password,
        string issuePath)
    {
        _provider = provider;
        Server = server;
        Logs = logs;
        TempPath = tempPath;
        Password = password;
        IssuePath = issuePath;
    }

    /// <summary>The stub upstream, or null when the harness deliberately points at a dead address.</summary>
    public WireMockServer? Server { get; }

    /// <summary>Everything the issuer (and the HTTP stack under it) logged.</summary>
    public CapturingLoggerProvider Logs { get; }

    /// <summary>Scratch directory holding the password file and the static CA chain file.</summary>
    public string TempPath { get; }

    /// <summary>The upstream password this harness configured.</summary>
    public string Password { get; }

    /// <summary>The configured issuance path.</summary>
    public string IssuePath { get; }

    /// <summary>The subject under test, resolved from the container.</summary>
    public HttpDelegateIssuer Issuer => _provider.GetRequiredService<HttpDelegateIssuer>();

    /// <summary>The same instance, seen through the interface the protocol layer uses.</summary>
    public ICertificateIssuer AsInterface => _provider.GetRequiredService<ICertificateIssuer>();

    /// <summary>Requests the stub upstream actually received, in arrival order.</summary>
    public IReadOnlyList<WireMock.Logging.ILogEntry> ReceivedRequests =>
        Server is null ? [] : [.. Server.LogEntries];

    public static IssuerHarness Create(
        string? username = DefaultUsername,
        string password = DefaultPassword,
        bool passwordFileTrailingNewline = false,
        bool writePasswordFile = true,
        // 1 rather than 0: MaxRetryAttempts=0 currently throws inside Polly (see
        // RetryPolicyTests.Zero_retry_attempts_is_a_legal_configuration), so the default here keeps
        // unrelated tests off that fault while still being cheap.
        int maxRetryAttempts = 1,
        int timeoutSeconds = 30,
        int maxCsrSizeBytes = 16 * 1024,
        bool writeChainFile = true,
        string issuePath = DefaultIssuePath,
        bool pointAtDeadPort = false)
    {
        string tempPath = Path.Combine(
            Path.GetTempPath(),
            "modest-httpdelegate-tests",
            Guid.NewGuid().ToString("n", CultureInfo.InvariantCulture));
        Directory.CreateDirectory(tempPath);

        WireMockServer? server = pointAtDeadPort ? null : WireMockServer.Start();
        string baseAddress = pointAtDeadPort
            ? string.Create(CultureInfo.InvariantCulture, $"http://127.0.0.1:{FindClosedPort()}")
            : server!.Url!;

        string passwordFile = Path.Combine(tempPath, "upstream.pass");
        if (writePasswordFile)
        {
            File.WriteAllText(passwordFile, passwordFileTrailingNewline ? password + "\n" : password);
        }

        string chainPath = writeChainFile
            ? SharedPki.Ca.WriteChainPem(tempPath)
            : Path.Combine(tempPath, "absent-chain.pem");

        var settings = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["Issuance:HttpDelegate:BaseAddress"] = baseAddress,
            ["Issuance:HttpDelegate:IssuePath"] = issuePath,
            ["Issuance:HttpDelegate:StaticCaChainPath"] = chainPath,
            ["Issuance:HttpDelegate:TimeoutSeconds"] = timeoutSeconds.ToString(CultureInfo.InvariantCulture),
            ["Issuance:HttpDelegate:MaxRetryAttempts"] = maxRetryAttempts.ToString(CultureInfo.InvariantCulture),
            ["Issuance:HttpDelegate:MaxCsrSizeBytes"] = maxCsrSizeBytes.ToString(CultureInfo.InvariantCulture),
        };

        if (username is not null)
        {
            settings["Issuance:HttpDelegate:BasicAuthUsername"] = username;
            settings["Issuance:HttpDelegate:BasicAuthPasswordFile"] = passwordFile;
        }

        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var logs = new CapturingLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(builder =>
        {
            builder.SetMinimumLevel(LogLevel.Trace);
            builder.AddProvider(logs);
        });

        services.AddHttpDelegateIssuer(configuration);

        ServiceProvider provider = services.BuildServiceProvider();
        return new IssuerHarness(provider, server, logs, tempPath, password, issuePath);
    }

    /// <summary>Stubs the issuance endpoint with a raw body and status.</summary>
    public IssuerHarness StubIssuance(
        string body, int status = 200, string contentType = "application/json", TimeSpan? delay = null)
    {
        IResponseBuilder response = Response.Create()
            .WithStatusCode(status)
            .WithHeader("Content-Type", contentType)
            .WithBody(body);

        if (delay is not null)
        {
            response = response.WithDelay(delay.Value);
        }

        Server!.Given(Request.Create().WithPath(IssuePath).UsingPost()).RespondWith(response);
        return this;
    }

    /// <summary>Stubs a status-only issuance response.</summary>
    public IssuerHarness StubStatus(int status) =>
        StubIssuance("{\"error\":\"upstream said no\"}", status);

    /// <summary>Stubs a well-formed success response carrying the given PEM fields.</summary>
    public IssuerHarness StubSuccess(string? certificatePem, string? issuerPem) =>
        StubIssuance(SuccessBody(certificatePem, issuerPem));

    /// <summary>Serialises the upstream's documented success body.</summary>
    public static string SuccessBody(string? certificatePem, string? issuerPem) =>
        JsonSerializer.Serialize(new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["certificate"] = certificatePem,
            ["issuer"] = issuerPem,
        });

    /// <summary>The one request the upstream received; fails the test if there was not exactly one.</summary>
    public WireMock.IRequestMessage SingleRequest()
    {
        ReceivedRequests.Count.ShouldBe(1);
        WireMock.IRequestMessage? message = ReceivedRequests[0].RequestMessage;
        message.ShouldNotBeNull();
        return message;
    }

    /// <summary>The raw body of the single request the upstream received.</summary>
    public string SingleRequestBody() => SingleRequest().Body!;

    /// <summary>The value of a header on the single request the upstream received, or null.</summary>
    public string? SingleRequestHeader(string name)
    {
        IDictionary<string, WireMock.Types.WireMockList<string>>? headers = SingleRequest().Headers;

        if (headers is null)
        {
            return null;
        }

        foreach (KeyValuePair<string, WireMock.Types.WireMockList<string>> header in headers)
        {
            if (string.Equals(header.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                return string.Join(", ", header.Value);
            }
        }

        return null;
    }

    private static int FindClosedPort()
    {
        // Bind then release: the port is known-free and, crucially, nothing is listening on it, so a
        // connection attempt is refused immediately rather than hanging.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        _provider.Dispose();
        Server?.Stop();
        Server?.Dispose();

        try
        {
            Directory.Delete(TempPath, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
