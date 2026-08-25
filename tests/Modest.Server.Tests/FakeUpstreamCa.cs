using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using WireMock;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Modest.Server.Tests;

/// <summary>
/// A stub of the external issuance API that <c>Modest.Issuance.HttpDelegate</c> forwards CSRs to.
/// </summary>
/// <remarks>
/// It actually signs, rather than replaying a canned certificate. The point of running the whole EST
/// suite a second time in delegated mode is to prove the protocol layer is genuinely independent of
/// the issuer, and the assertions that matter — the returned leaf carries the key from *this* CSR
/// and chains to the CA published by /cacerts — cannot be made against a fixed response.
/// </remarks>
public sealed class FakeUpstreamCa : IDisposable
{
    /// <summary>Path the upstream serves issuance on.</summary>
    public const string IssuePath = "/api/v1/issue";

    private readonly WireMockServer _server;
    private bool _disposed;

    private FakeUpstreamCa(WireMockServer server)
    {
        _server = server;
    }

    /// <summary>Base address to point <c>Issuance:HttpDelegate:BaseAddress</c> at.</summary>
    public string BaseAddress => _server.Url!;

    /// <summary>Starts an upstream that issues a real certificate for every CSR it is given.</summary>
    public static FakeUpstreamCa StartIssuing()
    {
        var upstream = new FakeUpstreamCa(WireMockServer.Start());
        upstream.StubIssuing();
        return upstream;
    }

    /// <summary>Starts an upstream that answers every issuance call with a fixed status.</summary>
    public static FakeUpstreamCa StartFailing(int statusCode)
    {
        var upstream = new FakeUpstreamCa(WireMockServer.Start());
        upstream.SetStatus(statusCode);
        return upstream;
    }

    /// <summary>
    /// Replaces the current behaviour with a fixed failure status.
    /// </summary>
    /// <remarks>
    /// Resets first rather than layering another mapping on: two mappings matching the same request
    /// leave which one answers up to WireMock's matching order, and a test whose stub depends on that
    /// is a test that will start failing for reasons unrelated to the code it covers.
    /// </remarks>
    public void SetStatus(int statusCode)
    {
        _server.Reset();
        StubStatus(statusCode);
    }

    private void StubIssuing()
    {
        // Declared as a delegate rather than passed inline: WithBody has an object-taking overload
        // that a lambda would also bind to, and the resulting body would be the delegate's ToString().
        Func<IRequestMessage, string> issue = IssueForRequest;

        _server
            .Given(Request.Create().WithPath(IssuePath).UsingPost())
            .RespondWith(Response.Create()
                .WithStatusCode(200)
                .WithHeader("Content-Type", "application/json")
                .WithBody(issue));
    }

    private void StubStatus(int statusCode) =>
        _server
            .Given(Request.Create().WithPath(IssuePath).UsingPost())
            .RespondWith(Response.Create()
                .WithStatusCode(statusCode)
                .WithHeader("Content-Type", "application/json")
                .WithBody("{\"error\":\"the upstream CA is having a bad day\"}"));

    private static string IssueForRequest(IRequestMessage request)
    {
        using var document = JsonDocument.Parse(request.Body!);
        string pem = document.RootElement.GetProperty("CSR").GetString()!;

        // The wire contract is the PEM text itself, not base64 of it and not the raw DER
        // underneath it (see planning/09-open-questions.md #1).
        PemFields fields = PemEncoding.Find(pem);
        byte[] der = Convert.FromBase64String(pem[fields.Base64Data]);

        CertificateRequest submitted = CertificateRequest.LoadSigningRequest(
            der,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
            RSASignaturePadding.Pkcs1);

        var toIssue = new CertificateRequest(
            submitted.SubjectName,
            submitted.PublicKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        toIssue.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        toIssue.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        toIssue.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(submitted.PublicKey, false));
        toIssue.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.2")], false));

        // Carry the requested SANs through, the same subset of the CSR the internal CA copies, so
        // both modes produce comparable certificates.
        X509Extension? san = submitted.CertificateExtensions
            .FirstOrDefault(static e => e.Oid?.Value == "2.5.29.17");
        if (san is not null)
        {
            toIssue.CertificateExtensions.Add(san);
        }

        byte[] serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F;

        using X509Certificate2 issued = toIssue.Create(
            TestPki.Ca.Issuer,
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(30),
            serial);

        return JsonSerializer.Serialize(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["certificate"] = issued.ExportCertificatePem(),
            ["issuer"] = TestPki.Ca.ChainPem(),
        });
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _server.Stop();
        _server.Dispose();
    }
}
