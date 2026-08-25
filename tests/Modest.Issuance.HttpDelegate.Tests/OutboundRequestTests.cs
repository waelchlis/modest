using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Modest.Core.Issuance;
using Modest.TestSupport;

namespace Modest.Issuance.HttpDelegate.Tests;

/// <summary>
/// Byte-for-byte assertions on what actually goes out on the wire.
/// </summary>
/// <remarks>
/// The upstream is a real third party we cannot renegotiate with cheaply, so the request shape is a
/// contract, not an implementation detail. These are the regression guards for it.
/// </remarks>
public sealed class OutboundRequestTests
{
    /// <summary>Mirrors HttpDelegateIssuer's private OutboundJson options.</summary>
    private static readonly JsonSerializerOptions RelaxedJson = new(JsonSerializerDefaults.Web)
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    [Fact]
    public async Task Body_carries_exactly_one_property_named_CSR_in_that_casing()
    {
        using var harness = IssuerHarness.Create();
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        using JsonDocument document = JsonDocument.Parse(harness.SingleRequestBody());
        document.RootElement.ValueKind.ShouldBe(JsonValueKind.Object);
        document.RootElement.EnumerateObject().Select(static p => p.Name).ToArray().ShouldBe(new[] { "CSR" });
    }

    [Fact]
    public async Task Body_is_the_canonical_unescaped_JSON_form()
    {
        // The default JavaScriptEncoder escapes '+' (HTML-embedding armour an API payload that will
        // never touch HTML doesn't need), which is why OutboundJson opts out of it. The PEM text is
        // sent as the literal JSON string value (see 09-open-questions.md #1), so its base64 payload
        // lines — which contain '+' with near certainty for any real CSR — are directly visible on
        // the wire, not hidden behind an outer encoding layer. This is a real, exercisable escaping
        // path, unlike the double-base64 contract this replaced.
        byte[] der = CsrWithPlusInItsPem();
        string pem = ExpectedPem(der);
        pem.Contains('+', StringComparison.Ordinal)
            .ShouldBeTrue("this guard is only meaningful for a CSR whose PEM exercises '+'");

        using var harness = IssuerHarness.Create();
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        await harness.Issuer.IssueAsync(SharedPki.RequestFor(der), CancellationToken.None);

        string expectedJsonValue = JsonSerializer.Serialize(pem, RelaxedJson);
        harness.SingleRequestBody().ShouldBe($"{{\"CSR\":{expectedJsonValue}}}");
    }

    [Fact]
    public async Task Csr_field_is_the_pem_text_wrapping_exactly_the_DER_bytes_that_went_in()
    {
        // The whole point of IssuanceRequest carrying bytes rather than a parsed object is that no
        // re-encoding drift can creep in between the EST client and the upstream. This asserts it,
        // for the PEM contract confirmed in 09-open-questions.md #1 — the field is the PEM text
        // itself, not base64 of it and not the raw DER underneath it.
        byte[] der = CsrFactory.CreateEcdsa("CN=drift-check.example.com", dnsNames: ["drift-check.example.com"]);

        using var harness = IssuerHarness.Create();
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        await harness.Issuer.IssueAsync(SharedPki.RequestFor(der), CancellationToken.None);

        using JsonDocument document = JsonDocument.Parse(harness.SingleRequestBody());
        string pem = document.RootElement.GetProperty("CSR").GetString()!;

        pem.ShouldBe(ExpectedPem(der));
        pem.ShouldStartWith("-----BEGIN CERTIFICATE REQUEST-----");

        PemFields fields = PemEncoding.Find(pem);
        byte[] roundTripped = Convert.FromBase64String(pem[fields.Base64Data]);
        roundTripped.SequenceEqual(der).ShouldBeTrue("the DER handed to the issuer must reach the upstream unchanged");
    }

    [Fact]
    public async Task Posts_to_the_configured_issue_path()
    {
        using var harness = IssuerHarness.Create(issuePath: "/pki/v2/enroll");
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        harness.SingleRequest().Path.ShouldBe("/pki/v2/enroll");
        harness.SingleRequest().Method.ShouldBe("POST");
    }

    [Fact]
    public async Task Authorization_header_is_Basic_base64_of_username_colon_password()
    {
        using var harness = IssuerHarness.Create(username: "modest-gateway", password: "hunter2");
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        string expected = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("modest-gateway:hunter2"));
        harness.SingleRequestHeader("Authorization").ShouldBe(expected);
    }

    [Fact]
    public async Task Password_file_trailing_newline_produces_the_same_header()
    {
        // Both `echo secret > file` and a Kubernetes secret mounted from a YAML block scalar leave a
        // trailing newline. Sending it as part of the password yields a 401 nobody can explain.
        string withNewline = await CaptureAuthorizationHeaderAsync(trailingNewline: true);
        string withoutNewline = await CaptureAuthorizationHeaderAsync(trailingNewline: false);

        withNewline.ShouldBe(withoutNewline);
        withNewline.ShouldBe("Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("modest-gateway:hunter2")));
    }

    [Fact]
    public async Task Password_file_trailing_CRLF_produces_the_same_header()
    {
        using var harness = IssuerHarness.Create(username: "modest-gateway", password: "hunter2\r\n");
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        string expected = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("modest-gateway:hunter2"));
        harness.SingleRequestHeader("Authorization").ShouldBe(expected);
    }

    [Fact]
    public async Task No_Authorization_header_when_no_username_is_configured()
    {
        using var harness = IssuerHarness.Create(username: null);
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        IssuanceResult result = await harness.Issuer.IssueAsync(
            SharedPki.Request(), CancellationToken.None);

        result.ShouldBeOfType<IssuanceResult.Issued>();
        harness.SingleRequestHeader("Authorization").ShouldBeNull();
    }

    /// <summary>The PEM text the issuer is expected to send as the CSR field's value.</summary>
    private static string ExpectedPem(byte[] der) => PemEncoding.WriteString("CERTIFICATE REQUEST", der);

    private static byte[] CsrWithPlusInItsPem()
    {
        // PEM's base64 payload lines contain '+' with overwhelming probability for a ~1200-byte
        // CSR, but "overwhelming" is not "always", and a guard that silently stops guarding is
        // worse than no guard.
        for (int attempt = 0; attempt < 20; attempt++)
        {
            byte[] der = CsrFactory.CreateRsa("CN=encoder-check.example.com");
            if (ExpectedPem(der).Contains('+', StringComparison.Ordinal))
            {
                return der;
            }
        }

        throw new InvalidOperationException("Could not generate a CSR whose PEM contains '+'.");
    }

    private static async Task<string> CaptureAuthorizationHeaderAsync(bool trailingNewline)
    {
        using var harness = IssuerHarness.Create(
            username: "modest-gateway",
            password: "hunter2",
            passwordFileTrailingNewline: trailingNewline);

        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());
        await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        return harness.SingleRequestHeader("Authorization")!;
    }
}
