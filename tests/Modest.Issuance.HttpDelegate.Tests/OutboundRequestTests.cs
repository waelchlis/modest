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
        // never touch HTML doesn't need), which is why OutboundJson opts out of it. Under the old
        // raw-DER contract that mattered directly: base64 of arbitrary DER bytes contains '+' with
        // near certainty. Under the current base64-of-PEM contract it can't be provoked through a
        // real CSR at all -- every byte in PEM's own character set has its top bits pinned such that
        // none of the four base64 output groups per input triplet can land on 62/63 ('+'/'/'), so
        // this field structurally never contains either character now. The exact-match assertion
        // below still guards the byte-for-byte contract; it just can't exercise that specific
        // escaping path any more.
        byte[] der = CsrFactory.CreateRsa("CN=encoder-check.example.com");
        string expectedBase64 = Convert.ToBase64String(Encoding.ASCII.GetBytes(ExpectedPem(der)));

        using var harness = IssuerHarness.Create();
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        await harness.Issuer.IssueAsync(SharedPki.RequestFor(der), CancellationToken.None);

        harness.SingleRequestBody().ShouldBe($"{{\"CSR\":\"{expectedBase64}\"}}");
    }

    [Fact]
    public async Task Base64_decodes_to_pem_wrapping_exactly_the_DER_bytes_that_went_in()
    {
        // The whole point of IssuanceRequest carrying bytes rather than a parsed object is that no
        // re-encoding drift can creep in between the EST client and the upstream. This asserts it,
        // for the PEM contract confirmed in 09-open-questions.md #1 — base64 of PEM text, not base64
        // of the raw DER underneath it.
        byte[] der = CsrFactory.CreateEcdsa("CN=drift-check.example.com", dnsNames: ["drift-check.example.com"]);

        using var harness = IssuerHarness.Create();
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        await harness.Issuer.IssueAsync(SharedPki.RequestFor(der), CancellationToken.None);

        using JsonDocument document = JsonDocument.Parse(harness.SingleRequestBody());
        string encoded = document.RootElement.GetProperty("CSR").GetString()!;

        string pem = Encoding.ASCII.GetString(Convert.FromBase64String(encoded));
        pem.ShouldBe(ExpectedPem(der));

        PemFields fields = PemEncoding.Find(pem);
        byte[] roundTripped = Convert.FromBase64String(pem[fields.Base64Data]);
        roundTripped.SequenceEqual(der).ShouldBeTrue("the DER handed to the issuer must reach the upstream unchanged");
    }

    [Fact]
    public async Task Outer_base64_is_a_single_unwrapped_line()
    {
        // The PEM text inside legitimately contains newlines and "-----BEGIN ..." (that's the point
        // of the contract, see 09-open-questions.md #1) — what must stay unwrapped is the outer
        // base64 envelope itself, since that is what a hand-rolled JSON parser on the other end has
        // to consume as one opaque string.
        using var harness = IssuerHarness.Create();
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        using JsonDocument document = JsonDocument.Parse(harness.SingleRequestBody());
        string encoded = document.RootElement.GetProperty("CSR").GetString()!;

        encoded.ShouldNotContain("\n");
        encoded.ShouldNotContain("\r");
        encoded.ShouldNotContain(" ");
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

    /// <summary>The PEM text the issuer is expected to send, before the outer base64 wrap.</summary>
    private static string ExpectedPem(byte[] der) => PemEncoding.WriteString("CERTIFICATE REQUEST", der);

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
