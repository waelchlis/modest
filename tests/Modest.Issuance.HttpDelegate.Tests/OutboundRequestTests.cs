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
        // Base64's alphabet includes '+', and the default JavaScriptEncoder escapes it to +. That
        // is legal JSON, but it is HTML-embedding armour applied to an API payload that will never be
        // embedded in HTML, and it makes the body we send differ from the body the contract documents.
        // Against a third-party upstream with a hand-rolled parser that is an avoidable interop risk.
        byte[] der = CsrWithPlusInItsBase64();
        string expectedBase64 = Convert.ToBase64String(der);
        expectedBase64.Contains('+', StringComparison.Ordinal)
            .ShouldBeTrue("this guard is only meaningful for a CSR whose base64 exercises '+'");

        using var harness = IssuerHarness.Create();
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        await harness.Issuer.IssueAsync(SharedPki.RequestFor(der), CancellationToken.None);

        harness.SingleRequestBody().ShouldBe($"{{\"CSR\":\"{expectedBase64}\"}}");
    }

    [Fact]
    public async Task Base64_decodes_to_exactly_the_DER_bytes_that_went_in()
    {
        // The whole point of IssuanceRequest carrying bytes rather than a parsed object is that no
        // re-encoding drift can creep in between the EST client and the upstream. This asserts it.
        byte[] der = CsrFactory.CreateEcdsa("CN=drift-check.example.com", dnsNames: ["drift-check.example.com"]);

        using var harness = IssuerHarness.Create();
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        await harness.Issuer.IssueAsync(SharedPki.RequestFor(der), CancellationToken.None);

        using JsonDocument document = JsonDocument.Parse(harness.SingleRequestBody());
        string encoded = document.RootElement.GetProperty("CSR").GetString()!;

        byte[] roundTripped = Convert.FromBase64String(encoded);
        roundTripped.SequenceEqual(der).ShouldBeTrue("the DER handed to the issuer must reach the upstream unchanged");
    }

    [Fact]
    public async Task Base64_is_unwrapped()
    {
        using var harness = IssuerHarness.Create();
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        using JsonDocument document = JsonDocument.Parse(harness.SingleRequestBody());
        string encoded = document.RootElement.GetProperty("CSR").GetString()!;

        encoded.ShouldNotContain("\n");
        encoded.ShouldNotContain("\r");
        encoded.ShouldNotContain(" ");
        encoded.ShouldNotContain("-----BEGIN");
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

    private static byte[] CsrWithPlusInItsBase64()
    {
        // Base64 of a ~1200-byte CSR contains '+' with overwhelming probability, but "overwhelming"
        // is not "always", and a guard that silently stops guarding is worse than no guard.
        for (int attempt = 0; attempt < 20; attempt++)
        {
            byte[] der = CsrFactory.CreateRsa("CN=encoder-check.example.com");
            if (Convert.ToBase64String(der).Contains('+', StringComparison.Ordinal))
            {
                return der;
            }
        }

        throw new InvalidOperationException("Could not generate a CSR whose base64 contains '+'.");
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
