using System.Security.Cryptography.X509Certificates;
using System.Text;
using Modest.Core.Issuance;

namespace Modest.Issuance.HttpDelegate.Tests;

/// <summary>
/// What the issuer makes of the upstream's 200 responses.
/// </summary>
/// <remarks>
/// A 200 that cannot be turned into a certificate is an upstream contract violation, not a client
/// error, but it still has to be reported as a rejection rather than an unhandled exception —
/// nothing here should ever become an HTTP 500 in the EST layer.
/// </remarks>
public sealed class ResponseParsingTests
{
    [Fact]
    public async Task Well_formed_response_yields_Issued_with_the_certificate_from_the_certificate_field()
    {
        using var harness = IssuerHarness.Create();
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        var issued = result.ShouldBeOfType<IssuanceResult.Issued>();
        issued.Certificate.Thumbprint.ShouldBe(SharedPki.Leaf.Thumbprint);
        issued.Certificate.Subject.ShouldBe(SharedPki.Leaf.Subject);
    }

    [Fact]
    public async Task Chain_matches_the_issuer_field_in_order_and_excludes_the_leaf()
    {
        using var harness = IssuerHarness.Create();
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        var issued = result.ShouldBeOfType<IssuanceResult.Issued>();

        // Intermediate first, root last: the order RFC 7030 clients expect when building a path.
        issued.Chain.Count.ShouldBe(2);
        issued.Chain[0].Thumbprint.ShouldBe(SharedPki.Ca.Intermediate!.Thumbprint);
        issued.Chain[1].Thumbprint.ShouldBe(SharedPki.Ca.Root.Thumbprint);

        issued.Chain.Select(static c => c.Thumbprint)
            .ShouldNotContain(SharedPki.Leaf.Thumbprint, "the leaf must not be repeated in the chain");
    }

    [Fact]
    public async Task Single_certificate_issuer_field_yields_a_one_entry_chain()
    {
        using var harness = IssuerHarness.Create();
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.Root.ExportCertificatePem());

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        var issued = result.ShouldBeOfType<IssuanceResult.Issued>();
        issued.Chain.Count.ShouldBe(1);
        issued.Chain[0].Thumbprint.ShouldBe(SharedPki.Ca.Root.Thumbprint);
    }

    [Fact]
    public async Task Malformed_JSON_with_a_200_is_rejected_as_InvalidCsr()
    {
        using var harness = IssuerHarness.Create();
        harness.StubIssuance("{\"certificate\": \"oops", status: 200);

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        ShouldBeRejected(result, IssuanceRejectionKind.InvalidCsr);
    }

    [Fact]
    public async Task Body_that_is_not_JSON_at_all_with_a_200_is_rejected_as_InvalidCsr()
    {
        using var harness = IssuerHarness.Create();
        harness.StubIssuance("<html><body>502 Bad Gateway</body></html>", status: 200);

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        ShouldBeRejected(result, IssuanceRejectionKind.InvalidCsr);
    }

    [Fact]
    public async Task Empty_body_with_a_200_is_rejected_as_InvalidCsr()
    {
        using var harness = IssuerHarness.Create();
        harness.StubIssuance(string.Empty, status: 200);

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        ShouldBeRejected(result, IssuanceRejectionKind.InvalidCsr);
    }

    [Theory]
    [InlineData("{\"issuer\":\"x\"}")]
    [InlineData("{\"certificate\":null,\"issuer\":\"x\"}")]
    [InlineData("{\"certificate\":\"\",\"issuer\":\"x\"}")]
    [InlineData("{\"certificate\":\"   \",\"issuer\":\"x\"}")]
    [InlineData("{}")]
    [InlineData("null")]
    public async Task Missing_or_empty_certificate_field_is_rejected_as_InvalidCsr(string body)
    {
        using var harness = IssuerHarness.Create();
        harness.StubIssuance(body, status: 200);

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        ShouldBeRejected(result, IssuanceRejectionKind.InvalidCsr);
    }

    [Theory]
    [MemberData(nameof(GarbagePemCases))]
    public async Task Garbage_in_the_certificate_field_is_rejected_as_InvalidCsr(string label, string garbage)
    {
        label.ShouldNotBeNullOrEmpty();

        using var harness = IssuerHarness.Create();
        harness.StubSuccess(garbage, SharedPki.Ca.ChainPem());

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        ShouldBeRejected(result, IssuanceRejectionKind.InvalidCsr);
    }

    [Theory]
    [MemberData(nameof(GarbagePemCases))]
    public async Task Garbage_in_the_issuer_field_is_rejected_as_InvalidCsr(string label, string garbage)
    {
        // A leaf whose chain silently vanished is worse than a clean rejection: the EST client gets a
        // certificate it cannot build a path for, and nothing anywhere says why. The contract says
        // this field holds the chain, so an unusable value in it is a failed issuance.
        label.ShouldNotBeNullOrEmpty();

        using var harness = IssuerHarness.Create();
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), garbage);

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        ShouldBeRejected(result, IssuanceRejectionKind.InvalidCsr);
    }

    [Fact]
    public async Task A_200_carrying_a_truncated_PEM_certificate_is_rejected_rather_than_throwing()
    {
        string pem = SharedPki.Leaf.ExportCertificatePem();
        string truncated = pem[..(pem.Length / 2)];

        using var harness = IssuerHarness.Create();
        harness.StubSuccess(truncated, SharedPki.Ca.ChainPem());

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        ShouldBeRejected(result, IssuanceRejectionKind.InvalidCsr);
    }

    [Fact]
    public async Task Issued_certificates_carry_no_private_key()
    {
        // The upstream holds the CA key; Modest never sees one in this mode. If a parsed leaf ever
        // reported a private key it would mean something other than a plain certificate came back.
        using var harness = IssuerHarness.Create();
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        var issued = result.ShouldBeOfType<IssuanceResult.Issued>();
        issued.Certificate.HasPrivateKey.ShouldBeFalse();
        foreach (X509Certificate2 certificate in issued.Chain)
        {
            certificate.HasPrivateKey.ShouldBeFalse();
        }
    }

    public static TheoryData<string, string> GarbagePemCases() => new()
    {
        { "plain text", "this is not a certificate" },
        { "base64 of non-DER", Convert.ToBase64String(Encoding.UTF8.GetBytes("definitely not a certificate")) },
        {
            "PEM envelope around valid base64 that is not a certificate",
            "-----BEGIN CERTIFICATE-----\n" +
            Convert.ToBase64String(Encoding.UTF8.GetBytes("definitely not a certificate")) +
            "\n-----END CERTIFICATE-----\n"
        },
        {
            "PEM envelope around non-base64",
            "-----BEGIN CERTIFICATE-----\n!!! not base64 !!!\n-----END CERTIFICATE-----\n"
        },
        { "a JSON object where PEM was expected", "{\"nested\":\"object\"}" },
    };

    private static void ShouldBeRejected(IssuanceResult result, IssuanceRejectionKind kind)
    {
        var rejected = result.ShouldBeOfType<IssuanceResult.Rejected>();
        rejected.Kind.ShouldBe(kind);
        rejected.Reason.ShouldNotBeNullOrWhiteSpace();
    }
}
