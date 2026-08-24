using Modest.Core.Issuance;
using Modest.TestSupport;

namespace Modest.Issuance.HttpDelegate.Tests;

/// <summary>
/// Checks made before anything leaves the process.
/// </summary>
public sealed class PreflightTests
{
    [Fact]
    public async Task A_CSR_above_MaxCsrSizeBytes_is_rejected_as_InvalidCsr()
    {
        using var harness = IssuerHarness.Create(maxCsrSizeBytes: 256);
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        var rejected = result.ShouldBeOfType<IssuanceResult.Rejected>();
        rejected.Kind.ShouldBe(IssuanceRejectionKind.InvalidCsr);
    }

    [Fact]
    public async Task An_oversized_CSR_never_reaches_the_upstream()
    {
        // The point of a pre-flight guard is that a client cannot make Modest relay arbitrarily large
        // bodies to a third party on its behalf. If the request still goes out, the guard is theatre.
        using var harness = IssuerHarness.Create(maxCsrSizeBytes: 256);
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        harness.ReceivedRequests.ShouldBeEmpty();
    }

    [Fact]
    public async Task A_CSR_at_exactly_the_limit_is_still_forwarded()
    {
        byte[] der = CsrFactory.CreateRsa("CN=boundary.example.com");

        using var harness = IssuerHarness.Create(maxCsrSizeBytes: der.Length);
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        IssuanceResult result = await harness.Issuer.IssueAsync(
            SharedPki.RequestFor(der), CancellationToken.None);

        result.ShouldBeOfType<IssuanceResult.Issued>();
        harness.ReceivedRequests.Count.ShouldBe(1);
    }
}
