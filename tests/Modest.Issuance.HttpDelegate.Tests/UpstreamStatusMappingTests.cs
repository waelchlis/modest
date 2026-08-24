using System.Diagnostics;
using Modest.Core.Issuance;

namespace Modest.Issuance.HttpDelegate.Tests;

/// <summary>
/// How upstream HTTP statuses and transport faults become <see cref="IssuanceRejectionKind"/>s, and
/// which of them are allowed to be retried.
/// </summary>
public sealed class UpstreamStatusMappingTests
{
    [Theory]
    [InlineData(400)]
    [InlineData(404)]
    [InlineData(409)]
    [InlineData(422)]
    public async Task Client_error_statuses_map_to_PolicyDenied(int status)
    {
        using var harness = IssuerHarness.Create();
        harness.StubStatus(status);

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        var rejected = result.ShouldBeOfType<IssuanceResult.Rejected>();
        rejected.Kind.ShouldBe(IssuanceRejectionKind.PolicyDenied);
    }

    [Theory]
    [InlineData(400)]
    [InlineData(404)]
    [InlineData(409)]
    [InlineData(422)]
    public async Task Client_error_statuses_are_not_retried(int status)
    {
        // Repeating a CSR the upstream deliberately refused cannot change the answer, and against a
        // non-idempotent issuance API a retry risks minting a second certificate for one request.
        using var harness = IssuerHarness.Create(maxRetryAttempts: 3);
        harness.StubStatus(status);

        await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        harness.ReceivedRequests.Count.ShouldBe(1);
    }

    [Theory]
    [InlineData(401)]
    [InlineData(403)]
    public async Task Refused_upstream_credentials_map_to_UpstreamUnavailable_not_PolicyDenied(int status)
    {
        // A 401/403 here means Modest's own Basic credentials were refused. Reporting that to the EST
        // client as a policy denial blames the client for our misconfiguration and sends whoever
        // investigates to the wrong end of the system.
        using var harness = IssuerHarness.Create();
        harness.StubStatus(status);

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        var rejected = result.ShouldBeOfType<IssuanceResult.Rejected>();
        rejected.Kind.ShouldBe(IssuanceRejectionKind.UpstreamUnavailable);
        rejected.Kind.ShouldNotBe(IssuanceRejectionKind.PolicyDenied);
    }

    [Theory]
    [InlineData(401)]
    [InlineData(403)]
    public async Task Refused_upstream_credentials_are_not_retried(int status)
    {
        using var harness = IssuerHarness.Create(maxRetryAttempts: 3);
        harness.StubStatus(status);

        await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        harness.ReceivedRequests.Count.ShouldBe(1);
    }

    [Theory]
    [InlineData(500)]
    [InlineData(502)]
    [InlineData(503)]
    public async Task Server_error_statuses_map_to_UpstreamUnavailable(int status)
    {
        using var harness = IssuerHarness.Create();
        harness.StubStatus(status);

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        var rejected = result.ShouldBeOfType<IssuanceResult.Rejected>();
        rejected.Kind.ShouldBe(IssuanceRejectionKind.UpstreamUnavailable);
    }

    [Theory]
    [InlineData(500)]
    [InlineData(502)]
    [InlineData(503)]
    public async Task Server_error_statuses_are_retried_exactly_MaxRetryAttempts_times(int status)
    {
        const int MaxRetryAttempts = 2;

        using var harness = IssuerHarness.Create(maxRetryAttempts: MaxRetryAttempts);
        harness.StubStatus(status);

        await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        harness.ReceivedRequests.Count.ShouldBe(1 + MaxRetryAttempts);
    }

    [Fact]
    public async Task A_connection_that_is_refused_maps_to_UpstreamUnavailable()
    {
        using var harness = IssuerHarness.Create(pointAtDeadPort: true, maxRetryAttempts: 1);

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        var rejected = result.ShouldBeOfType<IssuanceResult.Rejected>();
        rejected.Kind.ShouldBe(IssuanceRejectionKind.UpstreamUnavailable);
    }

    [Fact]
    public async Task An_upstream_slower_than_the_configured_timeout_maps_to_UpstreamUnavailable()
    {
        // The per-attempt timeout is the whole reason TimeoutSeconds exists. Whatever the resilience
        // pipeline throws when it fires has to arrive back at the EST layer as a rejection, not as an
        // unhandled exception that becomes an HTTP 500.
        using var harness = IssuerHarness.Create(timeoutSeconds: 1, maxRetryAttempts: 1);
        harness.StubIssuance(
            IssuerHarness.SuccessBody(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem()),
            delay: TimeSpan.FromSeconds(3));

        var stopwatch = Stopwatch.StartNew();
        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);
        stopwatch.Stop();

        var rejected = result.ShouldBeOfType<IssuanceResult.Rejected>();
        rejected.Kind.ShouldBe(IssuanceRejectionKind.UpstreamUnavailable);

        stopwatch.Elapsed.ShouldBeLessThan(
            TimeSpan.FromSeconds(3), "the per-attempt timeout, not the upstream, must decide when to give up");
    }

    [Fact]
    public async Task Zero_retry_attempts_is_a_legal_configuration_meaning_try_once()
    {
        // HttpDelegateOptions.MaxRetryAttempts is annotated [Range(0, 10)] and documented as attempts
        // "beyond the first try", so 0 is a supported way for an operator to say "never retry" —
        // which is exactly what someone fronting a non-idempotent CA would configure.
        using var harness = IssuerHarness.Create(maxRetryAttempts: 0);
        harness.StubStatus(503);

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        var rejected = result.ShouldBeOfType<IssuanceResult.Rejected>();
        rejected.Kind.ShouldBe(IssuanceRejectionKind.UpstreamUnavailable);
        harness.ReceivedRequests.Count.ShouldBe(1);
    }
}
