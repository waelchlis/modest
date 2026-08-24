using System.Text;
using Modest.Core.Issuance;

namespace Modest.Issuance.HttpDelegate.Tests;

/// <summary>
/// The upstream password is the one secret this component holds. It must reach the Authorization
/// header and nowhere else.
/// </summary>
public sealed class CredentialHandlingTests
{
    private const string Password = "Sup3rSecret-Upstream-Passw0rd";

    [Fact]
    public async Task The_upstream_password_never_appears_in_logs_on_a_successful_request()
    {
        using var harness = IssuerHarness.Create(password: Password);
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);
        result.ShouldBeOfType<IssuanceResult.Issued>();

        AssertNoSecretLeak(harness);
    }

    [Theory]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(500)]
    public async Task The_upstream_password_never_appears_in_logs_on_a_failed_request(int status)
    {
        // The 401 case is the dangerous one: the natural instinct when credentials are refused is to
        // log the credential so someone can see what was sent.
        using var harness = IssuerHarness.Create(password: Password);
        harness.StubStatus(status);

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);
        result.ShouldBeOfType<IssuanceResult.Rejected>();

        harness.Logs.Entries.ShouldNotBeEmpty("this test is only meaningful if something was logged");
        AssertNoSecretLeak(harness);
    }

    [Fact]
    public async Task The_upstream_password_never_appears_in_logs_when_the_upstream_is_unreachable()
    {
        using var harness = IssuerHarness.Create(password: Password, pointAtDeadPort: true, maxRetryAttempts: 1);

        await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        AssertNoSecretLeak(harness);
    }

    [Fact]
    public async Task The_upstream_password_never_appears_in_the_rejection_reason_shown_to_the_client()
    {
        using var harness = IssuerHarness.Create(password: Password);
        harness.StubStatus(401);

        IssuanceResult result = await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        var rejected = result.ShouldBeOfType<IssuanceResult.Rejected>();
        rejected.Reason.ShouldNotContain(Password);
        rejected.Reason.ShouldNotContain(EncodedCredential);
    }

    [Fact]
    public async Task The_Authorization_header_value_is_redacted_where_headers_are_logged()
    {
        using var harness = IssuerHarness.Create(password: Password);
        harness.StubSuccess(SharedPki.Leaf.ExportCertificatePem(), SharedPki.Ca.ChainPem());

        await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        string log = harness.Logs.AllText;
        log.ShouldContain("Authorization", Case.Insensitive, "trace-level header logging is expected to run");
        log.ShouldContain("Authorization: *", Case.Sensitive, "the value must be redacted, not printed");
    }

    [Fact]
    public async Task An_upstream_error_body_is_truncated_before_it_reaches_the_log()
    {
        // The upstream's error body is attacker-adjacent, unbounded text. Logging it whole invites a
        // hostile upstream (or a confused one) to flood the operator's log store.
        using var harness = IssuerHarness.Create(password: Password);
        harness.StubIssuance(new string('x', 20_000), status: 500);

        await harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None);

        harness.Logs.AllText.ShouldNotContain(new string('x', 1_000));
    }

    private static string EncodedCredential =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes($"{IssuerHarness.DefaultUsername}:{Password}"));

    private static void AssertNoSecretLeak(IssuerHarness harness)
    {
        string log = harness.Logs.AllText;

        log.Contains(Password, StringComparison.OrdinalIgnoreCase)
            .ShouldBeFalse("the upstream password must never be logged");
        log.Contains(EncodedCredential, StringComparison.Ordinal)
            .ShouldBeFalse("the base64 credential is the password in a thin disguise");

        // The HTTP stack logs request headers by name at Trace level. The name is harmless; the
        // credential after the scheme is not, so nothing may ever log a rendered "Basic <...>".
        log.Contains("Basic ", StringComparison.Ordinal)
            .ShouldBeFalse("a rendered Basic credential must never reach a log sink");
    }
}
