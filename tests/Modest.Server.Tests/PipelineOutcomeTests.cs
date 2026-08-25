using System.Net;
using Modest.Codec;
using Modest.Core.Est;
using Modest.Core.Issuance;
using Modest.TestSupport;

namespace Modest.Server.Tests;

/// <summary>
/// The two outcomes of the status table that no shipping issuer can produce.
/// </summary>
/// <remarks>
/// <para>
/// <c>202 Accepted</c> exists so that an asynchronous CA can be plugged in later without changing the
/// issuance interface, and <c>500</c> is what stands between an unexpected fault and a stack trace on
/// the wire. Both are real code in the protocol layer; neither is reachable from a request against
/// the internal CA or the HTTP delegate. Leaving them untested would mean the only two paths nobody
/// can rehearse are also the only two nobody has ever run.
/// </para>
/// <para>
/// Only the issuer is substituted. Kestrel, TLS, routing, authentication, body limits, the codec and
/// the result mapping are all the production ones.
/// </para>
/// </remarks>
public sealed class PipelineOutcomeTests : IAsyncLifetime
{
    private const string EnrollPath = EstUriPaths.Prefix + EstUriPaths.SimpleEnroll;

    private ModestServerHarness _pending = null!;
    private ModestServerHarness _faulty = null!;

    public async Task InitializeAsync()
    {
        _pending = await ModestServerHarness.StartAsync(static options =>
            options.IssuerOverride = new ScriptedIssuer(
                _ => new IssuanceResult.Pending(TimeSpan.FromSeconds(42))));

        _faulty = await ModestServerHarness.StartAsync(static options =>
            options.IssuerOverride = new ScriptedIssuer(
                _ => throw new InvalidOperationException(
                    "the HSM caught fire and here is the internal detail nobody outside should see")));
    }

    public async Task DisposeAsync()
    {
        await _pending.DisposeAsync();
        await _faulty.DisposeAsync();
    }

    [Fact]
    [Trait("Rfc7030Section", "7")]
    public async Task A_pending_issuance_becomes_202_with_a_retry_after_and_no_body()
    {
        using HttpResponseMessage response = await EnrollAgainstAsync(_pending);

        response.StatusCode.ShouldBe(HttpStatusCode.Accepted);

        TimeSpan? retryAfter = response.Headers.RetryAfter?.Delta;
        retryAfter.ShouldBe(TimeSpan.FromSeconds(42));
        (await response.Content.ReadAsByteArrayAsync()).ShouldBeEmpty();
    }

    [Fact]
    [Trait("Rfc7030Section", "8")]
    public async Task An_unexpected_failure_becomes_500_without_leaking_the_reason()
    {
        using HttpResponseMessage response = await EnrollAgainstAsync(_faulty);

        response.StatusCode.ShouldBe(HttpStatusCode.InternalServerError);

        string body = await response.Content.ReadAsStringAsync();

        // The client gets a correlation handle and nothing else. Exception text from inside a CA can
        // name key stores, hostnames and file paths, and this caller is only ever authenticated —
        // never trusted with the server's internals.
        body.ShouldNotContain("HSM", Case.Insensitive);
        body.ShouldNotContain("caught fire", Case.Insensitive);
        body.ShouldNotContain("InvalidOperationException", Case.Insensitive);
        body.ShouldContain("Trace identifier");

        // The detail has to go somewhere, though: an operator handed that trace identifier must be
        // able to find the real cause.
        _faulty.Logs.AllText.ShouldContain("caught fire");
    }

    [Fact]
    [Trait("Rfc7030Section", "8")]
    public async Task An_unexpected_failure_on_cacerts_is_a_500_with_a_generic_body()
    {
        using HttpResponseMessage response =
            await _faulty.GetEstAsync(EstUriPaths.Prefix + EstUriPaths.CaCerts);

        response.StatusCode.ShouldBe(HttpStatusCode.InternalServerError);

        string body = await response.Content.ReadAsStringAsync();
        body.ShouldNotContain("caught fire", Case.Insensitive);
    }

    private static Task<HttpResponseMessage> EnrollAgainstAsync(ModestServerHarness harness) =>
        harness.PostEstAsync(
            EnrollPath,
            Base64Wire.Encode(CsrFactory.CreateRsa("CN=scripted.example.com")),
            EstMediaTypes.Pkcs10,
            ModestServerHarness.ValidBasicHeader());

    /// <summary>An issuer that does whatever the test told it to.</summary>
    private sealed class ScriptedIssuer : ICertificateIssuer
    {
        private readonly Func<IssuanceRequest, IssuanceResult> _script;

        public ScriptedIssuer(Func<IssuanceRequest, IssuanceResult> script)
        {
            _script = script;
        }

        public Task<CaChainResult> GetCaChainAsync(CancellationToken cancellationToken)
        {
            // Whatever the script does to an issuance, it does to the chain lookup too, so /cacerts
            // gets the same treatment without a second issuer type.
            _ = _script(null!);
            return Task.FromResult(new CaChainResult(TestPki.Ca.Chain));
        }

        public Task<IssuanceResult> IssueAsync(IssuanceRequest request, CancellationToken cancellationToken) =>
            Task.FromResult(_script(request));

        public Task<bool> IsReadyAsync(CancellationToken cancellationToken) => Task.FromResult(true);
    }
}
