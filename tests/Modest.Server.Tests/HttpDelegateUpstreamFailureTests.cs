using System.Net;
using Modest.Codec;
using Modest.Core.Est;
using Modest.Server.Configuration;
using Modest.TestSupport;

namespace Modest.Server.Tests;

/// <summary>
/// What an EST client sees when the delegated issuer's upstream misbehaves.
/// </summary>
/// <remarks>
/// Its own host with its own stub upstream, because each test rewires that stub. Doing so to the
/// upstream the shared delegated-mode host talks to would make both suites depend on execution order.
/// </remarks>
public sealed class HttpDelegateUpstreamFailureTests : IAsyncLifetime
{
    private const string EnrollPath = EstUriPaths.Prefix + EstUriPaths.SimpleEnroll;

    private FakeUpstreamCa _upstream = null!;
    private ModestServerHarness _harness = null!;

    public async Task InitializeAsync()
    {
        _upstream = FakeUpstreamCa.StartFailing(503);

        _harness = await ModestServerHarness.StartAsync(options =>
        {
            options.Mode = IssuanceMode.HttpDelegate;
            options.Configuration["Issuance:HttpDelegate:BaseAddress"] = _upstream.BaseAddress;
        });
    }

    public async Task DisposeAsync()
    {
        await _harness.DisposeAsync();
        _upstream.Dispose();
    }

    [Fact]
    public async Task An_unavailable_upstream_is_reported_as_502_and_not_500()
    {
        // The distinction is what an operator reads off a dashboard at 3am: 502 says "the CA behind
        // me is down", 500 says "I am broken". Getting it wrong sends someone to the wrong system.
        _upstream.SetStatus(503);

        using HttpResponseMessage response = await EnrollAsync();

        response.StatusCode.ShouldBe(HttpStatusCode.BadGateway);
    }

    [Fact]
    public async Task An_upstream_refusing_modests_own_credentials_is_a_502_and_not_a_403()
    {
        // A 401 from upstream means *our* configuration is wrong. Passing it through as a client
        // error would blame the enrolling device for an operator's mistake and send whoever
        // investigates to the wrong end of the system entirely.
        _upstream.SetStatus(401);

        using HttpResponseMessage response = await EnrollAsync();

        response.StatusCode.ShouldBe(HttpStatusCode.BadGateway);
    }

    [Fact]
    public async Task An_upstream_declining_the_csr_on_policy_is_a_403()
    {
        // Any other 4xx is the upstream applying its own issuance policy — a deliberate refusal of
        // this request, which is the client's business and not a gateway failure.
        _upstream.SetStatus(400);

        using HttpResponseMessage response = await EnrollAsync();

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task A_failing_upstream_does_not_leak_its_response_to_the_client()
    {
        _upstream.SetStatus(503);

        using HttpResponseMessage response = await EnrollAsync();

        string body = await response.Content.ReadAsStringAsync();
        body.ShouldNotContain("bad day", Case.Insensitive);
    }

    [Fact]
    public async Task Cacerts_still_answers_while_the_upstream_is_down()
    {
        // The chain is configured statically for exactly this reason: /cacerts has to serve a client
        // that has never enrolled, and a cache filled by past issuances would be empty at precisely
        // the moment it is needed.
        _upstream.SetStatus(503);

        using HttpResponseMessage response =
            await _harness.GetEstAsync(EstUriPaths.Prefix + EstUriPaths.CaCerts);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await EstResponse.ReadCertsOnlyAsync(response)).Count.ShouldBe(TestPki.Ca.Chain.Count);
    }

    private Task<HttpResponseMessage> EnrollAsync() =>
        _harness.PostEstAsync(
            EnrollPath,
            Base64Wire.Encode(CsrFactory.CreateRsa("CN=upstream-trouble.example.com")),
            EstMediaTypes.Pkcs10,
            ModestServerHarness.ValidBasicHeader());
}
