using System.Net;
using Modest.Codec;
using Modest.Core.Est;
using Modest.TestSupport;

namespace Modest.Server.Tests;

/// <summary>
/// The two listeners must not share a route table.
/// </summary>
/// <remarks>
/// Kestrel gives one route table to every binding, so the split is enforced by a
/// <c>MapWhen</c> on <c>Connection.LocalPort</c>. That is easy to "simplify" away, and if it went
/// the consequence would be certificate enrollment served over plain HTTP with no transport security
/// at all. These tests exist to make that regression impossible to land quietly, and they need real
/// ports to say anything at all — an in-memory test server has no local port to branch on.
/// </remarks>
[Collection(InternalCaHost.Name)]
public sealed class ListenerIsolationTests(InternalCaFixture fixture)
{
    private readonly ModestServerHarness _harness = fixture.Harness;

    [Fact]
    public async Task Healthz_answers_over_plain_http_on_the_ops_port()
    {
        using HttpResponseMessage response = await _harness.GetOpsAsync("/healthz");

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync()).ShouldBe("ok");
    }

    [Fact]
    public async Task Readyz_answers_over_plain_http_on_the_ops_port()
    {
        // The reason the split exists: a kubelet probes this without a TLS handshake or client
        // certificate negotiation.
        using HttpResponseMessage response = await _harness.GetOpsAsync("/readyz");

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync()).ShouldBe("ready");
    }

    [Theory]
    [InlineData(EstUriPaths.Prefix + EstUriPaths.CaCerts)]
    [InlineData(EstUriPaths.Prefix + EstUriPaths.CsrAttrs)]
    public async Task Est_get_routes_are_not_served_on_the_ops_port(string path)
    {
        using HttpResponseMessage response = await _harness.GetOpsAsync(path);

        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Theory]
    [InlineData(EstUriPaths.Prefix + EstUriPaths.SimpleEnroll)]
    [InlineData(EstUriPaths.Prefix + EstUriPaths.SimpleReenroll)]
    public async Task Enrollment_is_unreachable_on_the_plain_http_port_even_with_valid_credentials(string path)
    {
        // Deliberately a request that would succeed on the EST listener. A 404 here is the only
        // acceptable answer: anything else would mean a CSR and a Basic password had just crossed
        // the network in the clear.
        string body = Base64Wire.Encode(CsrFactory.CreateRsa("CN=should-never-be-issued.example.com"));

        using HttpResponseMessage response = await _harness.PostOpsAsync(
            path, body, EstMediaTypes.Pkcs10, ModestServerHarness.ValidBasicHeader());

        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Theory]
    [InlineData("/healthz")]
    [InlineData("/readyz")]
    public async Task Health_endpoints_are_not_served_on_the_est_port(string path)
    {
        using HttpResponseMessage response = await _harness.GetEstAsync(path);

        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task The_ops_listener_speaks_plain_http_and_not_tls()
    {
        // Attempting TLS against it must fail rather than quietly succeed: if the ops port ever
        // negotiated TLS, the port-based route split would still hold but the deployment assumption
        // behind it — probes need no handshake — would have silently changed.
        using var client = new HttpClient();
        Uri httpsOnOpsPort = new($"https://127.0.0.1:{_harness.OpsPort}/healthz");

        await Should.ThrowAsync<HttpRequestException>(() => client.GetAsync(httpsOnOpsPort));
    }
}
