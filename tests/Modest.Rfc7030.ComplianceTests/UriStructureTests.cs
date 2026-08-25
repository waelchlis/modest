using System.Net;
using Modest.Core.Est;
using Modest.Server.Tests;

namespace Modest.Rfc7030.ComplianceTests;

/// <summary>
/// RFC 7030 s3.2.2 fixes the EST URI structure at
/// <c>/.well-known/est/[&lt;label&gt;/]&lt;operation&gt;</c>. Modest v1 does not implement the
/// optional <c>&lt;label&gt;</c> segment (see 01-rfc7030-reference.md §1), so what's checkable here is
/// narrower: every operation hangs off the fixed, unlabelled prefix, and nothing responds outside it.
/// </summary>
[Trait("Rfc7030Section", "1")]
public sealed class UriStructureTests : IAsyncLifetime
{
    private ModestServerHarness _harness = null!;

    public async Task InitializeAsync() => _harness = await ModestServerHarness.StartAsync();

    public async Task DisposeAsync() => await _harness.DisposeAsync();

    [Fact]
    public async Task Cacerts_responds_under_the_well_known_est_prefix()
    {
        using HttpResponseMessage response =
            await _harness.GetEstAsync(EstUriPaths.Prefix + EstUriPaths.CaCerts);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Theory]
    [InlineData(EstUriPaths.CaCerts)]
    [InlineData(EstUriPaths.CsrAttrs)]
    public async Task An_operation_reached_without_the_well_known_est_prefix_is_a_404(string operation)
    {
        // A client that gets the path wrong must get "not found", not a handler that happens to
        // answer anyway because minimal-API routing was left permissive.
        using HttpResponseMessage response = await _harness.GetEstAsync(operation);

        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task An_operation_the_server_does_not_implement_is_a_404_not_a_500()
    {
        // /fullcmc and /serverkeygen are optional per the RFC and out of scope for v1 (see
        // 01-rfc7030-reference.md §2) — the routing layer must say "not found", not fall through to
        // something that looks like a server fault.
        using HttpResponseMessage response =
            await _harness.GetEstAsync(EstUriPaths.Prefix + "/fullcmc");

        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }
}
