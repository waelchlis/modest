using System.Net;
using System.Security.Cryptography.X509Certificates;
using Modest.Codec;
using Modest.Core.Est;
using Modest.Server.Tests;
using Modest.TestSupport;

namespace Modest.Rfc7030.ComplianceTests;

/// <summary>
/// Wire-contract exactness that the endpoint-behaviour suite in <c>Modest.Server.Tests</c> does not
/// already pin for every operation. Most of the exactness checks RFC 7030 s3.2.1/s3.3-s3.4 requires —
/// <c>Content-Type</c> including the <c>smime-type=certs-only</c> parameter, and
/// <c>Content-Transfer-Encoding: base64</c> — already run on every request through
/// <c>EstResponse.ShouldBeCertsOnlyResponse</c>, tagged <c>Rfc7030Section</c> "2"/"3" in that project;
/// duplicating them here would just be the same assertion twice. What's added here is the coverage gap:
/// <c>/simplereenroll</c>'s success response never goes through that helper elsewhere, and
/// <c>/csrattrs</c>'s empty response has never had its headers checked at all.
/// </summary>
[Trait("Rfc7030Section", "3")]
public sealed class EndpointExactnessTests : IAsyncLifetime
{
    private ModestServerHarness _harness = null!;

    public async Task InitializeAsync() => _harness = await ModestServerHarness.StartAsync();

    public async Task DisposeAsync() => await _harness.DisposeAsync();

    [Fact]
    public async Task Simplereenroll_success_response_has_the_exact_certs_only_content_type()
    {
        using X509Certificate2 held = TestPki.Ca.IssueLeaf("CN=exactness.example.com");
        byte[] csr = CsrFactory.CreateRsa("CN=exactness.example.com");

        using HttpResponseMessage response = await _harness.PostEstAsync(
            EstUriPaths.Prefix + EstUriPaths.SimpleReenroll,
            Base64Wire.Encode(csr),
            EstMediaTypes.Pkcs10,
            authorization: null,
            clientCertificate: held);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        EstResponse.ShouldBeCertsOnlyResponse(response);
    }

    [Fact]
    public async Task Csrattrs_204_response_carries_no_content_type_header()
    {
        // RFC 7030 s3.3-s3.4 ties application/csrattrs to a body that actually exists; v1's empty
        // CsrAttrs is signalled by 204 instead (01-rfc7030-reference.md §3), which by definition has
        // no content. A stray Content-Type on an empty response would be nonsensical wire output, and
        // nothing else in the suite has looked at this response's headers rather than its status code.
        using HttpResponseMessage response =
            await _harness.GetEstAsync(EstUriPaths.Prefix + EstUriPaths.CsrAttrs);

        response.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        response.Content.Headers.ContentType.ShouldBeNull();
    }
}
