using System.Net;
using System.Security.Cryptography.X509Certificates;
using Modest.Codec;
using Modest.Core.Est;
using Modest.TestSupport;

namespace Modest.Server.Tests;

/// <summary>
/// The same host with <c>Issuance:Reenrollment:RequireMatchingIdentity</c> turned off.
/// </summary>
/// <remarks>
/// A toggle nobody tests in its second position is a toggle that does not work. Operators fronting a
/// PKI that already enforces its own naming policy have a legitimate reason to disable this, and they
/// need to know that doing so actually disables it — and, just as importantly, that it disables only
/// this check and not authentication along with it.
/// </remarks>
[Trait("Rfc7030Section", "5")]
public sealed class ReenrollmentCheckDisabledTests : IAsyncLifetime
{
    private const string ReenrollPath = EstUriPaths.Prefix + EstUriPaths.SimpleReenroll;

    private ModestServerHarness _harness = null!;

    public async Task InitializeAsync() =>
        _harness = await ModestServerHarness.StartAsync(static options =>
            options.RequireMatchingIdentity = false);

    public async Task DisposeAsync() => await _harness.DisposeAsync();

    [Fact]
    public async Task A_mismatched_subject_is_issued_when_the_check_is_disabled()
    {
        using X509Certificate2 held = TestPki.Ca.IssueLeaf("CN=self.example.com");
        byte[] csr = CsrFactory.CreateRsa("CN=somebody-else.example.com");

        using HttpResponseMessage response = await _harness.PostEstAsync(
            ReenrollPath,
            Base64Wire.Encode(csr),
            EstMediaTypes.Pkcs10,
            authorization: null,
            clientCertificate: held);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        IReadOnlyList<X509Certificate2> issued = await EstResponse.ReadCertsOnlyAsync(response);
        issued.ShouldNotBeEmpty();
        issued[0].SubjectName.Name.ShouldBe("CN=somebody-else.example.com");
    }

    [Fact]
    public async Task Basic_authenticated_reenrollment_is_allowed_when_the_check_is_disabled()
    {
        using HttpResponseMessage response = await _harness.PostEstAsync(
            ReenrollPath,
            Base64Wire.Encode(CsrFactory.CreateRsa("CN=password-only.example.com")),
            EstMediaTypes.Pkcs10,
            ModestServerHarness.ValidBasicHeader());

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Authentication_is_still_required_when_the_check_is_disabled()
    {
        using HttpResponseMessage response = await _harness.PostEstAsync(
            ReenrollPath,
            Base64Wire.Encode(CsrFactory.CreateRsa("CN=anonymous.example.com")),
            EstMediaTypes.Pkcs10,
            authorization: null);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }
}
