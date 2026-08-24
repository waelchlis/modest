using System.Net;
using Modest.Codec;
using Modest.Core.Est;
using Modest.TestSupport;

namespace Modest.Server.Tests;

/// <summary>
/// Rows of the status table that only the internal CA can produce, because they come from its own
/// key policy rather than from the protocol layer.
/// </summary>
[Collection(InternalCaHost.Name)]
public sealed class InternalCaPolicyTests(InternalCaFixture fixture)
{
    private const string EnrollPath = EstUriPaths.Prefix + EstUriPaths.SimpleEnroll;

    private readonly ModestServerHarness _harness = fixture.Harness;

    [Fact]
    public async Task An_rsa_key_below_the_configured_minimum_is_a_400()
    {
        // IssuanceRejectionKind.InvalidCsr, and therefore 400 rather than 403: the request is
        // malformed by this CA's rules and the client can fix it by generating a stronger key.
        byte[] csr = CsrFactory.CreateRsa("CN=weak.example.com", keySizeBits: 1024);

        using HttpResponseMessage response = await _harness.PostEstAsync(
            EnrollPath,
            Base64Wire.Encode(csr),
            EstMediaTypes.Pkcs10,
            ModestServerHarness.ValidBasicHeader());

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        string body = await response.Content.ReadAsStringAsync();
        body.ShouldContain("RSA-1024");
        body.ShouldContain("RSA-2048");
    }

    [Fact]
    public async Task An_error_body_is_plain_text_as_rfc_7030_requires()
    {
        using HttpResponseMessage response = await _harness.PostEstAsync(
            EnrollPath,
            "not base64 at all ***",
            EstMediaTypes.Pkcs10,
            ModestServerHarness.ValidBasicHeader());

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        string? mediaType = response.Content.Headers.ContentType?.MediaType;
        mediaType.ShouldBe("text/plain");
    }

    [Fact]
    public async Task A_csr_asking_for_ca_privileges_does_not_get_them()
    {
        // The CSR is a request, not a fact. A CA that copied requested extensions wholesale would
        // mint a subordinate authority for anyone who asked, so the response here must either refuse
        // outright or issue an end-entity certificate — never a CA one.
        byte[] csr = CsrFactory.CreateRequestingCaPrivileges("CN=ambitious.example.com");

        using HttpResponseMessage response = await _harness.PostEstAsync(
            EnrollPath,
            Base64Wire.Encode(csr),
            EstMediaTypes.Pkcs10,
            ModestServerHarness.ValidBasicHeader());

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var issued = await EstResponse.ReadCertsOnlyAsync(response);
            issued.ShouldNotBeEmpty();

            var basicConstraints = issued[0].Extensions
                .OfType<System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension>()
                .FirstOrDefault();

            (basicConstraints?.CertificateAuthority ?? false).ShouldBeFalse(
                "a certificate authority must never be minted from a client's request for one");
        }
        else
        {
            response.StatusCode.ShouldBeOneOf(HttpStatusCode.BadRequest, HttpStatusCode.Forbidden);
        }
    }
}
