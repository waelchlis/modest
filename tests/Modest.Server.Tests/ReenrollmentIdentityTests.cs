using System.Net;
using System.Security.Cryptography.X509Certificates;
using Modest.Codec;
using Modest.Core.Est;
using Modest.TestSupport;

namespace Modest.Server.Tests;

/// <summary>
/// /simplereenroll must renew the caller's own identity and nobody else's.
/// </summary>
/// <remarks>
/// Nothing in RFC 7030 forces the requested subject to match the certificate presented for
/// authentication, so without this check a renewal endpoint is also an impersonation endpoint: any
/// holder of any certificate this server trusts could ask for one bearing someone else's name. These
/// tests run against a host with <c>Issuance:Reenrollment:RequireMatchingIdentity</c> at its default
/// of true.
/// </remarks>
[Collection(InternalCaHost.Name)]
[Trait("Rfc7030Section", "5")]
public sealed class ReenrollmentIdentityTests(InternalCaFixture fixture)
{
    private const string ReenrollPath = EstUriPaths.Prefix + EstUriPaths.SimpleReenroll;

    private readonly ModestServerHarness _harness = fixture.Harness;

    [Fact]
    public async Task Identical_subject_and_sans_are_renewed()
    {
        using X509Certificate2 held = TestPki.Ca.IssueLeaf(
            "CN=renew.example.com", dnsNames: ["renew.example.com", "alias.example.com"]);

        byte[] csr = CsrFactory.CreateRsa(
            "CN=renew.example.com", dnsNames: ["renew.example.com", "alias.example.com"]);

        using HttpResponseMessage response = await ReenrollAsync(csr, held);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await EstResponse.ReadCertsOnlyAsync(response)).ShouldNotBeEmpty();
    }

    [Fact]
    public async Task San_order_does_not_matter()
    {
        // Set equality, not sequence equality. A client that reorders its own names between renewals
        // is doing nothing wrong, and failing it would make the check useless in practice — which is
        // how such checks end up switched off.
        using X509Certificate2 held = TestPki.Ca.IssueLeaf(
            "CN=ordered.example.com", dnsNames: ["one.example.com", "two.example.com", "three.example.com"]);

        byte[] csr = CsrFactory.CreateRsa(
            "CN=ordered.example.com", dnsNames: ["three.example.com", "one.example.com", "two.example.com"]);

        using HttpResponseMessage response = await ReenrollAsync(csr, held);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_subject_that_differs_from_the_presented_certificate_is_refused()
    {
        using X509Certificate2 held = TestPki.Ca.IssueLeaf("CN=self.example.com");
        byte[] csr = CsrFactory.CreateRsa("CN=somebody-else.example.com");

        using HttpResponseMessage response = await ReenrollAsync(csr, held);

        // 403 rather than 401: the caller authenticated perfectly well, they are simply not
        // authorised to renew this identity, and a 401 would invite them to retry with other
        // credentials as though that could help.
        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        // Which check fired matters as much as the status. Every refusal below is a 403, so without
        // this the SAN tests would still pass if the client certificate had silently not been
        // presented at all and the "no certificate" branch had answered instead.
        (await response.Content.ReadAsStringAsync()).ShouldContain("subject in the certificate signing request");
    }

    [Fact]
    public async Task An_extra_san_the_presented_certificate_lacks_is_refused()
    {
        // The escalation that matters. Subject DNs are rarely what a TLS peer is validated against;
        // DNS names are. A check that only compared subjects would wave this straight through.
        using X509Certificate2 held = TestPki.Ca.IssueLeaf(
            "CN=device.example.com", dnsNames: ["device.example.com"]);

        byte[] csr = CsrFactory.CreateRsa(
            "CN=device.example.com", dnsNames: ["device.example.com", "admin.example.com"]);

        using HttpResponseMessage response = await ReenrollAsync(csr, held);

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await response.Content.ReadAsStringAsync())
            .ShouldContain("subject alternative names");
    }

    [Fact]
    public async Task A_san_omitted_from_the_request_is_refused()
    {
        // Refused in this direction too. The rule is set equality, not containment: allowing a subset
        // would let a caller narrow its way towards a name set that later comparisons treat as its
        // own, and "renew what you hold" means exactly what you hold.
        using X509Certificate2 held = TestPki.Ca.IssueLeaf(
            "CN=device.example.com", dnsNames: ["device.example.com", "extra.example.com"]);

        byte[] csr = CsrFactory.CreateRsa("CN=device.example.com", dnsNames: ["device.example.com"]);

        using HttpResponseMessage response = await ReenrollAsync(csr, held);

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await response.Content.ReadAsStringAsync())
            .ShouldContain("subject alternative names");
    }

    [Fact]
    public async Task A_dns_san_does_not_match_an_ip_san_with_the_same_text()
    {
        using X509Certificate2 held = TestPki.Ca.IssueLeaf(
            "CN=numeric.example.com", ipAddresses: ["10.1.2.3"]);

        byte[] csr = CsrFactory.CreateRsa("CN=numeric.example.com", dnsNames: ["10.1.2.3"]);

        using HttpResponseMessage response = await ReenrollAsync(csr, held);

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await response.Content.ReadAsStringAsync())
            .ShouldContain("subject alternative names");
    }

    [Fact]
    public async Task Basic_authentication_with_no_client_certificate_is_refused()
    {
        // Documented behaviour, not an oversight: re-enrollment's premise is continuity with the
        // certificate being renewed, and a username and password establish continuity with nothing.
        byte[] csr = CsrFactory.CreateRsa("CN=password-only.example.com");

        using HttpResponseMessage response = await _harness.PostEstAsync(
            ReenrollPath,
            Base64Wire.Encode(csr),
            EstMediaTypes.Pkcs10,
            ModestServerHarness.ValidBasicHeader());

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await response.Content.ReadAsStringAsync())
            .ShouldContain("certificate being renewed");
    }

    [Fact]
    public async Task An_unauthenticated_reenrollment_is_a_401_not_a_403()
    {
        using HttpResponseMessage response = await _harness.PostEstAsync(
            ReenrollPath,
            Base64Wire.Encode(CsrFactory.CreateRsa("CN=anonymous.example.com")),
            EstMediaTypes.Pkcs10,
            authorization: null);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        EstResponse.Header(response, "WWW-Authenticate").ShouldBe("Basic realm=\"modest\"");
    }

    [Fact]
    public async Task Simpleenroll_is_not_subject_to_the_identity_check()
    {
        // The check belongs to renewal alone. Initial enrollment with a certificate that names
        // something else is the normal bootstrap case — a factory-issued device certificate asking
        // for its operational name — and must not be caught by it.
        using X509Certificate2 held = TestPki.Ca.IssueLeaf("CN=factory.example.com");
        byte[] csr = CsrFactory.CreateRsa("CN=operational.example.com");

        using HttpResponseMessage response = await _harness.PostEstAsync(
            EstUriPaths.Prefix + EstUriPaths.SimpleEnroll,
            Base64Wire.Encode(csr),
            EstMediaTypes.Pkcs10,
            authorization: null,
            clientCertificate: held);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    private Task<HttpResponseMessage> ReenrollAsync(byte[] csrDer, X509Certificate2 clientCertificate) =>
        _harness.PostEstAsync(
            ReenrollPath,
            Base64Wire.Encode(csrDer),
            EstMediaTypes.Pkcs10,
            authorization: null,
            clientCertificate: clientCertificate);
}
