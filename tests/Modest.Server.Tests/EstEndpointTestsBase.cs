using System.Net;
using System.Security.Cryptography.X509Certificates;
using Modest.Codec;
using Modest.Core.Est;
using Modest.TestSupport;

namespace Modest.Server.Tests;

/// <summary>
/// The EST protocol surface, exercised over real HTTPS against a real host.
/// </summary>
/// <remarks>
/// Every test here is inherited by one concrete class per issuance mode. That is the whole claim of
/// the modular-issuance design: the wire behaviour of the protocol layer — status codes, media types,
/// authentication, proof-of-possession — must not depend on which issuer is registered. Running the
/// suite once against the internal CA would leave that claim untested, and a protocol-layer
/// regression that only showed up in delegated mode would ship.
/// </remarks>
public abstract class EstEndpointTestsBase
{
    private const string CaCertsPath = EstUriPaths.Prefix + EstUriPaths.CaCerts;
    private const string CsrAttrsPath = EstUriPaths.Prefix + EstUriPaths.CsrAttrs;
    private const string EnrollPath = EstUriPaths.Prefix + EstUriPaths.SimpleEnroll;
    private const string ReenrollPath = EstUriPaths.Prefix + EstUriPaths.SimpleReenroll;

    protected EstEndpointTestsBase(ModestServerHarness harness)
    {
        Harness = harness;
    }

    /// <summary>The running host under test.</summary>
    protected ModestServerHarness Harness { get; }

    // ---------------------------------------------------------------- /cacerts

    [Fact]
    public async Task Cacerts_serves_the_configured_chain_without_any_credentials()
    {
        using HttpResponseMessage response = await Harness.GetEstAsync(CaCertsPath);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        EstResponse.ShouldBeCertsOnlyResponse(response);

        IReadOnlyList<X509Certificate2> certificates = await EstResponse.ReadCertsOnlyAsync(response);

        // Order is load-bearing: RFC 7030 clients walk the bag from the issuing CA upwards, and the
        // codec goes out of its way to preserve insertion order for exactly this reason.
        certificates.Select(static c => c.Thumbprint)
            .ShouldBe(TestPki.Ca.Chain.Select(static c => c.Thumbprint));
    }

    [Fact]
    public async Task Cacerts_ignores_credentials_it_is_given()
    {
        // Bootstrap operations are unauthenticated, not "authenticated when convenient": a client
        // that happens to hold credentials must get the same answer as one that does not.
        using HttpResponseMessage response =
            await Harness.GetEstAsync(CaCertsPath, ModestServerHarness.ValidBasicHeader());

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    // --------------------------------------------------------------- /csrattrs

    [Fact]
    public async Task Csrattrs_returns_204_with_an_empty_body_and_no_authentication()
    {
        using HttpResponseMessage response = await Harness.GetEstAsync(CsrAttrsPath);

        response.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await response.Content.ReadAsByteArrayAsync()).ShouldBeEmpty();
    }

    // ----------------------------------------------------------- authentication

    [Fact]
    public async Task Simpleenroll_without_credentials_returns_401_and_challenges_for_basic()
    {
        using HttpResponseMessage response = await PostCsrAsync(EnrollPath, NewCsr(), authorization: null);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        EstResponse.Header(response, "WWW-Authenticate").ShouldBe("Basic realm=\"modest\"");
    }

    [Fact]
    public async Task Simplereenroll_without_credentials_returns_401_and_challenges_for_basic()
    {
        using HttpResponseMessage response = await PostCsrAsync(ReenrollPath, NewCsr(), authorization: null);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        EstResponse.Header(response, "WWW-Authenticate").ShouldBe("Basic realm=\"modest\"");
    }

    [Fact]
    public async Task Simpleenroll_with_the_wrong_password_returns_401()
    {
        string header = ModestServerHarness.BasicHeader(
            ModestServerHarness.BasicUsername, ModestServerHarness.BasicPassword + "-wrong");

        using HttpResponseMessage response = await PostCsrAsync(EnrollPath, NewCsr(), header);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Simpleenroll_with_an_unknown_username_returns_401()
    {
        string header = ModestServerHarness.BasicHeader("nobody", ModestServerHarness.BasicPassword);

        using HttpResponseMessage response = await PostCsrAsync(EnrollPath, NewCsr(), header);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Theory]
    [InlineData("Basic")]
    [InlineData("Basic ")]
    [InlineData("Basic not-base64!!")]
    [InlineData("Basic dXNlcm5hbWUtd2l0aC1uby1jb2xvbg==")] // decodes, but has no ':' separator
    [InlineData("nonsense")]
    public async Task Simpleenroll_with_a_malformed_authorization_header_returns_401(string header)
    {
        using HttpResponseMessage response = await PostCsrAsync(EnrollPath, NewCsr(), header);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Simpleenroll_with_a_non_basic_scheme_returns_401()
    {
        // A bearer token is not an EST credential no matter how well formed it is; accepting one
        // would mean the middleware was parsing schemes it does not actually validate.
        using HttpResponseMessage response =
            await PostCsrAsync(EnrollPath, NewCsr(), "Bearer aGVsbG8td29ybGQ=");

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    // ------------------------------------------------------------- happy paths

    [Fact]
    public async Task Simpleenroll_with_valid_basic_credentials_issues_a_certificate_for_the_submitted_key()
    {
        byte[] csrDer = CsrFactory.CreateRsa("CN=basic-enrolled.example.com");

        using HttpResponseMessage response =
            await PostCsrAsync(EnrollPath, ToBody(csrDer), ModestServerHarness.ValidBasicHeader());

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        EstResponse.ShouldBeCertsOnlyResponse(response);

        await AssertIssuedForAsync(response, csrDer);
    }

    [Fact]
    public async Task Simpleenroll_with_a_tls_client_certificate_and_no_authorization_header_issues_a_certificate()
    {
        using X509Certificate2 clientCertificate = TestPki.Ca.IssueLeaf("CN=cert-enrolled.example.com");
        byte[] csrDer = CsrFactory.CreateRsa("CN=cert-enrolled.example.com");

        using HttpResponseMessage response = await Harness.PostEstAsync(
            EnrollPath, ToBody(csrDer), authorization: null, clientCertificate: clientCertificate);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        await AssertIssuedForAsync(response, csrDer);
    }

    [Fact]
    public async Task Simpleenroll_success_body_is_base64_text_and_survives_line_wrapping_on_the_way_in()
    {
        // Some EST clients wrap their request at 64 characters like classic PEM and some send one
        // unbroken line. Both are legal; neither may change the answer.
        byte[] csrDer = CsrFactory.CreateRsa("CN=wrapped.example.com");
        string wrapped = Base64Wire.EncodeWrapped(csrDer, lineLength: 64);

        wrapped.ShouldContain('\n');

        using HttpResponseMessage response =
            await PostCsrAsync(EnrollPath, wrapped, ModestServerHarness.ValidBasicHeader());

        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        string body = await response.Content.ReadAsStringAsync();
        body.ShouldNotBeNullOrWhiteSpace();

        // Decoding is done through the tolerant path so the assertion says nothing about whether the
        // server wraps its own output — only that whatever it wrote is base64 for a certs-only PKCS#7.
        Pkcs7CertsOnlyWriter.Read(Base64Wire.DecodeTolerant(body)).ShouldNotBeEmpty();
    }

    [Fact]
    public async Task Simpleenroll_accepts_a_content_type_carrying_parameters()
    {
        using HttpResponseMessage response = await Harness.PostEstAsync(
            EnrollPath,
            ToBody(CsrFactory.CreateRsa("CN=parameterised.example.com")),
            contentType: "application/pkcs10; charset=utf-8",
            authorization: ModestServerHarness.ValidBasicHeader());

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    // ----------------------------------------------------------- error mapping

    [Fact]
    public async Task Simpleenroll_with_the_wrong_content_type_returns_415()
    {
        using HttpResponseMessage response = await Harness.PostEstAsync(
            EnrollPath,
            ToBody(CsrFactory.CreateRsa()),
            contentType: "application/json",
            authorization: ModestServerHarness.ValidBasicHeader());

        response.StatusCode.ShouldBe(HttpStatusCode.UnsupportedMediaType);
    }

    [Fact]
    public async Task Simpleenroll_without_a_content_type_returns_415()
    {
        using HttpResponseMessage response = await Harness.PostEstAsync(
            EnrollPath,
            ToBody(CsrFactory.CreateRsa()),
            contentType: null,
            authorization: ModestServerHarness.ValidBasicHeader());

        response.StatusCode.ShouldBe(HttpStatusCode.UnsupportedMediaType);
    }

    [Fact]
    public async Task Simpleenroll_with_a_body_that_is_not_base64_returns_400()
    {
        using HttpResponseMessage response = await PostCsrAsync(
            EnrollPath, "this is definitely not base64 ***", ModestServerHarness.ValidBasicHeader());

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Simpleenroll_with_base64_that_is_not_a_csr_returns_400()
    {
        string body = Convert.ToBase64String("hello, this decodes cleanly and means nothing"u8.ToArray());

        using HttpResponseMessage response =
            await PostCsrAsync(EnrollPath, body, ModestServerHarness.ValidBasicHeader());

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Simpleenroll_with_a_tampered_csr_signature_returns_400()
    {
        // Proof-of-possession. The DER still parses; only the signature no longer matches the
        // enclosed public key, which is exactly the shape of a replayed CSR with a swapped key.
        byte[] tampered = CsrFactory.WithBrokenSignature(CsrFactory.CreateRsa("CN=impostor.example.com"));

        using HttpResponseMessage response =
            await PostCsrAsync(EnrollPath, ToBody(tampered), ModestServerHarness.ValidBasicHeader());

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Simpleenroll_with_an_empty_body_returns_400()
    {
        using HttpResponseMessage response =
            await PostCsrAsync(EnrollPath, string.Empty, ModestServerHarness.ValidBasicHeader());

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Simpleenroll_with_a_body_above_the_configured_limit_returns_413()
    {
        string oversized = new('A', (Harness.Options.MaxRequestBodyBytes * 2) + 1);

        using HttpResponseMessage response =
            await PostCsrAsync(EnrollPath, oversized, ModestServerHarness.ValidBasicHeader());

        response.StatusCode.ShouldBe(HttpStatusCode.RequestEntityTooLarge);
    }

    [Fact]
    public async Task Simpleenroll_checks_credentials_before_it_looks_at_the_body()
    {
        // An unauthenticated caller must not be able to learn anything about parsing or size limits.
        // Sending a request that is wrong in three ways at once pins the ordering of the checks.
        using HttpResponseMessage response = await Harness.PostEstAsync(
            EnrollPath,
            new string('A', (Harness.Options.MaxRequestBodyBytes * 2) + 1),
            contentType: "application/json",
            authorization: null);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>A fresh, well-formed 2048-bit RSA CSR as an EST request body.</summary>
    private static string NewCsr() => ToBody(CsrFactory.CreateRsa());

    private static string ToBody(byte[] der) => Base64Wire.Encode(der);

    private Task<HttpResponseMessage> PostCsrAsync(string path, string body, string? authorization) =>
        Harness.PostEstAsync(path, body, EstMediaTypes.Pkcs10, authorization);

    /// <summary>
    /// Asserts that an enrollment response really is a certificate for the key in
    /// <paramref name="csrDer"/>, anchored on the CA the server publishes from /cacerts.
    /// </summary>
    private async Task AssertIssuedForAsync(HttpResponseMessage response, byte[] csrDer)
    {
        IReadOnlyList<X509Certificate2> returned = await EstResponse.ReadCertsOnlyAsync(response);
        returned.ShouldNotBeEmpty();

        X509Certificate2 leaf = returned[0];

        ParsedCsr csr = Pkcs10CsrReader.Parse(csrDer);
        leaf.PublicKey.ExportSubjectPublicKeyInfo()
            .ShouldBe(
                csr.PublicKey.ExportSubjectPublicKeyInfo(),
                "the issued certificate must carry the public key from this CSR and no other");

        leaf.SubjectName.Name.ShouldBe(csr.Subject.Name);

        // Anchor on what the server itself advertises rather than on the test's own CA object: if
        // /cacerts and issuance ever disagreed about which CA this server is, a client following the
        // protocol would be stuck, and only an assertion routed through /cacerts would notice.
        IReadOnlyList<X509Certificate2> advertised = await FetchCaCertsAsync();

        (bool built, string status) = TestPki.TryBuildChain(leaf, advertised);
        built.ShouldBeTrue($"the issued certificate should chain to the advertised CA, but: {status}");
    }

    private async Task<IReadOnlyList<X509Certificate2>> FetchCaCertsAsync()
    {
        using HttpResponseMessage response = await Harness.GetEstAsync(CaCertsPath);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        return await EstResponse.ReadCertsOnlyAsync(response);
    }
}
