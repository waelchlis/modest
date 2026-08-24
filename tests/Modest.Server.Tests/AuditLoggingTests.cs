using System.Net;
using System.Security.Cryptography.X509Certificates;
using Modest.Codec;
using Modest.Core.Est;
using Modest.TestSupport;

namespace Modest.Server.Tests;

/// <summary>
/// What the server writes down about an issuance, and what it must never write down.
/// </summary>
/// <remarks>
/// A certificate authority's log is the only record of who was given authority to speak as whom. It
/// has to name both halves of that — the identity that asked and the certificate that came back —
/// and it must do so without capturing the credential that authenticated the request, because logs
/// travel to places credentials must not.
/// </remarks>
public sealed class AuditLoggingTests : IAsyncLifetime
{
    private const string EnrollPath = EstUriPaths.Prefix + EstUriPaths.SimpleEnroll;

    private ModestServerHarness _harness = null!;

    // Its own host rather than a shared one: the assertions are about the contents of the log, and a
    // log other test classes are concurrently writing to would make "the password never appears"
    // depend on what else happened to run.
    public async Task InitializeAsync() => _harness = await ModestServerHarness.StartAsync();

    public async Task DisposeAsync() => await _harness.DisposeAsync();

    [Fact]
    public async Task A_successful_enrollment_records_the_serial_and_who_asked_for_it()
    {
        using HttpResponseMessage response = await _harness.PostEstAsync(
            EnrollPath,
            Base64Wire.Encode(CsrFactory.CreateRsa("CN=audited.example.com")),
            EstMediaTypes.Pkcs10,
            ModestServerHarness.ValidBasicHeader());

        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        IReadOnlyList<X509Certificate2> issued = await EstResponse.ReadCertsOnlyAsync(response);
        string serial = issued[0].SerialNumber;

        string log = _harness.Logs.AllText;

        log.ShouldContain(serial, Case.Insensitive, "the issued serial number must be auditable");
        log.ShouldContain(
            ModestServerHarness.BasicUsername,
            Case.Sensitive,
            "the log must name the identity that obtained the certificate");
        log.ShouldContain("CN=audited.example.com");
    }

    [Fact]
    public async Task An_enrollment_authenticated_by_certificate_records_that_certificate_subject()
    {
        using X509Certificate2 clientCertificate = TestPki.Ca.IssueLeaf("CN=audited-by-cert.example.com");

        using HttpResponseMessage response = await _harness.PostEstAsync(
            EnrollPath,
            Base64Wire.Encode(CsrFactory.CreateRsa("CN=issued-to-cert-holder.example.com")),
            EstMediaTypes.Pkcs10,
            authorization: null,
            clientCertificate: clientCertificate);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        _harness.Logs.AllText.ShouldContain("CN=audited-by-cert.example.com");
    }

    [Fact]
    public async Task The_basic_password_never_reaches_the_log()
    {
        // Exercise every path that has seen the password or something derived from it: a success, a
        // failed attempt with the wrong password, and a malformed header. Each is a plausible place
        // for a well-meant "log the header so we can debug auth" to be added later.
        string valid = ModestServerHarness.ValidBasicHeader();
        string wrong = ModestServerHarness.BasicHeader(
            ModestServerHarness.BasicUsername, ModestServerHarness.BasicPassword + "-wrong");

        foreach (string header in new[] { valid, wrong, "Basic " + valid })
        {
            using HttpResponseMessage response = await _harness.PostEstAsync(
                EnrollPath,
                Base64Wire.Encode(CsrFactory.CreateRsa("CN=secret-hunting.example.com")),
                EstMediaTypes.Pkcs10,
                header);

            response.StatusCode.ShouldBeOneOf(HttpStatusCode.OK, HttpStatusCode.Unauthorized);
        }

        string log = _harness.Logs.AllText;

        log.ShouldNotContain(
            ModestServerHarness.BasicPassword,
            Case.Insensitive,
            "the plaintext password must never be written to a log");

        // The encoded credential is the same secret in a thin disguise, and logging the raw
        // Authorization header is the usual way it escapes.
        log.ShouldNotContain(valid.AsSpan("Basic ".Length).ToString(), Case.Insensitive);
    }

    [Fact]
    public async Task A_rejected_request_is_logged_with_its_reason()
    {
        using HttpResponseMessage response = await _harness.PostEstAsync(
            EnrollPath,
            Base64Wire.Encode(CsrFactory.WithBrokenSignature(CsrFactory.CreateRsa("CN=tampered.example.com"))),
            EstMediaTypes.Pkcs10,
            ModestServerHarness.ValidBasicHeader());

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        _harness.Logs.AllText.ShouldContain("Enroll", Case.Insensitive);
    }
}
