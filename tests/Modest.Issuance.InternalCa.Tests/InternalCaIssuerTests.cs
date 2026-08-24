using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using Modest.Core.Est;
using Modest.Core.Issuance;
using Modest.TestSupport;

namespace Modest.Issuance.InternalCa.Tests;

/// <summary>
/// End-to-end behaviour of the issuer: bytes in, an <see cref="IssuanceResult"/> out. Rejection is
/// an ordinary outcome here — the one thing that must never happen is an exception escaping to the
/// protocol layer and turning a hostile CSR into a 500.
/// </summary>
public sealed class InternalCaIssuerTests
{
    private static IssuanceResult.Issued ShouldBeIssued(IssuanceResult result)
    {
        result.ShouldBeOfType<IssuanceResult.Issued>();
        return (IssuanceResult.Issued)result;
    }

    private static IssuanceResult.Rejected ShouldBeRejected(
        IssuanceResult result, IssuanceRejectionKind kind = IssuanceRejectionKind.InvalidCsr)
    {
        result.ShouldBeOfType<IssuanceResult.Rejected>();
        var rejected = (IssuanceResult.Rejected)result;
        rejected.Kind.ShouldBe(kind);
        rejected.Reason.ShouldNotBeNullOrWhiteSpace();
        return rejected;
    }

    // ------------------------------------------------------------------ happy path

    [Fact]
    public async Task IssueAsync_IssuesForAValidRsaCsr()
    {
        using DiskCa ca = DiskCa.Create();
        using InternalCaIssuer issuer = ca.CreateIssuer();

        IssuanceResult result = await issuer.IssueAsync(
            Test.Request(CsrFactory.CreateRsa(dnsNames: ["device01.example.com"])),
            CancellationToken.None);

        IssuanceResult.Issued issued = ShouldBeIssued(result);

        issued.Certificate.Issuer.ShouldBe(ca.Ca.Issuer.Subject);
        issued.Certificate.Subject.ShouldBe("CN=device01.example.com");
        issued.Chain.Count.ShouldBe(2);
        issued.Chain[0].Thumbprint.ShouldBe(ca.Ca.Intermediate!.Thumbprint);
        issued.Chain[1].Thumbprint.ShouldBe(ca.Ca.Root.Thumbprint);

        (bool built, string status) = Test.BuildChain(issued.Certificate, ca.Ca);
        built.ShouldBeTrue("Chain build failed: " + status);

        issued.Certificate.Dispose();
    }

    [Fact]
    public async Task IssueAsync_IssuesForAnEcdsaCsr()
    {
        using DiskCa ca = DiskCa.Create();
        using InternalCaIssuer issuer = ca.CreateIssuer();

        IssuanceResult result = await issuer.IssueAsync(
            Test.Request(CsrFactory.CreateEcdsa()), CancellationToken.None);

        IssuanceResult.Issued issued = ShouldBeIssued(result);

        using ECDsa? key = issued.Certificate.GetECDsaPublicKey();
        key.ShouldNotBeNull();

        issued.Certificate.Dispose();
    }

    [Fact]
    public async Task IssueAsync_WorksForReenrollmentToo()
    {
        using DiskCa ca = DiskCa.Create();
        using InternalCaIssuer issuer = ca.CreateIssuer();

        IssuanceResult result = await issuer.IssueAsync(
            Test.Request(CsrFactory.CreateRsa(), EstOperation.Reenroll),
            CancellationToken.None);

        ShouldBeIssued(result).Certificate.Dispose();
    }

    [Fact]
    public async Task IssueAsync_GivesEachEnrollmentOfTheSameCsrAFreshSerial()
    {
        using DiskCa ca = DiskCa.Create();
        using InternalCaIssuer issuer = ca.CreateIssuer();
        byte[] der = CsrFactory.CreateRsa();

        IssuanceResult first = await issuer.IssueAsync(
            Test.Request(der), CancellationToken.None);
        IssuanceResult second = await issuer.IssueAsync(
            Test.Request(der), CancellationToken.None);

        using X509Certificate2 a = ShouldBeIssued(first).Certificate;
        using X509Certificate2 b = ShouldBeIssued(second).Certificate;

        a.SerialNumber.ShouldNotBe(b.SerialNumber);
    }

    // ------------------------------------------------------------------ the critical one

    [Fact]
    public async Task IssueAsync_DoesNotMintASubordinateCaOnRequest()
    {
        using DiskCa ca = DiskCa.Create();
        using InternalCaIssuer issuer = ca.CreateIssuer();

        IssuanceResult result = await issuer.IssueAsync(
            Test.Request(CsrFactory.CreateRequestingCaPrivileges()),
            CancellationToken.None);

        using X509Certificate2 issued = ShouldBeIssued(result).Certificate;

        Test.BasicConstraints(issued).CertificateAuthority.ShouldBeFalse();
        Test.KeyUsage(issued).KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign).ShouldBeFalse();
    }

    // ------------------------------------------------------------------ rejections

    [Fact]
    public async Task IssueAsync_RejectsACsrWhoseSignatureDoesNotVerify()
    {
        using DiskCa ca = DiskCa.Create();
        using InternalCaIssuer issuer = ca.CreateIssuer();
        byte[] tampered = CsrFactory.WithBrokenSignature(CsrFactory.CreateRsa());

        IssuanceResult result = await issuer.IssueAsync(
            Test.Request(tampered), CancellationToken.None);

        ShouldBeRejected(result);
    }

    [Fact]
    public async Task IssueAsync_RejectsAnEmptyBody()
    {
        using DiskCa ca = DiskCa.Create();
        using InternalCaIssuer issuer = ca.CreateIssuer();

        IssuanceResult result = await issuer.IssueAsync(
            Test.Request([]), CancellationToken.None);

        ShouldBeRejected(result);
    }

    [Fact]
    public async Task IssueAsync_RejectsBytesThatAreNotDerAtAll()
    {
        using DiskCa ca = DiskCa.Create();
        using InternalCaIssuer issuer = ca.CreateIssuer();

        IssuanceResult result = await issuer.IssueAsync(
            Test.Request([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]), CancellationToken.None);

        ShouldBeRejected(result);
    }

    [Fact]
    public async Task IssueAsync_RejectsACertificateSubmittedInPlaceOfACsr()
    {
        using DiskCa ca = DiskCa.Create();
        using InternalCaIssuer issuer = ca.CreateIssuer();

        IssuanceResult result = await issuer.IssueAsync(
            Test.Request(ca.Ca.Root.RawData), CancellationToken.None);

        ShouldBeRejected(result);
    }

    [Fact]
    public async Task IssueAsync_RejectsAnUndersizedRsaKey()
    {
        using DiskCa ca = DiskCa.Create();
        using InternalCaIssuer issuer = ca.CreateIssuer(o => o.MinimumRsaKeySizeBits = 2048);

        IssuanceResult result = await issuer.IssueAsync(
            Test.Request(CsrFactory.CreateRsa(keySizeBits: 1024)), CancellationToken.None);

        ShouldBeRejected(result).Reason.ShouldContain("RSA-1024");
    }

    [Fact]
    public async Task IssueAsync_RejectsADisallowedCurve()
    {
        using DiskCa ca = DiskCa.Create();
        using InternalCaIssuer issuer = ca.CreateIssuer(o => o.AllowedEllipticCurves = ["nistP521"]);

        IssuanceResult result = await issuer.IssueAsync(
            Test.Request(CsrFactory.CreateEcdsa(curveName: "nistP256")),
            CancellationToken.None);

        ShouldBeRejected(result);
    }

    [Fact]
    public async Task IssueAsync_RejectsACsrCarryingASanUriThatIsNotAUri()
    {
        // Every byte of the SAN is attacker-controlled. A value the certificate builder cannot
        // encode has to come back as a rejection; letting the exception escape turns a malformed
        // CSR into an unhandled fault at the protocol layer.
        using DiskCa ca = DiskCa.Create();
        using InternalCaIssuer issuer = ca.CreateIssuer();
        byte[] der = CsrFactory.CreateRsa(extraExtensions: [Test.MalformedUriSan()]);

        IssuanceResult result = await issuer.IssueAsync(
            Test.Request(der), CancellationToken.None);

        ShouldBeRejected(result);
    }

    [Fact]
    public async Task IssueAsync_ThrowsForANullRequest()
    {
        using DiskCa ca = DiskCa.Create();
        using InternalCaIssuer issuer = ca.CreateIssuer();

        await Should.ThrowAsync<ArgumentNullException>(
            async () => await issuer.IssueAsync(null!, CancellationToken.None));
    }

    // ------------------------------------------------------------------ chain and readiness

    [Fact]
    public async Task GetCaChainAsync_ReturnsTheSigningCaFollowedByTheConfiguredExtras()
    {
        using DiskCa ca = DiskCa.Create();
        using InternalCaIssuer issuer = ca.CreateIssuer();

        CaChainResult chain = await issuer.GetCaChainAsync(CancellationToken.None);

        chain.Chain.Count.ShouldBe(2);
        chain.Chain[0].Thumbprint.ShouldBe(ca.Ca.Intermediate!.Thumbprint);
        chain.Chain[1].Thumbprint.ShouldBe(ca.Ca.Root.Thumbprint);
    }

    [Fact]
    public async Task GetCaChainAsync_ReturnsJustTheCaWhenNoExtrasAreConfigured()
    {
        using DiskCa ca = DiskCa.Create(withIntermediate: false);
        using InternalCaIssuer issuer = ca.CreateIssuer(o => o.AdditionalChainCertificatePaths = []);

        CaChainResult chain = await issuer.GetCaChainAsync(CancellationToken.None);

        chain.Chain.Count.ShouldBe(1);
        chain.Chain[0].Thumbprint.ShouldBe(ca.Ca.Root.Thumbprint);
    }

    [Fact]
    public async Task GetCaChainAsync_IsAnswerableBeforeAnyEnrollmentHasHappened()
    {
        using DiskCa ca = DiskCa.Create();
        using InternalCaIssuer issuer = ca.CreateIssuer();

        CaChainResult chain = await issuer.GetCaChainAsync(CancellationToken.None);

        chain.Chain.ShouldNotBeEmpty();
    }

    [Fact]
    public async Task IsReadyAsync_IsTrueOnceConstructionSucceeded()
    {
        using DiskCa ca = DiskCa.Create();
        using InternalCaIssuer issuer = ca.CreateIssuer();

        (await issuer.IsReadyAsync(CancellationToken.None)).ShouldBeTrue();
    }

    [Fact]
    public async Task IsReadyAsync_IsFalseAfterDisposal()
    {
        using DiskCa ca = DiskCa.Create();
        InternalCaIssuer issuer = ca.CreateIssuer();
        issuer.Dispose();

        (await issuer.IsReadyAsync(CancellationToken.None)).ShouldBeFalse();
    }

    [Fact]
    public async Task IssueAsync_ThrowsAfterDisposal()
    {
        using DiskCa ca = DiskCa.Create();
        InternalCaIssuer issuer = ca.CreateIssuer();
        byte[] der = CsrFactory.CreateRsa();
        issuer.Dispose();

        await Should.ThrowAsync<ObjectDisposedException>(
            async () => await issuer.IssueAsync(Test.Request(der), CancellationToken.None));
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        using DiskCa ca = DiskCa.Create();
        InternalCaIssuer issuer = ca.CreateIssuer();

        issuer.Dispose();
        Should.NotThrow(issuer.Dispose);
    }

    // ------------------------------------------------------------------ fail-closed startup

    [Fact]
    public void Constructor_ThrowsCaKeyLoadExceptionForABrokenConfiguration()
    {
        // Epic 3's definition of done: a broken PFX config must surface as this exact type so the
        // host can print an operator-facing message and exit non-zero, never start unable to sign.
        using var directory = new TempDirectory();
        var options = new InternalCaOptions { CertificatePath = directory.MissingFile("ca.pfx") };

        Should.Throw<CaKeyLoadException>(() => new InternalCaIssuer(
            Test.Wrap(options),
            new CaKeyLoader(NullLogger<CaKeyLoader>.Instance),
            NullLogger<InternalCaIssuer>.Instance));
    }

    [Fact]
    public void Constructor_ThrowsForNullArguments()
    {
        var options = new InternalCaOptions { CertificatePath = "unused.pfx" };

        Should.Throw<ArgumentNullException>(() => new InternalCaIssuer(
            null!, new CaKeyLoader(NullLogger<CaKeyLoader>.Instance), NullLogger<InternalCaIssuer>.Instance));

        Should.Throw<ArgumentNullException>(() => new InternalCaIssuer(
            Test.Wrap(options), null!, NullLogger<InternalCaIssuer>.Instance));
    }

    // ------------------------------------------------------------------ logging

    [Fact]
    public async Task IssueAsync_LogsTheAuditFactsAboutTheIssuance()
    {
        using DiskCa ca = DiskCa.Create();
        var logger = new CapturingLogger<InternalCaIssuer>();
        using InternalCaIssuer issuer = ca.CreateIssuer(logger: logger);

        IssuanceResult result = await issuer.IssueAsync(
            Test.Request(CsrFactory.CreateRsa("CN=audit.example.com")),
            CancellationToken.None);

        using X509Certificate2 issued = ShouldBeIssued(result).Certificate;

        logger.Text.ShouldContain(issued.SerialNumber);
        logger.Text.ShouldContain("CN=audit.example.com");
        logger.Text.ShouldContain("device01"); // the authenticated identity
        logger.Text.ShouldContain("Enroll");
    }

    [Fact]
    public async Task IssueAsync_NeverLogsTheCaPrivateKeyOrThePfxPassword()
    {
        using DiskCa ca = DiskCa.Create();
        var issuerLogger = new CapturingLogger<InternalCaIssuer>();
        var loaderLogger = new CapturingLogger<CaKeyLoader>();

        using var issuer = new InternalCaIssuer(
            Test.Wrap(ca.Options()), new CaKeyLoader(loaderLogger), issuerLogger);

        IssuanceResult result = await issuer.IssueAsync(
            Test.Request(CsrFactory.CreateRsa()), CancellationToken.None);

        ShouldBeIssued(result).Certificate.Dispose();

        string log = loaderLogger.Text + "\n" + issuerLogger.Text;

        log.ShouldNotBeNullOrWhiteSpace("The issuance path logged nothing at all, so this proves little.");
        log.ShouldNotContain(DiskCa.Password);
        log.ShouldNotContain("PRIVATE KEY");

        foreach (string secret in Test.PrivateKeyFingerprints(ca.Ca.Issuer))
        {
            log.ShouldNotContain(secret);
        }
    }

    [Fact]
    public async Task IssueAsync_LogsWhyItRejectedARequest()
    {
        using DiskCa ca = DiskCa.Create();
        var logger = new CapturingLogger<InternalCaIssuer>();
        using InternalCaIssuer issuer = ca.CreateIssuer(logger: logger);

        IssuanceResult result = await issuer.IssueAsync(
            Test.Request(CsrFactory.CreateRsa("CN=weak.example.com", keySizeBits: 1024)),
            CancellationToken.None);

        ShouldBeRejected(result);

        logger.Text.ShouldContain("RSA-1024");
        logger.Text.ShouldContain("CN=weak.example.com");
    }
}
