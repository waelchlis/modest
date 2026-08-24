using Modest.Codec;
using Modest.Core.Issuance;
using Modest.TestSupport;

namespace Modest.Issuance.InternalCa.Tests;

/// <summary>
/// Policy is the only thing standing between a client's key and a signature over it, so each
/// switch is tested in both directions: what it lets through as well as what it stops.
/// </summary>
public sealed class CsrPolicyTests
{
    private static InternalCaOptions Defaults(Action<InternalCaOptions>? configure = null)
    {
        var options = new InternalCaOptions { CertificatePath = "unused.pfx" };
        configure?.Invoke(options);
        return options;
    }

    // ------------------------------------------------------------------ RSA key size

    [Fact]
    public void Evaluate_RejectsRsaBelowTheConfiguredMinimum()
    {
        ParsedCsr csr = Test.Parse(CsrFactory.CreateRsa(keySizeBits: 1024));

        IssuanceResult.Rejected? rejection =
            CsrPolicy.Evaluate(csr, Defaults(o => o.MinimumRsaKeySizeBits = 2048));

        rejection.ShouldNotBeNull();
        rejection.Kind.ShouldBe(IssuanceRejectionKind.InvalidCsr);
        rejection.Reason.ShouldContain("RSA-1024");
        rejection.Reason.ShouldContain("RSA-2048");
    }

    [Fact]
    public void Evaluate_AcceptsRsaExactlyAtTheMinimum()
    {
        ParsedCsr csr = Test.Parse(CsrFactory.CreateRsa(keySizeBits: 2048));

        CsrPolicy.Evaluate(csr, Defaults(o => o.MinimumRsaKeySizeBits = 2048)).ShouldBeNull();
    }

    [Fact]
    public void Evaluate_AcceptsRsaAboveTheMinimum()
    {
        ParsedCsr csr = Test.Parse(CsrFactory.CreateRsa(keySizeBits: 3072));

        CsrPolicy.Evaluate(csr, Defaults(o => o.MinimumRsaKeySizeBits = 2048)).ShouldBeNull();
    }

    [Fact]
    public void Evaluate_RejectsRsaWhenRsaIsDisabledEntirely()
    {
        ParsedCsr csr = Test.Parse(CsrFactory.CreateRsa(keySizeBits: 3072));

        IssuanceResult.Rejected? rejection = CsrPolicy.Evaluate(csr, Defaults(o => o.AllowRsa = false));

        rejection.ShouldNotBeNull();
        rejection.Kind.ShouldBe(IssuanceRejectionKind.InvalidCsr);
        rejection.Reason.ShouldContain("RSA");
    }

    [Fact]
    public void Evaluate_RefusesRsaWhenDisabledEvenThoughTheKeyIsLarge()
    {
        // The algorithm switch must not be shadowed by the size check passing.
        ParsedCsr csr = Test.Parse(CsrFactory.CreateRsa(keySizeBits: 4096));

        CsrPolicy.Evaluate(csr, Defaults(o =>
        {
            o.AllowRsa = false;
            o.MinimumRsaKeySizeBits = 1024;
        })).ShouldNotBeNull();
    }

    // ------------------------------------------------------------------ elliptic curves

    [Theory]
    [InlineData("nistP256")]
    [InlineData("nistP384")]
    [InlineData("nistP521")]
    public void Evaluate_AcceptsTheDefaultAllowedCurves(string curve)
    {
        ParsedCsr csr = Test.Parse(CsrFactory.CreateEcdsa(curveName: curve));

        CsrPolicy.Evaluate(csr, Defaults()).ShouldBeNull();
    }

    [Theory]
    [InlineData("nistP256")]
    [InlineData("nistP384")]
    [InlineData("nistP521")]
    public void TheDefaultAllowListUsesTheCurveNamesTheCsrReaderActuallyReports(string curve)
    {
        // The allow-list is compared against Pkcs10CsrReader.GetCurveName, whose value comes from
        // Oid.FriendlyName. If the two vocabularies disagree the default policy silently refuses
        // every EC key, which is exactly the sort of dead configuration that goes unnoticed.
        ParsedCsr csr = Test.Parse(CsrFactory.CreateEcdsa(curveName: curve));
        string? reported = Pkcs10CsrReader.GetCurveName(csr);

        reported.ShouldNotBeNull();
        new InternalCaOptions().EffectiveAllowedEllipticCurves.ShouldContain(
            reported!,
            StringComparer.OrdinalIgnoreCase,
            $"The default allow-list does not contain '{reported}', the name this platform reports.");
    }

    [Fact]
    public void Evaluate_RejectsACurveThatIsNotOnTheAllowList()
    {
        ParsedCsr csr = Test.Parse(CsrFactory.CreateEcdsa(curveName: "nistP256"));

        IssuanceResult.Rejected? rejection =
            CsrPolicy.Evaluate(csr, Defaults(o => o.AllowedEllipticCurves = ["nistP384"]));

        rejection.ShouldNotBeNull();
        rejection.Kind.ShouldBe(IssuanceRejectionKind.InvalidCsr);
        rejection.Reason.ShouldContain("nistP384");
    }

    [Fact]
    public void Evaluate_RejectsEveryCurveWhenTheAllowListIsEmpty()
    {
        ParsedCsr csr = Test.Parse(CsrFactory.CreateEcdsa());

        CsrPolicy.Evaluate(csr, Defaults(o => o.AllowedEllipticCurves = [])).ShouldNotBeNull();
    }

    [Fact]
    public void Evaluate_RejectsEcWhenEllipticCurveIsDisabledEntirely()
    {
        ParsedCsr csr = Test.Parse(CsrFactory.CreateEcdsa(curveName: "nistP256"));

        IssuanceResult.Rejected? rejection =
            CsrPolicy.Evaluate(csr, Defaults(o => o.AllowEllipticCurve = false));

        rejection.ShouldNotBeNull();
        rejection.Kind.ShouldBe(IssuanceRejectionKind.InvalidCsr);
    }

    [Fact]
    public void Evaluate_MatchesCurveNamesCaseInsensitively()
    {
        ParsedCsr csr = Test.Parse(CsrFactory.CreateEcdsa(curveName: "nistP256"));
        string allowed = Pkcs10CsrReader.GetCurveName(csr)!.ToUpperInvariant();

        CsrPolicy.Evaluate(csr, Defaults(o => o.AllowedEllipticCurves = [allowed])).ShouldBeNull();
    }

    [Fact]
    public void Evaluate_DoesNotApplyTheRsaMinimumToEcKeys()
    {
        // A P-256 key is 256 bits; if the RSA size rule leaked onto the EC path every EC CSR
        // would be refused. The allow-list is taken from the reader so this test fails only for
        // the reason it names.
        ParsedCsr csr = Test.Parse(CsrFactory.CreateEcdsa(curveName: "nistP256"));

        CsrPolicy.Evaluate(csr, Defaults(o =>
        {
            o.AllowedEllipticCurves = [Pkcs10CsrReader.GetCurveName(csr)!];
            o.MinimumRsaKeySizeBits = 4096;
        })).ShouldBeNull();
    }

    // ------------------------------------------------------------------ identity

    [Fact]
    public void Evaluate_RejectsACsrWithNeitherSubjectNorSan()
    {
        ParsedCsr csr = Test.Parse(CsrFactory.CreateRsa(subject: string.Empty));

        IssuanceResult.Rejected? rejection = CsrPolicy.Evaluate(csr, Defaults());

        rejection.ShouldNotBeNull();
        rejection.Kind.ShouldBe(IssuanceRejectionKind.InvalidCsr);
        rejection.Reason.ShouldContain("identify nobody");
    }

    [Fact]
    public void Evaluate_AcceptsAnEmptySubjectWhenSansCarryTheIdentity()
    {
        // The common shape for device enrollment: identity lives entirely in the SAN.
        ParsedCsr csr = Test.Parse(
            CsrFactory.CreateRsa(subject: string.Empty, dnsNames: ["device01.example.com"]));

        csr.Subject.Name.ShouldBeNullOrEmpty();
        csr.SubjectAlternativeNames.IsEmpty.ShouldBeFalse();

        CsrPolicy.Evaluate(csr, Defaults()).ShouldBeNull();
    }

    [Fact]
    public void Evaluate_AcceptsAnEmptySubjectWithAnIpSanOnly()
    {
        ParsedCsr csr = Test.Parse(
            CsrFactory.CreateRsa(subject: string.Empty, ipAddresses: ["10.1.2.3"]));

        CsrPolicy.Evaluate(csr, Defaults()).ShouldBeNull();
    }

    [Fact]
    public void Evaluate_AllowsAnAnonymousCsrWhenTheIdentityRequirementIsTurnedOff()
    {
        ParsedCsr csr = Test.Parse(CsrFactory.CreateRsa(subject: string.Empty));

        CsrPolicy.Evaluate(csr, Defaults(o => o.RequireSubjectOrSan = false)).ShouldBeNull();
    }

    [Fact]
    public void Evaluate_AppliesTheIdentityRuleToEcCsrsToo()
    {
        ParsedCsr csr = Test.Parse(CsrFactory.CreateEcdsa(subject: string.Empty));

        IssuanceResult.Rejected? rejection = CsrPolicy.Evaluate(
            csr, Defaults(o => o.AllowedEllipticCurves = [Pkcs10CsrReader.GetCurveName(csr)!]));

        rejection.ShouldNotBeNull();
        rejection.Reason.ShouldContain("identify nobody");
    }

    // ------------------------------------------------------------------ argument guards

    [Fact]
    public void Evaluate_ThrowsForNullArguments()
    {
        ParsedCsr csr = Test.Parse(CsrFactory.CreateRsa());

        Should.Throw<ArgumentNullException>(() => CsrPolicy.Evaluate(null!, Defaults()));
        Should.Throw<ArgumentNullException>(() => CsrPolicy.Evaluate(csr, null!));
    }
}
