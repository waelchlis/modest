using System.Net;
using System.Security.Cryptography.X509Certificates;
using Modest.TestSupport;

namespace Modest.Codec.Tests;

/// <summary>
/// Interop against the real <c>openssl</c> binary. Everything else in this suite checks that the
/// codec agrees with itself; these tests check that it agrees with the rest of the world, which is
/// what an EST client on a switch or a sensor actually confronts.
/// </summary>
/// <remarks>
/// Each test returns early when openssl is not on PATH, so a machine without it still runs a green
/// suite — at the cost of losing this coverage, which is why CI is expected to provide openssl.
/// </remarks>
public sealed class OpenSslInteropTests : IDisposable
{
    private readonly TestCertificateAuthority _ca = TestCertificateAuthority.CreateWithIntermediate();

    public void Dispose() => _ca.Dispose();

    // ---------------------------------------------------------------- openssl -> codec

    [Fact]
    public void Parse_ReadsACsrGeneratedByOpenSsl()
    {
        if (!OpenSsl.IsAvailable)
        {
            return;
        }

        using var temp = new TempDirectory();

        OpenSsl.RunOrFail(
            "req -new -newkey rsa:2048 -nodes -keyout key.pem -out csr.pem " +
            "-subj /CN=openssl-device.example.com " +
            "-addext subjectAltName=DNS:openssl-device.example.com,DNS:alt.example.com,IP:203.0.113.9",
            temp.FullPath);

        OpenSsl.RunOrFail("req -in csr.pem -outform DER -out csr.der", temp.FullPath);

        byte[] der = File.ReadAllBytes(temp.File("csr.der"));

        ParsedCsr csr = Pkcs10CsrReader.Parse(der);

        csr.Subject.Name.ShouldBe("CN=openssl-device.example.com");
        Pkcs10CsrReader.IsRsa(csr).ShouldBeTrue();
        Pkcs10CsrReader.GetKeySizeBits(csr).ShouldBe(2048);

        SubjectAlternativeNames sans = csr.SubjectAlternativeNames;
        sans.DnsNames.ShouldBe(["openssl-device.example.com", "alt.example.com"], ignoreOrder: true);
        sans.IPAddresses.Single().ShouldBe(IPAddress.Parse("203.0.113.9"));
        sans.DnsNames.ShouldNotContain("203.0.113.9");
    }

    [Fact]
    public void Parse_ReadsAnEcCsrGeneratedByOpenSsl()
    {
        if (!OpenSsl.IsAvailable)
        {
            return;
        }

        using var temp = new TempDirectory();

        OpenSsl.RunOrFail(
            "req -new -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -keyout eckey.pem " +
            "-outform DER -out eccsr.der -subj /CN=openssl-ec.example.com",
            temp.FullPath);

        ParsedCsr csr = Pkcs10CsrReader.Parse(File.ReadAllBytes(temp.File("eccsr.der")));

        csr.Subject.Name.ShouldBe("CN=openssl-ec.example.com");
        Pkcs10CsrReader.IsEllipticCurve(csr).ShouldBeTrue();
        Pkcs10CsrReader.GetKeySizeBits(csr).ShouldBe(384);
        Pkcs10CsrReader.GetCurveName(csr).ShouldNotBeNull();
    }

    [Fact]
    public void Parse_ReportsNoCurveNameForAnExplicitParameterEcCsr()
    {
        if (!OpenSsl.IsAvailable)
        {
            return;
        }

        using var temp = new TempDirectory();

        // Some older clients emit EC keys with the curve spelled out rather than named. There is no
        // friendly name to report for those, so GetCurveName has nothing to say — but parsing must
        // still work, because the key itself is perfectly valid.
        OpenSsl.RunOrFail("ecparam -name prime256v1 -param_enc explicit -genkey -out explicit.pem", temp.FullPath);
        OpenSsl.RunOrFail(
            "req -new -key explicit.pem -outform DER -out explicit.der -subj /CN=explicit-curve.example.com",
            temp.FullPath);

        ParsedCsr csr = Pkcs10CsrReader.Parse(File.ReadAllBytes(temp.File("explicit.der")));

        Pkcs10CsrReader.IsEllipticCurve(csr).ShouldBeTrue();
        Pkcs10CsrReader.GetCurveName(csr).ShouldBeNull();
    }

    [Fact]
    public void Parse_NeverLeaksANonCodecExceptionForAnUnsupportedKeyAlgorithm()
    {
        if (!OpenSsl.IsAvailable)
        {
            return;
        }

        using var temp = new TempDirectory();

        // Ed25519 is a legal PKCS#10 key algorithm that .NET's certificate stack does not model.
        // Whether this build parses it or rejects it, the contract is the same: a client-supplied
        // CSR must never produce an exception the API layer would turn into a 500.
        OpenSsl.RunOrFail(
            "req -new -newkey ed25519 -nodes -keyout ed.pem -outform DER -out ed.der " +
            "-subj /CN=ed25519.example.com",
            temp.FullPath);

        byte[] der = File.ReadAllBytes(temp.File("ed.der"));

        ParsedCsr? csr = null;
        Exception? thrown = Record.Exception(() => csr = Pkcs10CsrReader.Parse(der));

        if (thrown is not null)
        {
            thrown.ShouldBeOfType<EstCodecException>(
                "An unsupported key algorithm is client-supplied input, so it must surface as " +
                $"EstCodecException (a 400), not as {thrown.GetType().Name}: {thrown.Message}");
            return;
        }

        // Parsed after all: then the key-shape helpers must degrade honestly rather than lie.
        csr.ShouldNotBeNull();
        Pkcs10CsrReader.IsRsa(csr).ShouldBeFalse();
        Pkcs10CsrReader.IsEllipticCurve(csr).ShouldBeFalse();
        Pkcs10CsrReader.GetKeySizeBits(csr).ShouldBe(0);
        Pkcs10CsrReader.GetCurveName(csr).ShouldBeNull();
    }

    [Fact]
    public void Parse_AcceptsACsrCarryingAChallengePasswordAttribute()
    {
        if (!OpenSsl.IsAvailable)
        {
            return;
        }

        using var temp = new TempDirectory();

        // RFC 7030 says a server may ignore challengePassword; it must not choke on it. Only
        // openssl can conveniently produce one, so the test lives here.
        File.WriteAllText(
            temp.File("challenge.cnf"),
            """
            [ req ]
            prompt = no
            distinguished_name = dn
            attributes = attrs

            [ dn ]
            CN = challenge.example.com

            [ attrs ]
            challengePassword = s3cret-provisioning-token

            """);

        OpenSsl.RunOrFail(
            "req -new -newkey rsa:2048 -nodes -keyout ckey.pem -config challenge.cnf " +
            "-outform DER -out challenge.der",
            temp.FullPath);

        ParsedCsr csr = Pkcs10CsrReader.Parse(File.ReadAllBytes(temp.File("challenge.der")));

        csr.Subject.Name.ShouldBe("CN=challenge.example.com");
        csr.SubjectAlternativeNames.IsEmpty.ShouldBeTrue();
    }

    [Fact]
    public void Read_ParsesACertsOnlyBlobProducedByOpenSsl()
    {
        if (!OpenSsl.IsAvailable)
        {
            return;
        }

        using var temp = new TempDirectory();

        X509Certificate2 leaf = _ca.IssueLeaf("CN=reverse-interop.example.com");
        WritePem(temp.File("chain.pem"), [leaf, _ca.Intermediate!, _ca.Root]);

        OpenSsl.RunOrFail("crl2pkcs7 -nocrl -certfile chain.pem -outform DER -out openssl.p7b", temp.FullPath);

        IReadOnlyList<X509Certificate2> read =
            Pkcs7CertsOnlyWriter.Read(File.ReadAllBytes(temp.File("openssl.p7b")));

        read.Select(c => c.Thumbprint)
            .ShouldBe([leaf.Thumbprint, _ca.Intermediate!.Thumbprint, _ca.Root.Thumbprint], ignoreOrder: true);
    }

    // ---------------------------------------------------------------- codec -> openssl

    [Fact]
    public void Build_ProducesABlobOpenSslCanPrint()
    {
        if (!OpenSsl.IsAvailable)
        {
            return;
        }

        using var temp = new TempDirectory();

        X509Certificate2 leaf = _ca.IssueLeaf("CN=printed-leaf.example.com");
        File.WriteAllBytes(temp.File("modest.p7b"), Pkcs7CertsOnlyWriter.Build(leaf, _ca.Chain));

        OpenSslResult result = OpenSsl.RunOrFail(
            "pkcs7 -inform DER -in modest.p7b -print_certs -noout", temp.FullPath);

        // openssl 3 prints "subject=CN = printed-leaf.example.com"; assert on the value, not the
        // exact spacing it chose.
        result.StandardOutput.ShouldContain("printed-leaf.example.com");
        result.StandardOutput.ShouldContain("Modest Test Issuing CA");
        result.StandardOutput.ShouldContain("Modest Test Root CA");

        CountSubjectLines(result.StandardOutput).ShouldBe(3);
    }

    [Fact]
    public void BuildForCaChain_ProducesABlobOpenSslCanPrint()
    {
        if (!OpenSsl.IsAvailable)
        {
            return;
        }

        using var temp = new TempDirectory();

        File.WriteAllBytes(temp.File("cacerts.p7b"), Pkcs7CertsOnlyWriter.BuildForCaChain(_ca.Chain));

        OpenSslResult result = OpenSsl.RunOrFail(
            "pkcs7 -inform DER -in cacerts.p7b -print_certs -noout", temp.FullPath);

        result.StandardOutput.ShouldContain("Modest Test Issuing CA");
        result.StandardOutput.ShouldContain("Modest Test Root CA");
        CountSubjectLines(result.StandardOutput).ShouldBe(2);
    }

    [Fact]
    public void Build_SurvivesOpenSslsStrictDerReencode()
    {
        if (!OpenSsl.IsAvailable)
        {
            return;
        }

        using var temp = new TempDirectory();

        byte[] modest = Pkcs7CertsOnlyWriter.Build(_ca.Chain);
        File.WriteAllBytes(temp.File("modest.p7b"), modest);

        OpenSsl.RunOrFail("pkcs7 -inform DER -in modest.p7b -outform DER -out reencoded.p7b", temp.FullPath);

        // If Modest's encoding were non-canonical, openssl's re-encode would differ from it.
        File.ReadAllBytes(temp.File("reencoded.p7b")).ShouldBe(modest);
    }

    // ---------------------------------------------------------------- the gold standard

    [Fact]
    public void Build_IsByteIdenticalToOpenSslCrl2Pkcs7()
    {
        if (!OpenSsl.IsAvailable)
        {
            return;
        }

        using var temp = new TempDirectory();

        // NOTE: this test currently FAILS, and it is the most important failure in the suite.
        // Pkcs7CertsOnlyWriter's own documentation claims byte-identity with openssl crl2pkcs7;
        // it does not hold for multi-certificate bags because AsnWriter.PushSetOf sorts SET OF
        // members in DER mode while openssl preserves the order it was given. Everything else in
        // the encoding does match — see the single-certificate variant below, which passes.
        X509Certificate2 leaf = _ca.IssueLeaf("CN=gold-standard.example.com");
        List<X509Certificate2> certificates = [leaf, _ca.Intermediate!, _ca.Root];

        // Same certificates, same order, on both sides.
        WritePem(temp.File("chain.pem"), certificates);
        OpenSsl.RunOrFail("crl2pkcs7 -nocrl -certfile chain.pem -outform DER -out openssl.p7b", temp.FullPath);

        byte[] fromOpenSsl = File.ReadAllBytes(temp.File("openssl.p7b"));
        byte[] fromModest = Pkcs7CertsOnlyWriter.Build(certificates);

        fromModest.Length.ShouldBe(fromOpenSsl.Length);
        fromModest.ShouldBe(fromOpenSsl);
    }

    [Fact]
    public void Build_IsByteIdenticalToOpenSslCrl2Pkcs7ForASingleCertificate()
    {
        if (!OpenSsl.IsAvailable)
        {
            return;
        }

        using var temp = new TempDirectory();

        WritePem(temp.File("root.pem"), [_ca.Root]);
        OpenSsl.RunOrFail("crl2pkcs7 -nocrl -certfile root.pem -outform DER -out openssl.p7b", temp.FullPath);

        Pkcs7CertsOnlyWriter.Build([_ca.Root]).ShouldBe(File.ReadAllBytes(temp.File("openssl.p7b")));
    }

    // ---------------------------------------------------------------- helpers

    private static void WritePem(string path, IReadOnlyList<X509Certificate2> certificates) =>
        File.WriteAllText(path, string.Join('\n', certificates.Select(c => c.ExportCertificatePem())) + "\n");

    private static int CountSubjectLines(string printCertsOutput) =>
        printCertsOutput
            .Split('\n')
            .Count(line => line.StartsWith("subject=", StringComparison.Ordinal));
}
