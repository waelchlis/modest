using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Modest.Codec;
using Modest.TestSupport;

namespace Modest.Issuance.InternalCa.Tests;

/// <summary>
/// What the builder carries over from a CSR is the whole ballgame. A PKCS#10 request is an
/// untrusted wish list; anything honoured from it that policy did not choose is a privilege the
/// requester granted themselves.
/// </summary>
public sealed class CertificateBuilderTests : IDisposable
{
    private readonly TestCertificateAuthority _ca = TestCertificateAuthority.CreateWithIntermediate();

    private static InternalCaOptions Options(Action<InternalCaOptions>? configure = null)
    {
        var options = new InternalCaOptions { CertificatePath = "unused.pfx" };
        configure?.Invoke(options);
        return options;
    }

    private X509Certificate2 Build(byte[] csrDer, Action<InternalCaOptions>? configure = null) =>
        CertificateBuilder.Build(Test.Parse(csrDer), _ca.Issuer, Options(configure));

    public void Dispose() => _ca.Dispose();

    // ------------------------------------------------------------------ the critical one

    [Fact]
    public void Build_RefusesToHonourARequestForCaPrivileges()
    {
        // The CSR asks for basicConstraints CA:true, pathLen 3. Honouring it would hand the
        // requester a subordinate CA and with it the entire PKI.
        using X509Certificate2 issued = Build(CsrFactory.CreateRequestingCaPrivileges());

        X509BasicConstraintsExtension basicConstraints = Test.BasicConstraints(issued);

        basicConstraints.CertificateAuthority.ShouldBeFalse();
        basicConstraints.HasPathLengthConstraint.ShouldBeFalse();
        basicConstraints.Critical.ShouldBeTrue();
    }

    [Fact]
    public void Build_EmitsExactlyOneBasicConstraintsExtension()
    {
        // Two basicConstraints extensions would be a malformed certificate whose interpretation
        // depends on which one a given validator reads first.
        using X509Certificate2 issued = Build(CsrFactory.CreateRequestingCaPrivileges());

        issued.Extensions.Count(e => e.Oid?.Value == "2.5.29.19").ShouldBe(1);
    }

    [Fact]
    public void Build_MarksEveryIssuedCertificateAsAnEndEntity()
    {
        using X509Certificate2 issued = Build(CsrFactory.CreateRsa());

        Test.BasicConstraints(issued).CertificateAuthority.ShouldBeFalse();
    }

    // ------------------------------------------------------------------ requested extensions

    [Fact]
    public void Build_IgnoresARequestedExtendedKeyUsage()
    {
        // The CSR asks for serverAuth and OCSP signing; policy says clientAuth.
        byte[] der = CsrFactory.CreateRsa(extraExtensions:
        [
            new X509EnhancedKeyUsageExtension(
                [new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.9")], critical: false),
        ]);

        using X509Certificate2 issued = Build(der, o => o.EnhancedKeyUsageOids = ["1.3.6.1.5.5.7.3.2"]);

        string[] ekus = [.. Test.Eku(issued).EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value!)];

        ekus.ShouldBe(["1.3.6.1.5.5.7.3.2"]);
    }

    [Fact]
    public void Build_IgnoresARequestedKeyUsage()
    {
        // A CSR asking for keyCertSign + crlSign: the "please make me a CA" request in its other
        // form, since a validator that ignores basicConstraints may still honour keyUsage.
        byte[] der = CsrFactory.CreateRsa(extraExtensions:
        [
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true),
        ]);

        using X509Certificate2 issued = Build(der, o => o.KeyUsages = ["DigitalSignature"]);

        X509KeyUsageExtension keyUsage = Test.KeyUsage(issued);

        keyUsage.KeyUsages.ShouldBe(X509KeyUsageFlags.DigitalSignature);
        keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign).ShouldBeFalse();
        keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.CrlSign).ShouldBeFalse();
    }

    [Fact]
    public void Build_DropsAnExtensionItHasNeverHeardOf()
    {
        const string PrivateOid = "1.3.6.1.4.1.99999.1.1";
        byte[] der = CsrFactory.CreateRsa(extraExtensions:
        [
            new X509Extension(new Oid(PrivateOid), [0x04, 0x03, 0x01, 0x02, 0x03], critical: false),
        ]);

        // Sanity: the request really does carry it, so the assertion below means something.
        Test.Parse(der).RequestedExtensions.ShouldContain(e => e.Oid!.Value == PrivateOid);

        using X509Certificate2 issued = Build(der);

        issued.Extensions.ShouldNotContain(e => e.Oid!.Value == PrivateOid);
    }

    [Fact]
    public void Build_DropsARequestedNameConstraintsExtension()
    {
        // nameConstraints on a leaf is meaningless, but a copied one on a cert that also somehow
        // became a CA would let the holder pick which namespaces to mint.
        byte[] der = CsrFactory.CreateRsa(extraExtensions:
        [
            new X509Extension(new Oid("2.5.29.30"), [0x30, 0x00], critical: true),
        ]);

        using X509Certificate2 issued = Build(der);

        issued.Extensions.ShouldNotContain(e => e.Oid!.Value == "2.5.29.30");
    }

    [Fact]
    public void Build_PutsOnlyThePolicyChosenExtensionsOnTheCertificate()
    {
        byte[] der = CsrFactory.CreateRsa(dnsNames: ["device01.example.com"]);

        using X509Certificate2 issued = Build(der);

        string[] oids = [.. issued.Extensions.Select(e => e.Oid!.Value!).Order(StringComparer.Ordinal)];

        string[] permitted =
        [
            "2.5.29.14", // subjectKeyIdentifier
            "2.5.29.15", // keyUsage
            "2.5.29.17", // subjectAltName
            "2.5.29.19", // basicConstraints
            "2.5.29.35", // authorityKeyIdentifier
            "2.5.29.37", // extendedKeyUsage
        ];

        oids.ShouldAllBe(
            oid => permitted.Contains(oid, StringComparer.Ordinal),
            "Unexpected extension set: " + string.Join(", ", oids));

        oids.ShouldContain("2.5.29.19");
        oids.ShouldContain("2.5.29.15");
        oids.ShouldContain("2.5.29.37");
        oids.ShouldContain("2.5.29.14");
        oids.ShouldContain("2.5.29.17");
    }

    // ------------------------------------------------------------------ policy extensions

    [Fact]
    public void Build_TakesKeyUsageFromConfiguration()
    {
        using X509Certificate2 issued = Build(
            CsrFactory.CreateRsa(), o => o.KeyUsages = ["DigitalSignature", "KeyEncipherment"]);

        X509KeyUsageExtension keyUsage = Test.KeyUsage(issued);

        keyUsage.KeyUsages.ShouldBe(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment);
        keyUsage.Critical.ShouldBeTrue();
    }

    [Fact]
    public void Build_TakesExtendedKeyUsageFromConfiguration()
    {
        using X509Certificate2 issued = Build(
            CsrFactory.CreateRsa(),
            o => o.EnhancedKeyUsageOids = ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"]);

        string[] ekus = [.. Test.Eku(issued).EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value!)];

        ekus.ShouldBe(["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"], ignoreOrder: true);
    }

    [Fact]
    public void Build_OmitsKeyUsageWhenNoneIsConfigured()
    {
        using X509Certificate2 issued = Build(CsrFactory.CreateRsa(), o => o.KeyUsages = []);

        Test.Extension(issued, "2.5.29.15").ShouldBeNull();
    }

    [Fact]
    public void Build_OmitsExtendedKeyUsageWhenNoneIsConfigured()
    {
        using X509Certificate2 issued = Build(CsrFactory.CreateRsa(), o => o.EnhancedKeyUsageOids = []);

        Test.Extension(issued, "2.5.29.37").ShouldBeNull();
    }

    [Fact]
    public void Build_RefusesToIssueACertificateThatCouldSignCertificates()
    {
        // Provisioning keyCertSign on an end-entity certificate is the same compromise as
        // basicConstraints CA:true, arrived at by way of a config file instead of a CSR.
        ArgumentOutOfRangeException ex = Should.Throw<ArgumentOutOfRangeException>(
            () => Build(CsrFactory.CreateRsa(), o => o.KeyUsages = ["DigitalSignature", "KeyCertSign"]));

        ex.Message.ShouldContain("keyCertSign");
    }

    [Theory]
    [InlineData("keycertsign")]
    [InlineData("KEYCERTSIGN")]
    [InlineData("Key_Cert_Sign")]
    public void Build_RefusesKeyCertSignHoweverItIsSpelled(string spelling)
    {
        Should.Throw<ArgumentOutOfRangeException>(
            () => Build(CsrFactory.CreateRsa(), o => o.KeyUsages = [spelling]));
    }

    [Fact]
    public void Build_RefusesAnUnrecognisedKeyUsage()
    {
        Should.Throw<ArgumentOutOfRangeException>(
            () => Build(CsrFactory.CreateRsa(), o => o.KeyUsages = ["MakeMeAdmin"]));
    }

    [Fact]
    public void Build_AddsASubjectKeyIdentifierDerivedFromTheSubjectPublicKey()
    {
        using X509Certificate2 issued = Build(CsrFactory.CreateRsa());

        X509Extension? raw = Test.Extension(issued, "2.5.29.14");
        raw.ShouldNotBeNull();

        var ski = new X509SubjectKeyIdentifierExtension(new AsnEncodedData(raw!.RawData), raw.Critical);

        ski.SubjectKeyIdentifier.ShouldNotBeNullOrEmpty();
        ski.Critical.ShouldBeFalse();

        var expected = new X509SubjectKeyIdentifierExtension(issued.PublicKey, false);
        ski.SubjectKeyIdentifier.ShouldBe(expected.SubjectKeyIdentifier);
    }

    [Fact]
    public void Build_AddsAnAuthorityKeyIdentifierPointingAtTheSigningCa()
    {
        // Epic 3 lists AKI among the extensions the issuer sets, and RFC 5280 s4.2.1.1 requires it
        // on every certificate issued by a conforming CA. Without it a relying party has only the
        // issuer DN to go on, which breaks chain building across a CA key rollover where two CA
        // certificates share a subject.
        using X509Certificate2 issued = Build(CsrFactory.CreateRsa());

        X509Extension? raw = Test.Extension(issued, "2.5.29.35");
        raw.ShouldNotBeNull("The issued certificate carries no authorityKeyIdentifier extension.");

        var aki = new X509AuthorityKeyIdentifierExtension(raw!.RawData, raw.Critical);

        X509Extension? caSki = Test.Extension(_ca.Issuer, "2.5.29.14");
        caSki.ShouldNotBeNull();
        var expected = new X509SubjectKeyIdentifierExtension(new AsnEncodedData(caSki!.RawData), caSki.Critical);

        aki.KeyIdentifier.ShouldNotBeNull();
        Convert.ToHexString(aki.KeyIdentifier!.Value.Span).ShouldBe(expected.SubjectKeyIdentifier);
    }

    // ------------------------------------------------------------------ identity

    [Fact]
    public void Build_CopiesTheSubjectFromTheCsrByteForByte()
    {
        byte[] der = CsrFactory.CreateRsa("CN=device01.example.com, O=Contoso, C=CH");
        ParsedCsr csr = Test.Parse(der);

        using X509Certificate2 issued = CertificateBuilder.Build(csr, _ca.Issuer, Options());

        issued.SubjectName.RawData.ShouldBe(csr.Subject.RawData);
    }

    [Fact]
    public void Build_SetsTheIssuerToTheSigningCasSubject()
    {
        using X509Certificate2 issued = Build(CsrFactory.CreateRsa());

        issued.IssuerName.RawData.ShouldBe(_ca.Issuer.SubjectName.RawData);
        issued.Issuer.ShouldBe(_ca.Issuer.Subject);
    }

    [Fact]
    public void Build_CertifiesThePublicKeyFromTheCsrAndNoOther()
    {
        byte[] der = CsrFactory.CreateRsa();
        ParsedCsr csr = Test.Parse(der);

        using X509Certificate2 issued = CertificateBuilder.Build(csr, _ca.Issuer, Options());

        issued.PublicKey.ExportSubjectPublicKeyInfo()
            .ShouldBe(csr.PublicKey.ExportSubjectPublicKeyInfo());
    }

    [Fact]
    public void Build_CopiesDnsAndIpSansWithTheirTypesIntact()
    {
        byte[] der = CsrFactory.CreateRsa(
            dnsNames: ["device01.example.com", "alt.example.com"],
            ipAddresses: ["10.1.2.3", "2001:db8::42"]);

        using X509Certificate2 issued = Build(der, o => o.CopySubjectAlternativeNames = true);

        X509SubjectAlternativeNameExtension san = Test.San(issued);

        san.EnumerateDnsNames().ShouldBe(["device01.example.com", "alt.example.com"], ignoreOrder: true);
        san.EnumerateIPAddresses().Select(ip => ip.ToString())
            .ShouldBe(["10.1.2.3", "2001:db8::42"], ignoreOrder: true);

        // A DNS name must not arrive as an IP entry or vice versa: the two are different identities.
        san.EnumerateDnsNames().ShouldNotContain("10.1.2.3");
    }

    [Fact]
    public void Build_CopiesEmailSans()
    {
        byte[] der = CsrFactory.CreateRsa(emailAddresses: ["device01@example.com"]);

        using X509Certificate2 issued = Build(der);

        // rfc822Name is an IA5String, so its bytes appear verbatim inside the encoded extension.
        System.Text.Encoding.ASCII.GetString(Test.San(issued).RawData)
            .ShouldContain("device01@example.com");
    }

    [Fact]
    public void Build_OmitsSansEntirelyWhenCopyingIsTurnedOff()
    {
        byte[] der = CsrFactory.CreateRsa(
            dnsNames: ["device01.example.com"], ipAddresses: ["10.1.2.3"]);

        using X509Certificate2 issued = Build(der, o => o.CopySubjectAlternativeNames = false);

        Test.Extension(issued, "2.5.29.17")
            .ShouldBeNull("SANs were copied even though CopySubjectAlternativeNames is false.");
    }

    [Fact]
    public void Build_OmitsTheSanExtensionWhenTheCsrRequestsNone()
    {
        using X509Certificate2 issued = Build(CsrFactory.CreateRsa());

        Test.Extension(issued, "2.5.29.17").ShouldBeNull();
    }

    // ------------------------------------------------------------------ validity window

    [Fact]
    public void Build_BackdatesNotBeforeByTheConfiguredSkewAllowance()
    {
        DateTimeOffset before = DateTimeOffset.UtcNow;

        using X509Certificate2 issued = Build(
            CsrFactory.CreateRsa(), o => o.BackdateBy = TimeSpan.FromMinutes(17));

        DateTimeOffset notBefore = issued.NotBefore.ToUniversalTime();

        notBefore.ShouldBeInRange(
            before - TimeSpan.FromMinutes(17) - TimeSpan.FromSeconds(30),
            before - TimeSpan.FromMinutes(17) + TimeSpan.FromSeconds(30));
    }

    [Fact]
    public void Build_SetsNotAfterFromTheConfiguredValidityPeriod()
    {
        DateTimeOffset before = DateTimeOffset.UtcNow;

        using X509Certificate2 issued = Build(
            CsrFactory.CreateRsa(), o => o.ValidityPeriod = TimeSpan.FromDays(30));

        DateTimeOffset notAfter = issued.NotAfter.ToUniversalTime();

        notAfter.ShouldBeInRange(
            before + TimeSpan.FromDays(30) - TimeSpan.FromSeconds(30),
            before + TimeSpan.FromDays(30) + TimeSpan.FromSeconds(30));
    }

    [Fact]
    public void Build_ProducesAValidityWindowThatIsNotInverted()
    {
        using X509Certificate2 issued = Build(CsrFactory.CreateRsa());

        issued.NotBefore.ShouldBeLessThan(issued.NotAfter);
    }

    [Fact]
    public void Build_NeverIssuesALeafThatOutlivesTheSigningCa()
    {
        // A leaf valid past its issuer's own notAfter is unverifiable for the tail of its life:
        // every chain build after the CA expires fails, however healthy the leaf looks. A CA has
        // to clamp the requested lifetime to its own.
        using X509Certificate2 issued = Build(
            CsrFactory.CreateRsa(), o => o.ValidityPeriod = TimeSpan.FromDays(3650));

        issued.NotAfter.ToUniversalTime()
            .ShouldBeLessThanOrEqualTo(
                _ca.Issuer.NotAfter.ToUniversalTime(),
                "The issued certificate outlives the CA that signed it.");
    }

    // ------------------------------------------------------------------ algorithms

    [Fact]
    public void Build_SignsAnEcdsaCsrWithTheRsaCaKey()
    {
        using X509Certificate2 issued = Build(CsrFactory.CreateEcdsa(curveName: "nistP384"));

        // Leaf key is EC ...
        issued.PublicKey.Oid.Value.ShouldBe("1.2.840.10045.2.1");
        using ECDsa? leafKey = issued.GetECDsaPublicKey();
        leafKey.ShouldNotBeNull();
        leafKey.KeySize.ShouldBe(384);
        issued.GetRSAPublicKey().ShouldBeNull();

        // ... while the signature over it is the CA's RSA one (sha256WithRSAEncryption).
        issued.SignatureAlgorithm.Value.ShouldBe("1.2.840.113549.1.1.11");
    }

    [Theory]
    [InlineData("SHA256", "1.2.840.113549.1.1.11")]
    [InlineData("sha-256", "1.2.840.113549.1.1.11")]
    [InlineData("SHA384", "1.2.840.113549.1.1.12")]
    [InlineData("SHA512", "1.2.840.113549.1.1.13")]
    public void Build_UsesTheConfiguredSignatureHash(string configured, string expectedOid)
    {
        using X509Certificate2 issued = Build(
            CsrFactory.CreateRsa(), o => o.SignatureAlgorithm = configured);

        issued.SignatureAlgorithm.Value.ShouldBe(expectedOid);
    }

    [Theory]
    [InlineData("SHA1")]
    [InlineData("MD5")]
    [InlineData("")]
    public void Build_RefusesAWeakOrUnknownSignatureHash(string configured)
    {
        Should.Throw<ArgumentOutOfRangeException>(
            () => Build(CsrFactory.CreateRsa(), o => o.SignatureAlgorithm = configured));
    }

    [Fact]
    public void Build_ThrowsForNullArguments()
    {
        ParsedCsr csr = Test.Parse(CsrFactory.CreateRsa());

        Should.Throw<ArgumentNullException>(() => CertificateBuilder.Build(null!, _ca.Issuer, Options()));
        Should.Throw<ArgumentNullException>(() => CertificateBuilder.Build(csr, null!, Options()));
        Should.Throw<ArgumentNullException>(() => CertificateBuilder.Build(csr, _ca.Issuer, null!));
    }

    // ------------------------------------------------------------------ chaining

    [Fact]
    public void Build_ProducesACertificateThatChainsToTheTestRoot()
    {
        using X509Certificate2 issued = Build(CsrFactory.CreateRsa(dnsNames: ["device01.example.com"]));

        (bool built, string status) = Test.BuildChain(issued, _ca);

        built.ShouldBeTrue("Chain build failed: " + status);
    }

    [Fact]
    public void Build_ProducesAnEcCertificateThatChainsToTheTestRoot()
    {
        using X509Certificate2 issued = Build(CsrFactory.CreateEcdsa());

        (bool built, string status) = Test.BuildChain(issued, _ca);

        built.ShouldBeTrue("Chain build failed: " + status);
    }

    [Fact]
    public void Build_ProducesASignatureThatDoesNotVerifyUnderAForeignRoot()
    {
        // Negative control for the chaining tests above: they would pass trivially if the chain
        // builder were accepting anything.
        using var otherCa = TestCertificateAuthority.CreateWithIntermediate(
            "CN=Some Other Root", "CN=Some Other Issuing CA");
        using X509Certificate2 issued = Build(CsrFactory.CreateRsa());

        (bool built, _) = Test.BuildChain(issued, otherCa);

        built.ShouldBeFalse();
    }

    // ------------------------------------------------------------------ serial numbers

    [Fact]
    public void GenerateSerialNumber_IsTwentyPositiveBytesWithNoLeadingZero()
    {
        for (int i = 0; i < 1000; i++)
        {
            byte[] serial = CertificateBuilder.GenerateSerialNumber();

            serial.Length.ShouldBe(20);
            (serial[0] & 0x80).ShouldBe(0, "RFC 5280 requires a positive serial.");
            serial[0].ShouldNotBe((byte)0, "A leading zero byte is stripped as redundant DER padding.");
        }
    }

    [Fact]
    public void GenerateSerialNumber_DoesNotRepeat()
    {
        HashSet<string> seen = [];

        for (int i = 0; i < 5000; i++)
        {
            seen.Add(Convert.ToHexString(CertificateBuilder.GenerateSerialNumber())).ShouldBeTrue();
        }
    }

    [Fact]
    public void Build_GivesEveryCertificateADistinctTwentyByteSerial()
    {
        ParsedCsr csr = Test.Parse(CsrFactory.CreateRsa());
        InternalCaOptions options = Options();
        HashSet<string> serials = [];
        var certificates = new List<X509Certificate2>();

        try
        {
            for (int i = 0; i < 100; i++)
            {
                X509Certificate2 issued = CertificateBuilder.Build(csr, _ca.Issuer, options);
                certificates.Add(issued);

                string serial = issued.SerialNumber;

                serial.Length.ShouldBe(40, $"Serial '{serial}' is not 20 bytes.");
                serials.Add(serial).ShouldBeTrue($"Serial '{serial}' was issued twice.");

                byte[] bytes = Convert.FromHexString(serial);
                bytes.Length.ShouldBe(20);
                (bytes[0] & 0x80).ShouldBe(0, "Serial must be a positive integer.");
            }

            // A counter dressed up as a random number would still be distinct, so check that the
            // values are not consecutive: sequential serials leak issuance volume and ordering.
            string[] ordered = [.. serials.Order(StringComparer.Ordinal)];
            int adjacent = 0;
            for (int i = 1; i < ordered.Length; i++)
            {
                var previous = System.Numerics.BigInteger.Parse(
                    "0" + ordered[i - 1], System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);
                var current = System.Numerics.BigInteger.Parse(
                    "0" + ordered[i], System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);

                if (current - previous == 1)
                {
                    adjacent++;
                }
            }

            adjacent.ShouldBe(0, "Serials look sequential.");
        }
        finally
        {
            foreach (X509Certificate2 certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }

    [Fact]
    public void Build_DoesNotReuseTheCasOwnSerial()
    {
        using X509Certificate2 issued = Build(CsrFactory.CreateRsa());

        issued.SerialNumber.ShouldNotBe(_ca.Issuer.SerialNumber);
    }

    // ------------------------------------------------------------------ hostile SAN content

    [Fact]
    public void Build_HandlesASanUriThatIsNotAValidUri()
    {
        // A client controls every byte of the SAN extension. An IA5String that is not a parseable
        // absolute URI must be a rejection, not an unhandled exception on the signing path.
        byte[] der = CsrFactory.CreateRsa(extraExtensions: [Test.MalformedUriSan()]);
        ParsedCsr csr = Test.Parse(der);

        csr.SubjectAlternativeNames.Uris.ShouldContain("this is not a uri");

        Exception? thrown = Record.Exception(() => CertificateBuilder.Build(csr, _ca.Issuer, Options()));

        // Whatever the outcome, it must be an exception type the issuer knows how to turn into a
        // clean rejection: ArgumentException or CryptographicException. A UriFormatException
        // escapes InternalCaIssuer.IssueAsync and becomes a 500.
        if (thrown is not null)
        {
            thrown.ShouldSatisfyAllConditions(
                () => thrown.ShouldNotBeOfType<UriFormatException>(),
                () => (thrown is ArgumentException or CryptographicException).ShouldBeTrue(
                    $"Unexpected exception type {thrown.GetType().Name}: {thrown.Message}"));
        }
    }

    [Fact]
    public void Build_HandlesAnEmptyDnsSanWithoutCrashing()
    {
        byte[] der = CsrFactory.CreateRsa(extraExtensions:
        [
            new X509Extension(new Oid("2.5.29.17"), [0x30, 0x02, 0x82, 0x00], critical: false),
        ]);

        Exception? thrown = Record.Exception(() =>
        {
            ParsedCsr csr = Test.Parse(der);
            CertificateBuilder.Build(csr, _ca.Issuer, Options()).Dispose();
        });

        if (thrown is not null)
        {
            (thrown is ArgumentException or CryptographicException or EstCodecException).ShouldBeTrue(
                $"Unexpected exception type {thrown.GetType().Name}: {thrown.Message}");
        }
    }
}
