using System.Formats.Asn1;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Modest.TestSupport;

namespace Modest.Codec.Tests;

/// <summary>
/// Pkcs10CsrReader is where proof-of-possession is enforced, so both halves matter: valid requests
/// must be parsed faithfully, and anything malformed or unsigned must fail as an
/// <see cref="EstCodecException"/> (the codec's 400-shaped failure) rather than as a raw BCL throw.
/// </summary>
public sealed class Pkcs10CsrReaderTests
{
    private const string BasicConstraintsOid = "2.5.29.19";
    private const string SubjectAltNameOid = "2.5.29.17";
    private const string RsaOid = "1.2.840.113549.1.1.1";
    private const string EcPublicKeyOid = "1.2.840.10045.2.1";

    // ---------------------------------------------------------------- RSA

    [Theory]
    [InlineData(2048)]
    [InlineData(3072)]
    public void Parse_ReadsRsaRequests(int keySizeBits)
    {
        byte[] der = CsrFactory.CreateRsa("CN=rsa.example.com", keySizeBits);

        ParsedCsr csr = Pkcs10CsrReader.Parse(der);

        csr.Subject.Name.ShouldBe("CN=rsa.example.com");
        csr.PublicKeyAlgorithmOid.ShouldBe(RsaOid);
        Pkcs10CsrReader.IsRsa(csr).ShouldBeTrue();
        Pkcs10CsrReader.IsEllipticCurve(csr).ShouldBeFalse();
        Pkcs10CsrReader.GetKeySizeBits(csr).ShouldBe(keySizeBits);
        Pkcs10CsrReader.GetCurveName(csr).ShouldBeNull();
    }

    // ---------------------------------------------------------------- ECDSA

    [Theory]
    [InlineData("nistP256", 256, "1.2.840.10045.3.1.7")]
    [InlineData("nistP384", 384, "1.3.132.0.34")]
    public void Parse_ReadsEcdsaRequests(string curveName, int expectedBits, string expectedCurveOid)
    {
        byte[] der = CsrFactory.CreateEcdsa("CN=ec.example.com", curveName);

        ParsedCsr csr = Pkcs10CsrReader.Parse(der);

        csr.Subject.Name.ShouldBe("CN=ec.example.com");
        csr.PublicKeyAlgorithmOid.ShouldBe(EcPublicKeyOid);
        Pkcs10CsrReader.IsEllipticCurve(csr).ShouldBeTrue();
        Pkcs10CsrReader.IsRsa(csr).ShouldBeFalse();
        Pkcs10CsrReader.GetKeySizeBits(csr).ShouldBe(expectedBits);

        string? reported = Pkcs10CsrReader.GetCurveName(csr);
        reported.ShouldNotBeNull();

        // The friendly name a platform reports for a named curve varies (nistP256 / ECDSA_P256 /
        // prime256v1 / the bare OID), so pin the identity of the curve rather than its spelling.
        ResolveCurveOid(reported).ShouldBe(expectedCurveOid);
    }

    // ---------------------------------------------------------------- SANs

    [Fact]
    public void Parse_KeepsDnsAndIpSubjectAlternativeNamesApart()
    {
        byte[] der = CsrFactory.CreateRsa(
            "CN=device01.example.com",
            dnsNames: ["device01.example.com", "alt.example.com"],
            ipAddresses: ["192.0.2.10", "2001:db8::1"]);

        ParsedCsr csr = Pkcs10CsrReader.Parse(der);
        SubjectAlternativeNames sans = csr.SubjectAlternativeNames;

        sans.IsEmpty.ShouldBeFalse();
        sans.DnsNames.ShouldBe(["device01.example.com", "alt.example.com"], ignoreOrder: true);
        sans.IPAddresses.Select(ip => ip.ToString())
            .ShouldBe(["192.0.2.10", "2001:db8::1"], ignoreOrder: true);

        // The security property: an IP SAN must never leak into the DNS bucket, or a policy engine
        // that allow-lists DNS names would be handed an address it never vetted.
        sans.DnsNames.ShouldNotContain("192.0.2.10");
        sans.DnsNames.ShouldNotContain("2001:db8::1");
        sans.EmailAddresses.ShouldBeEmpty();
    }

    [Fact]
    public void Parse_ExtractsEmailSubjectAlternativeNames()
    {
        byte[] der = CsrFactory.CreateRsa(
            "CN=user.example.com",
            emailAddresses: ["dev@example.com", "ops@example.com"]);

        SubjectAlternativeNames sans = Pkcs10CsrReader.Parse(der).SubjectAlternativeNames;

        sans.EmailAddresses.ShouldBe(["dev@example.com", "ops@example.com"], ignoreOrder: true);
        sans.DnsNames.ShouldBeEmpty();
        sans.IPAddresses.ShouldBeEmpty();
        sans.IsEmpty.ShouldBeFalse();
    }

    [Fact]
    public void Parse_ExtractsMixedSubjectAlternativeNameTypesTogether()
    {
        byte[] der = CsrFactory.CreateRsa(
            "CN=mixed.example.com",
            dnsNames: ["mixed.example.com"],
            ipAddresses: ["198.51.100.7"],
            emailAddresses: ["admin@example.com"]);

        SubjectAlternativeNames sans = Pkcs10CsrReader.Parse(der).SubjectAlternativeNames;

        sans.DnsNames.ShouldBe(["mixed.example.com"]);
        sans.IPAddresses.Single().ShouldBe(IPAddress.Parse("198.51.100.7"));
        sans.EmailAddresses.ShouldBe(["admin@example.com"]);
        sans.UserPrincipalNames.ShouldBeEmpty();
        sans.Uris.ShouldBeEmpty();
    }

    [Fact]
    public void Parse_ReportsAnEmptySanSetWhenTheRequestAsksForNone()
    {
        byte[] der = CsrFactory.CreateRsa("CN=nosans.example.com");

        ParsedCsr csr = Pkcs10CsrReader.Parse(der);

        csr.SubjectAlternativeNames.IsEmpty.ShouldBeTrue();
        csr.SubjectAlternativeNames.ShouldBeSameAs(SubjectAlternativeNames.Empty);
        csr.RequestedExtensions.Any(e => e.Oid?.Value == SubjectAltNameOid).ShouldBeFalse();
    }

    [Fact]
    public void Parse_ExtractsUriAndUserPrincipalNameSubjectAlternativeNames()
    {
        // The BCL surfaces only DNS and IP directly; URI and UPN come out of the codec's own
        // GeneralNames walk. Re-enrollment compares every name a certificate would assert, so a
        // silently dropped UPN would let an identity change through unnoticed.
        var builder = new SubjectAlternativeNameBuilder();
        builder.AddDnsName("both.example.com");
        builder.AddUri(new Uri("https://device.example.com/est"));
        builder.AddUserPrincipalName("device01@corp.example");

        byte[] der = CsrFactory.CreateRsa("CN=uri.example.com", extraExtensions: [builder.Build()]);

        SubjectAlternativeNames sans = Pkcs10CsrReader.Parse(der).SubjectAlternativeNames;

        sans.DnsNames.ShouldBe(["both.example.com"]);
        sans.Uris.ShouldBe(["https://device.example.com/est"]);
        sans.UserPrincipalNames.ShouldBe(["device01@corp.example"]);
        sans.EmailAddresses.ShouldBeEmpty();
        sans.IsEmpty.ShouldBeFalse();
    }

    [Fact]
    public void Parse_IgnoresSubjectAlternativeNameTypesItDoesNotModel()
    {
        // A registeredID SAN is legal and rare. The codec has no bucket for it; skipping it must
        // not disturb the names it does understand, and must not throw.
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteCharacterString(
                UniversalTagNumber.IA5String, "known.example.com", new Asn1Tag(TagClass.ContextSpecific, 2));
            writer.WriteObjectIdentifier("1.3.6.1.4.1.99999.1", new Asn1Tag(TagClass.ContextSpecific, 8));
            writer.WriteCharacterString(
                UniversalTagNumber.IA5String, "ops@example.com", new Asn1Tag(TagClass.ContextSpecific, 1));
        }

        byte[] der = CsrFactory.CreateRsa(
            "CN=registeredid.example.com",
            extraExtensions: [new X509Extension(new Oid(SubjectAltNameOid), writer.Encode(), critical: false)]);

        SubjectAlternativeNames sans = Pkcs10CsrReader.Parse(der).SubjectAlternativeNames;

        sans.DnsNames.ShouldBe(["known.example.com"]);
        sans.EmailAddresses.ShouldBe(["ops@example.com"]);
        sans.Uris.ShouldBeEmpty();
        sans.UserPrincipalNames.ShouldBeEmpty();
    }

    [Fact]
    public void Parse_IgnoresAnOtherNameThatIsNotAUserPrincipalName()
    {
        // otherName [0] with an OID the codec does not care about: skipped, not misfiled as a UPN.
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                writer.WriteObjectIdentifier("1.3.6.1.4.1.99999.2");
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, "not-a-upn");
                }
            }

            writer.WriteCharacterString(
                UniversalTagNumber.IA5String, "kept.example.com", new Asn1Tag(TagClass.ContextSpecific, 2));
        }

        byte[] der = CsrFactory.CreateRsa(
            "CN=othername.example.com",
            extraExtensions: [new X509Extension(new Oid(SubjectAltNameOid), writer.Encode(), critical: false)]);

        SubjectAlternativeNames sans = Pkcs10CsrReader.Parse(der).SubjectAlternativeNames;

        sans.UserPrincipalNames.ShouldBeEmpty();
        sans.DnsNames.ShouldBe(["kept.example.com"]);
    }

    [Fact]
    public void Parse_RejectsAMalformedSubjectAlternativeNameExtension()
    {
        // GeneralNames SEQUENCE announcing a five-byte dNSName but carrying one. This is
        // client-supplied garbage, so it must surface as EstCodecException (a 400), never as a raw
        // CryptographicException, which the API layer would report as a server fault.
        byte[] malformed = [0x30, 0x03, 0x82, 0x05, 0x41];

        byte[] der = CsrFactory.CreateRsa(
            "CN=malformed-san.example.com",
            extraExtensions: [new X509Extension(new Oid(SubjectAltNameOid), malformed, critical: false)]);

        Should.Throw<EstCodecException>(() => Pkcs10CsrReader.Parse(der));
    }

    // ---------------------------------------------------------------- raw bytes

    [Fact]
    public void Parse_ExposesTheSubmittedDerBytesVerbatim()
    {
        byte[] der = CsrFactory.CreateRsa("CN=verbatim.example.com", dnsNames: ["verbatim.example.com"]);

        ParsedCsr csr = Pkcs10CsrReader.Parse(der);

        csr.Der.ToArray().ShouldBe(der);

        // Stronger than value equality: the delegating issuer forwards these bytes to an upstream
        // CA untouched, so the reader must not have re-encoded or copied-and-normalised them.
        MemoryMarshal.TryGetArray(csr.Der, out ArraySegment<byte> segment).ShouldBeTrue();
        segment.Array.ShouldBeSameAs(der);
        segment.Offset.ShouldBe(0);
        segment.Count.ShouldBe(der.Length);
    }

    // ---------------------------------------------------------------- hostile requests

    [Fact]
    public void Parse_SurfacesARequestForCaPrivilegesInsteadOfDroppingIt()
    {
        byte[] der = CsrFactory.CreateRequestingCaPrivileges("CN=hostile.example.com");

        ParsedCsr csr = Pkcs10CsrReader.Parse(der);

        X509Extension requested = csr.RequestedExtensions
            .Where(e => e.Oid?.Value == BasicConstraintsOid)
            .ToList()
            .ShouldHaveSingleItem();

        var basicConstraints = new X509BasicConstraintsExtension(
            new AsnEncodedData(requested.RawData), requested.Critical);

        // The codec deliberately does NOT filter: silently dropping the request would hide a
        // privilege-escalation attempt from the issuer whose job it is to reject it.
        basicConstraints.CertificateAuthority.ShouldBeTrue();
        basicConstraints.HasPathLengthConstraint.ShouldBeTrue();
        basicConstraints.PathLengthConstraint.ShouldBe(3);
        requested.Critical.ShouldBeTrue();
    }

    // ---------------------------------------------------------------- rejection

    [Fact]
    public void Parse_RejectsATamperedSignature()
    {
        byte[] der = CsrFactory.CreateRsa("CN=tampered.example.com");
        byte[] tampered = CsrFactory.WithBrokenSignature(der);

        tampered.ShouldNotBe(der);
        Pkcs10CsrReader.Parse(der).ShouldNotBeNull(); // the untampered original does parse

        EstCodecException ex = Should.Throw<EstCodecException>(() => Pkcs10CsrReader.Parse(tampered));

        ex.Message.ShouldContain("signature");
    }

    [Fact]
    public void Parse_RejectsATamperedSignatureOnAnEcRequest()
    {
        byte[] tampered = CsrFactory.WithBrokenSignature(CsrFactory.CreateEcdsa("CN=ec-tampered.example.com"));

        Should.Throw<EstCodecException>(() => Pkcs10CsrReader.Parse(tampered));
    }

    [Fact]
    public void Parse_RejectsEmptyInput()
    {
        EstCodecException ex = Should.Throw<EstCodecException>(
            () => Pkcs10CsrReader.Parse(ReadOnlyMemory<byte>.Empty));

        ex.Message.ShouldContain("empty");
    }

    [Fact]
    public void Parse_RejectsTruncatedDer()
    {
        byte[] der = CsrFactory.CreateRsa("CN=truncated.example.com");

        Should.Throw<EstCodecException>(() => Pkcs10CsrReader.Parse(der.AsMemory(0, der.Length / 2)));
    }

    [Fact]
    public void Parse_RejectsDerWithTrailingGarbage()
    {
        byte[] der = CsrFactory.CreateRsa("CN=trailing.example.com");
        byte[] withTail = [.. der, 0xDE, 0xAD, 0xBE, 0xEF];

        Should.Throw<EstCodecException>(() => Pkcs10CsrReader.Parse(withTail));
    }

    [Theory]
    [InlineData(new byte[] { 0x00 })]
    [InlineData(new byte[] { 0x30, 0x00 })]
    [InlineData(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF })]
    [InlineData(new byte[] { 0x30, 0x82, 0xFF, 0xFF, 0x01, 0x02 })]
    public void Parse_RejectsGarbage(byte[] garbage)
    {
        Should.Throw<EstCodecException>(() => Pkcs10CsrReader.Parse(garbage));
    }

    [Fact]
    public void Parse_RejectsACertificateMasqueradingAsACsr()
    {
        using var ca = TestCertificateAuthority.CreateRootOnly();

        Should.Throw<EstCodecException>(() => Pkcs10CsrReader.Parse(ca.Root.RawData));
    }

    // ---------------------------------------------------------------- ParseBase64

    [Fact]
    public void ParseBase64_AcceptsWrappedBodyText()
    {
        byte[] der = CsrFactory.CreateRsa("CN=wrapped.example.com", dnsNames: ["wrapped.example.com"]);

        ParsedCsr csr = Pkcs10CsrReader.ParseBase64(Base64Wire.EncodeWrapped(der, 76));

        csr.Subject.Name.ShouldBe("CN=wrapped.example.com");
        csr.SubjectAlternativeNames.DnsNames.ShouldBe(["wrapped.example.com"]);
        csr.Der.ToArray().ShouldBe(der);
    }

    [Fact]
    public void ParseBase64_RejectsInvalidBase64AsACodecException()
    {
        Should.Throw<EstCodecException>(() => Pkcs10CsrReader.ParseBase64("!!!not base64!!!"));
    }

    [Fact]
    public void ParseBase64_RejectsAnEmptyBody()
    {
        Should.Throw<EstCodecException>(() => Pkcs10CsrReader.ParseBase64("   \r\n  "));
    }

    [Fact]
    public void ParseBase64_RejectsValidBase64ThatIsNotACsr()
    {
        Should.Throw<EstCodecException>(() => Pkcs10CsrReader.ParseBase64(Convert.ToBase64String("hello"u8)));
    }

    // ---------------------------------------------------------------- guards

    [Fact]
    public void KeyPredicates_RejectNull()
    {
        Should.Throw<ArgumentNullException>(() => Pkcs10CsrReader.IsRsa(null!));
        Should.Throw<ArgumentNullException>(() => Pkcs10CsrReader.IsEllipticCurve(null!));
        Should.Throw<ArgumentNullException>(() => Pkcs10CsrReader.GetKeySizeBits(null!));
        Should.Throw<ArgumentNullException>(() => Pkcs10CsrReader.GetCurveName(null!));
    }

    // ---------------------------------------------------------------- helpers

    /// <summary>
    /// Maps whatever curve name the platform reported back onto the curve's OID, so assertions can
    /// pin the curve identity without depending on a particular friendly-name spelling.
    /// </summary>
    private static string ResolveCurveOid(string reported)
    {
        if (reported.Length > 0 && char.IsAsciiDigit(reported[0]))
        {
            return reported; // already an OID
        }

        return reported.ToUpperInvariant() switch
        {
            "NISTP256" or "ECDSA_P256" or "SECP256R1" or "PRIME256V1" => "1.2.840.10045.3.1.7",
            "NISTP384" or "ECDSA_P384" or "SECP384R1" => "1.3.132.0.34",
            "NISTP521" or "ECDSA_P521" or "SECP521R1" => "1.3.132.0.35",
            _ => reported,
        };
    }
}
