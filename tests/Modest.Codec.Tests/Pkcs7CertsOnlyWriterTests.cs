using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using Modest.TestSupport;

namespace Modest.Codec.Tests;

/// <summary>
/// The certs-only PKCS#7 blob is what every EST client parses to obtain its trust anchors and its
/// issued certificate, so both its structure (degenerate SignedData: no signers, no content) and
/// the certificates it carries have to be exactly right.
/// </summary>
public sealed class Pkcs7CertsOnlyWriterTests : IDisposable
{
    private const string IdSignedData = "1.2.840.113549.1.7.2";
    private const string IdData = "1.2.840.113549.1.7.1";

    private readonly TestCertificateAuthority _ca = TestCertificateAuthority.CreateWithIntermediate();

    public void Dispose() => _ca.Dispose();

    // ---------------------------------------------------------------- round trip

    [Fact]
    public void BuildThenRead_RoundTripsASingleCertificate()
    {
        byte[] der = Pkcs7CertsOnlyWriter.Build([_ca.Root]);

        IReadOnlyList<X509Certificate2> read = Pkcs7CertsOnlyWriter.Read(der);

        read.Count.ShouldBe(1);
        read[0].Thumbprint.ShouldBe(_ca.Root.Thumbprint);
        read[0].RawData.ShouldBe(_ca.Root.RawData);
    }

    // NOTE: the four ordering tests below currently FAIL. Pkcs7CertsOnlyWriter.Build emits the
    // certificate bag through AsnWriter.PushSetOf, and AsnWriter in DER mode sorts SET OF members
    // by their encoding (X.690 s11.6). The supplied order is therefore discarded and replaced by
    // an order driven by certificate length and then by serial number — which, for random serials,
    // is arbitrary. openssl crl2pkcs7 does not sort, so this also breaks byte-identity with
    // openssl (see OpenSslInteropTests.Build_IsByteIdenticalToOpenSslCrl2Pkcs7). These tests assert
    // the intended behaviour, not the current behaviour.

    [Fact]
    public void BuildThenRead_RoundTripsTheCertificatesInTheExactOrderSupplied()
    {
        X509Certificate2 leaf = _ca.IssueLeaf("CN=order-leaf.example.com");
        List<X509Certificate2> supplied = [leaf, _ca.Intermediate!, _ca.Root];

        IReadOnlyList<X509Certificate2> read = Pkcs7CertsOnlyWriter.Read(Pkcs7CertsOnlyWriter.Build(supplied));

        read.Select(c => c.Thumbprint).ShouldBe(supplied.Select(c => c.Thumbprint));
    }

    [Fact]
    public void Build_PutsTheLeafFirst()
    {
        X509Certificate2 leaf = _ca.IssueLeaf("CN=leaf-first.example.com");

        byte[] der = Pkcs7CertsOnlyWriter.Build(leaf, _ca.Chain);

        IReadOnlyList<X509Certificate2> read = Pkcs7CertsOnlyWriter.Read(der);

        read.Count.ShouldBe(3);
        read[0].Thumbprint.ShouldBe(leaf.Thumbprint);
        read[1].Thumbprint.ShouldBe(_ca.Intermediate!.Thumbprint);
        read[2].Thumbprint.ShouldBe(_ca.Root.Thumbprint);
    }

    [Fact]
    public void Build_PreservesOrderAcrossAFourCertificateBag()
    {
        X509Certificate2 first = _ca.IssueLeaf("CN=one.example.com");
        X509Certificate2 second = _ca.IssueLeaf("CN=two.example.com");
        List<X509Certificate2> supplied = [first, second, _ca.Intermediate!, _ca.Root];

        IReadOnlyList<X509Certificate2> read = Pkcs7CertsOnlyWriter.Read(Pkcs7CertsOnlyWriter.Build(supplied));

        read.Select(c => c.Subject).ShouldBe(supplied.Select(c => c.Subject));
    }

    [Fact]
    public void Build_WithAnEmptyChainStillProducesAParseableStructure()
    {
        // Build (unlike BuildForCaChain) has no business rule against it; it must not crash.
        byte[] der = Pkcs7CertsOnlyWriter.Build([]);

        Pkcs7CertsOnlyWriter.Read(der).ShouldBeEmpty();
    }

    [Fact]
    public void BuildForCaChain_RoundTripsTheChain()
    {
        byte[] der = Pkcs7CertsOnlyWriter.BuildForCaChain(_ca.Chain);

        Pkcs7CertsOnlyWriter.Read(der)
            .Select(c => c.Thumbprint)
            .ShouldBe(_ca.Chain.Select(c => c.Thumbprint));
    }

    [Fact]
    public void BuildForCaChain_AndBuild_AgreeOnTheEncoding()
    {
        // The two entry points exist for readability at the call site, not because the bytes
        // differ; pin that so they cannot silently diverge.
        Pkcs7CertsOnlyWriter.BuildForCaChain(_ca.Chain).ShouldBe(Pkcs7CertsOnlyWriter.Build(_ca.Chain));
    }

    // ---------------------------------------------------------------- structure

    [Fact]
    public void Build_EmitsADegenerateSignedDataWithNoSignerAndNoContent()
    {
        byte[] der = Pkcs7CertsOnlyWriter.Build([_ca.Root]);

        var outer = new AsnReader(der, AsnEncodingRules.DER);
        AsnReader contentInfo = outer.ReadSequence();
        outer.HasData.ShouldBeFalse();

        contentInfo.ReadObjectIdentifier().ShouldBe(IdSignedData);

        AsnReader explicitContent = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        contentInfo.HasData.ShouldBeFalse();

        AsnReader signedData = explicitContent.ReadSequence();
        explicitContent.HasData.ShouldBeFalse();

        signedData.ReadInteger().ShouldBe(1);
        signedData.ReadSetOf().HasData.ShouldBeFalse();                 // digestAlgorithms: empty

        AsnReader encapContentInfo = signedData.ReadSequence();
        encapContentInfo.ReadObjectIdentifier().ShouldBe(IdData);
        encapContentInfo.HasData.ShouldBeFalse();                       // eContent absent, not an empty OCTET STRING

        AsnReader certificates = signedData.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 0));
        certificates.ReadEncodedValue().ToArray().ShouldBe(_ca.Root.RawData);
        certificates.HasData.ShouldBeFalse();

        signedData.ReadSetOf().HasData.ShouldBeFalse();                 // signerInfos: nobody signed
        signedData.HasData.ShouldBeFalse();
    }

    [Fact]
    public void Build_ProducesStrictDerThatReparsesUnderDerRules()
    {
        byte[] der = Pkcs7CertsOnlyWriter.Build(_ca.Chain);

        // BER would accept sloppier encodings; insisting on DER here is what embedded EST clients
        // with strict parsers effectively do.
        Should.NotThrow(() =>
        {
            var reader = new AsnReader(der, AsnEncodingRules.DER);
            reader.ReadSequence();
            reader.HasData.ShouldBeFalse();
        });
    }

    [Fact]
    public void Build_IsDeterministic()
    {
        Pkcs7CertsOnlyWriter.Build(_ca.Chain).ShouldBe(Pkcs7CertsOnlyWriter.Build(_ca.Chain));
    }

    // ---------------------------------------------------------------- guards

    [Fact]
    public void BuildForCaChain_RefusesAnEmptyChain()
    {
        InvalidOperationException ex = Should.Throw<InvalidOperationException>(
            () => Pkcs7CertsOnlyWriter.BuildForCaChain([]));

        ex.Message.ShouldContain("empty");
    }

    [Fact]
    public void NullArguments_AreRejected()
    {
        Should.Throw<ArgumentNullException>(() => Pkcs7CertsOnlyWriter.Build(null!, _ca.Chain));
        Should.Throw<ArgumentNullException>(() => Pkcs7CertsOnlyWriter.Build(_ca.Root, null!));
        Should.Throw<ArgumentNullException>(() => Pkcs7CertsOnlyWriter.Build(null!));
        Should.Throw<ArgumentNullException>(() => Pkcs7CertsOnlyWriter.BuildForCaChain(null!));
    }

    // ---------------------------------------------------------------- Read rejection

    [Fact]
    public void Read_RejectsAStructureThatIsNotSignedData()
    {
        // A well-formed ContentInfo, but carrying id-data instead of id-signedData.
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(IdData);
        }

        EstCodecException ex = Should.Throw<EstCodecException>(() => Pkcs7CertsOnlyWriter.Read(writer.Encode()));

        ex.Message.ShouldContain(IdData);
    }

    [Theory]
    [InlineData(new byte[] { })]
    [InlineData(new byte[] { 0x00 })]
    [InlineData(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF })]
    [InlineData(new byte[] { 0x30, 0x05, 0x01, 0x02, 0x03 })]
    [InlineData(new byte[] { 0x30, 0x82, 0x10, 0x00, 0x06, 0x01, 0x2A })]
    public void Read_RejectsGarbage(byte[] garbage)
    {
        Should.Throw<EstCodecException>(() => Pkcs7CertsOnlyWriter.Read(garbage));
    }

    [Fact]
    public void Read_RejectsATruncatedStructure()
    {
        byte[] der = Pkcs7CertsOnlyWriter.Build(_ca.Chain);

        Should.Throw<EstCodecException>(() => Pkcs7CertsOnlyWriter.Read(der.AsMemory(0, der.Length / 2)));
    }

    [Fact]
    public void Read_RejectsACertificateBagContainingRubbish()
    {
        // Structurally a signedData, but the "certificate" inside is not a certificate.
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(IdSignedData);
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            using (writer.PushSequence())
            {
                writer.WriteInteger(1);
                using (writer.PushSetOf())
                {
                }

                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(IdData);
                }

                using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    writer.WriteOctetString([1, 2, 3, 4]);
                }

                using (writer.PushSetOf())
                {
                }
            }
        }

        Should.Throw<EstCodecException>(() => Pkcs7CertsOnlyWriter.Read(writer.Encode()));
    }

    [Fact]
    public void Read_AcceptsAStructureWithNoCertificatesAtAll()
    {
        byte[] der = Pkcs7CertsOnlyWriter.Build([]);

        Pkcs7CertsOnlyWriter.Read(der).ShouldBeEmpty();
    }
}
