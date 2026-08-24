using System.Formats.Asn1;

namespace Modest.Codec.Tests;

/// <summary>
/// /csrattrs carries a DER <c>CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID</c>. The empty form
/// is two bytes and clients hard-code recognising it, so it is pinned literally.
/// </summary>
public sealed class CsrAttrsWriterTests
{
    [Fact]
    public void EmptySequence_IsExactlyThirtyZero()
    {
        byte[] der = CsrAttrsWriter.EmptySequence();

        der.ShouldBe(new byte[] { 0x30, 0x00 });
        der.Length.ShouldBe(2);
    }

    [Fact]
    public void EmptySequence_Base64EncodesToMAA()
    {
        Base64Wire.Encode(CsrAttrsWriter.EmptySequence()).ShouldBe("MAA=");
    }

    [Fact]
    public void EmptySequence_RoundTripsThroughTheWire()
    {
        string body = Base64Wire.Encode(CsrAttrsWriter.EmptySequence());

        Base64Wire.DecodeTolerant(body).ShouldBe(new byte[] { 0x30, 0x00 });
    }

    [Fact]
    public void EmptySequence_ParsesAsAnEmptySequence()
    {
        var reader = new AsnReader(CsrAttrsWriter.EmptySequence(), AsnEncodingRules.DER);

        reader.ReadSequence().HasData.ShouldBeFalse();
        reader.HasData.ShouldBeFalse();
    }

    [Fact]
    public void EmptySequence_ReturnsAFreshArrayEachTime()
    {
        // Callers hand this straight to a response writer; a shared mutable array would be a trap.
        CsrAttrsWriter.EmptySequence().ShouldNotBeSameAs(CsrAttrsWriter.EmptySequence());
    }

    [Fact]
    public void BuildFromOids_RoundTripsThroughAsnReader()
    {
        string[] oids =
        [
            "1.2.840.113549.1.9.7",   // challengePassword
            "1.2.840.10045.4.3.2",    // ecdsa-with-SHA256
            "1.2.840.113549.1.1.11",  // sha256WithRSAEncryption
        ];

        byte[] der = CsrAttrsWriter.BuildFromOids(oids);

        var reader = new AsnReader(der, AsnEncodingRules.DER);
        AsnReader sequence = reader.ReadSequence();
        reader.HasData.ShouldBeFalse();

        List<string> read = [];
        while (sequence.HasData)
        {
            read.Add(sequence.ReadObjectIdentifier());
        }

        read.ShouldBe(oids);
    }

    [Fact]
    public void BuildFromOids_WithNoOidsMatchesEmptySequence()
    {
        CsrAttrsWriter.BuildFromOids([]).ShouldBe(CsrAttrsWriter.EmptySequence());
    }

    [Fact]
    public void BuildFromOids_WithOneOidProducesAWellFormedSequence()
    {
        byte[] der = CsrAttrsWriter.BuildFromOids(["1.2.840.113549.1.9.7"]);

        der[0].ShouldBe((byte)0x30);
        der.Length.ShouldBe(der[1] + 2);

        var reader = new AsnReader(der, AsnEncodingRules.DER);
        reader.ReadSequence().ReadObjectIdentifier().ShouldBe("1.2.840.113549.1.9.7");
    }

    [Fact]
    public void BuildFromOids_RejectsNull()
    {
        Should.Throw<ArgumentNullException>(() => CsrAttrsWriter.BuildFromOids(null!));
    }
}
