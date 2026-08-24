using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace Modest.Codec;

/// <summary>
/// Builds the "certs-only" PKCS#7 / CMS structure that RFC 7030 uses for both /cacerts and
/// successful enrollment responses.
/// </summary>
/// <remarks>
/// <para>
/// The payload is a degenerate CMS SignedData (RFC 5652 s5.1): no signers, no encapsulated
/// content, just a bag of certificates.
/// </para>
/// <para>
/// This is written directly with <see cref="AsnWriter"/> rather than through
/// <c>System.Security.Cryptography.Pkcs.SignedCms</c>, for two measured reasons. First,
/// <c>SignedCms.Encode()</c> throws "The CMS message is not signed" when no signer has been
/// added, so it cannot express this structure at all. Second,
/// <c>X509Certificate2Collection.Export(X509ContentType.Pkcs7)</c> does produce a usable blob but
/// emits an empty OCTET STRING for eContent, where the canonical form omits eContent entirely.
/// The bytes below are identical to what <c>openssl crl2pkcs7 -nocrl</c> emits, which matters for
/// the strict ASN.1 parsers found in embedded and network-device EST clients.
/// </para>
/// </remarks>
public static class Pkcs7CertsOnlyWriter
{
    private const string IdSignedData = "1.2.840.113549.1.7.2";
    private const string IdData = "1.2.840.113549.1.7.1";

    /// <summary>
    /// Builds the DER certs-only structure for an enrollment response: the issued leaf first,
    /// then its chain.
    /// </summary>
    public static byte[] Build(X509Certificate2 leaf, IReadOnlyList<X509Certificate2> chain)
    {
        ArgumentNullException.ThrowIfNull(leaf);
        ArgumentNullException.ThrowIfNull(chain);

        List<X509Certificate2> all = new(chain.Count + 1) { leaf };
        all.AddRange(chain);
        return Build(all);
    }

    /// <summary>
    /// Builds the DER certs-only structure for /cacerts.
    /// </summary>
    /// <remarks>
    /// Distinct entry point from <see cref="Build(X509Certificate2, IReadOnlyList{X509Certificate2})"/>
    /// even though the encoding is the same, so each call site reads as what it is.
    /// </remarks>
    public static byte[] BuildForCaChain(IReadOnlyList<X509Certificate2> chain)
    {
        ArgumentNullException.ThrowIfNull(chain);

        if (chain.Count == 0)
        {
            throw new InvalidOperationException(
                "Refusing to build an empty /cacerts response: a client bootstrapping trust would " +
                "have nothing to anchor to. Check the issuer's CA chain configuration.");
        }

        return Build(chain);
    }

    /// <summary>Builds the DER certs-only structure containing the given certificates, in order.</summary>
    public static byte[] Build(IReadOnlyList<X509Certificate2> certificates)
    {
        ArgumentNullException.ThrowIfNull(certificates);

        // BER, not DER, and the distinction matters for exactly one field.
        //
        // certificates is a SET OF, and strict DER requires SET OF members to be sorted by their
        // encoding. AsnWriter honours that: under AsnEncodingRules.DER it silently reorders the
        // certificates, so the issued leaf does not reliably come first.
        //
        // That breaks interop in both directions. OpenSSL — the de facto reference, and what most
        // EST clients embed — does not sort here, so a DER-sorted bag stops being byte-identical to
        // `openssl crl2pkcs7 -nocrl` output. And simple EST clients routinely take the first
        // certificate in an enrollment response as their own rather than matching on public key;
        // reordering hands them somebody else's certificate.
        //
        // Every other component below is a primitive or a SEQUENCE, where BER and DER encode
        // identically with AsnWriter's definite-length output. So this yields canonical DER bytes
        // throughout, with insertion order preserved in the one place DER would have destroyed it.
        var writer = new AsnWriter(AsnEncodingRules.BER);

        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(IdSignedData);

            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            using (writer.PushSequence())
            {
                // CMSVersion: 1, since there are no v1/v2 attribute certificates present.
                writer.WriteInteger(1);

                // digestAlgorithms: empty, nothing is digested.
                using (writer.PushSetOf())
                {
                }

                // encapContentInfo: id-data with eContent absent.
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(IdData);
                }

                // certificates [0] IMPLICIT — the entire point of the structure.
                using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    foreach (X509Certificate2 certificate in certificates)
                    {
                        writer.WriteEncodedValue(certificate.RawDataMemory.Span);
                    }
                }

                // signerInfos: empty, nobody signed.
                using (writer.PushSetOf())
                {
                }
            }
        }

        return writer.Encode();
    }

    /// <summary>
    /// Reads the certificates back out of a certs-only structure. Used by tests and by clients of
    /// this library that need to round-trip.
    /// </summary>
    /// <exception cref="EstCodecException">The input is not a certs-only SignedData.</exception>
    public static IReadOnlyList<X509Certificate2> Read(ReadOnlyMemory<byte> der)
    {
        try
        {
            var outer = new AsnReader(der, AsnEncodingRules.BER);
            AsnReader contentInfo = outer.ReadSequence();

            string contentType = contentInfo.ReadObjectIdentifier();
            if (contentType != IdSignedData)
            {
                throw new EstCodecException($"Expected a PKCS#7 signedData structure but found OID {contentType}.");
            }

            AsnReader explicitContent = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            AsnReader signedData = explicitContent.ReadSequence();

            signedData.ReadInteger();                                            // version
            signedData.ReadSetOf();                                              // digestAlgorithms
            signedData.ReadSequence();                                           // encapContentInfo

            List<X509Certificate2> certificates = [];

            if (signedData.HasData && signedData.PeekTag() is { TagClass: TagClass.ContextSpecific, TagValue: 0 })
            {
                AsnReader certs = signedData.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 0));
                while (certs.HasData)
                {
                    certificates.Add(X509CertificateLoader.LoadCertificate(certs.ReadEncodedValue().Span));
                }
            }

            return certificates;
        }
        catch (AsnContentException ex)
        {
            throw new EstCodecException("The PKCS#7 structure is not valid DER.", ex);
        }
        catch (System.Security.Cryptography.CryptographicException ex)
        {
            throw new EstCodecException("The PKCS#7 structure contains an unreadable certificate.", ex);
        }
    }
}
