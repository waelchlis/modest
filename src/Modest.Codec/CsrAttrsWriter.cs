using System.Formats.Asn1;

namespace Modest.Codec;

/// <summary>
/// Builds the /csrattrs response body (RFC 7030 s4.5).
/// </summary>
/// <remarks>
/// The response is a DER <c>CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID</c>, telling clients
/// which attributes or algorithms the CA wants to see in a CSR. v1 always answers "nothing in
/// particular", which the RFC permits. Populating it — for example to steer clients onto a
/// specific curve — is the natural extension point, and would build on
/// <see cref="BuildFromOids"/> below.
/// </remarks>
public static class CsrAttrsWriter
{
    /// <summary>
    /// The empty CsrAttrs sequence: the two bytes 0x30 0x00.
    /// </summary>
    /// <remarks>
    /// Modest answers /csrattrs with HTTP 204 rather than returning this body, but the encoding is
    /// kept here because it is the canonical "no requirements" payload and tests pin it.
    /// </remarks>
    public static byte[] EmptySequence()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
        }

        return writer.Encode();
    }

    /// <summary>
    /// Builds a CsrAttrs sequence carrying bare OIDs — the AttrOrOID "oid" choice.
    /// </summary>
    public static byte[] BuildFromOids(IReadOnlyList<string> oids)
    {
        ArgumentNullException.ThrowIfNull(oids);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            foreach (string oid in oids)
            {
                writer.WriteObjectIdentifier(oid);
            }
        }

        return writer.Encode();
    }
}
