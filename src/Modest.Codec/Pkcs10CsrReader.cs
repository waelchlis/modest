using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Modest.Codec;

/// <summary>
/// Parses PKCS#10 CertificationRequests (RFC 2986) arriving at /simpleenroll and /simplereenroll.
/// </summary>
/// <remarks>
/// This type is where RFC 7030's proof-of-possession is enforced. The CSR's signature is made
/// with the private key matching the public key inside it, so verifying it proves the requester
/// holds that key. <see cref="CertificateRequest.LoadSigningRequest(byte[], HashAlgorithmName, CertificateRequestLoadOptions, RSASignaturePadding)"/>
/// performs that verification while loading, so no issuer can accidentally skip the check.
/// </remarks>
public static class Pkcs10CsrReader
{
    private const string RsaOid = "1.2.840.113549.1.1.1";
    private const string EcPublicKeyOid = "1.2.840.10045.2.1";

    /// <summary>Decodes base64 EST body text and parses the CSR it carries.</summary>
    /// <exception cref="EstCodecException">The body is not valid base64, or not a valid CSR.</exception>
    public static ParsedCsr ParseBase64(string base64Body) =>
        Parse(Base64Wire.DecodeTolerant(base64Body));

    /// <summary>Parses DER-encoded PKCS#10 bytes and verifies the embedded signature.</summary>
    /// <exception cref="EstCodecException">
    /// The bytes are not a well-formed CertificationRequest, or the signature does not verify
    /// against the enclosed public key.
    /// </exception>
    public static ParsedCsr Parse(ReadOnlyMemory<byte> der)
    {
        if (der.IsEmpty)
        {
            throw new EstCodecException("The certificate signing request is empty.");
        }

        CertificateRequest request;
        try
        {
            // RSASignaturePadding.Pkcs1 tells the loader how to interpret an RSA signature; it is
            // ignored for EC keys. Passing it unconditionally keeps both key types on one path.
            request = CertificateRequest.LoadSigningRequest(
                der.ToArray(),
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
                RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException ex)
        {
            throw new EstCodecException(
                $"The certificate signing request could not be parsed or its signature did not verify: {ex.Message}",
                ex);
        }
        catch (AsnContentException ex)
        {
            throw new EstCodecException("The certificate signing request is not valid DER.", ex);
        }
        catch (NotSupportedException ex)
        {
            // A key algorithm this platform does not model — Ed25519 (1.3.101.112) is the one clients
            // actually send. That is still client-supplied input, so it belongs in the 400 family:
            // letting NotSupportedException escape would report the client's choice of key as a
            // server fault.
            throw new EstCodecException(
                $"The certificate signing request uses a key algorithm this server cannot process: {ex.Message}",
                ex);
        }

        IReadOnlyList<X509Extension> extensions = [.. request.CertificateExtensions];

        return new ParsedCsr(
            der,
            request.SubjectName,
            request.PublicKey,
            extensions,
            ExtractSans(extensions));
    }

    /// <summary>True when the CSR carries an RSA public key.</summary>
    public static bool IsRsa(ParsedCsr csr)
    {
        ArgumentNullException.ThrowIfNull(csr);
        return csr.PublicKeyAlgorithmOid == RsaOid;
    }

    /// <summary>True when the CSR carries an elliptic curve public key.</summary>
    public static bool IsEllipticCurve(ParsedCsr csr)
    {
        ArgumentNullException.ThrowIfNull(csr);
        return csr.PublicKeyAlgorithmOid == EcPublicKeyOid;
    }

    /// <summary>
    /// The key size in bits, for policy checks. Returns 0 for a key type this build cannot size.
    /// </summary>
    public static int GetKeySizeBits(ParsedCsr csr)
    {
        ArgumentNullException.ThrowIfNull(csr);

        try
        {
            if (IsRsa(csr))
            {
                using RSA? rsa = csr.PublicKey.GetRSAPublicKey();
                return rsa?.KeySize ?? 0;
            }

            if (IsEllipticCurve(csr))
            {
                using ECDsa? ecdsa = csr.PublicKey.GetECDsaPublicKey();
                return ecdsa?.KeySize ?? 0;
            }
        }
        catch (CryptographicException)
        {
            return 0;
        }

        return 0;
    }

    /// <summary>
    /// The named curve friendly name for an EC key (for example nistP256), or null.
    /// </summary>
    public static string? GetCurveName(ParsedCsr csr)
    {
        ArgumentNullException.ThrowIfNull(csr);

        if (!IsEllipticCurve(csr))
        {
            return null;
        }

        try
        {
            using ECDsa? ecdsa = csr.PublicKey.GetECDsaPublicKey();
            if (ecdsa is null)
            {
                return null;
            }

            ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: false);
            ECCurve curve = parameters.Curve;

            if (!curve.IsNamed)
            {
                return null;
            }

            // Canonicalise before returning. Oid.FriendlyName is platform-dependent — Linux reports
            // "ECDSA_P256" where Windows reports "nistP256" — and returning it raw would make any
            // policy comparison against it silently platform-specific.
            string? reported = curve.Oid.Value ?? curve.Oid.FriendlyName;
            return reported is null ? null : EllipticCurveNames.Canonicalise(reported);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    private static SubjectAlternativeNames ExtractSans(IReadOnlyList<X509Extension> extensions)
    {
        X509SubjectAlternativeNameExtension? san = null;

        foreach (X509Extension extension in extensions)
        {
            if (extension.Oid?.Value != "2.5.29.17")
            {
                continue;
            }

            san = extension as X509SubjectAlternativeNameExtension
                  ?? new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical);
            break;
        }

        return san is null ? SubjectAlternativeNames.Empty : ExtractSubjectAlternativeNames(san);
    }

    /// <summary>
    /// Decomposes a subjectAltName extension into names grouped by type.
    /// </summary>
    /// <remarks>
    /// Public so that certificates and CSRs are decomposed by exactly the same code. The
    /// re-enrollment identity check compares the two, and two separate extraction paths would
    /// eventually disagree about what counts as a name — which is precisely the seam an
    /// impersonation attempt would aim at.
    /// </remarks>
    /// <exception cref="EstCodecException">The extension is malformed.</exception>
    public static SubjectAlternativeNames ExtractSubjectAlternativeNames(X509SubjectAlternativeNameExtension san)
    {
        ArgumentNullException.ThrowIfNull(san);

        try
        {
            List<string> dns = [.. san.EnumerateDnsNames()];
            List<IPAddress> ips = [.. san.EnumerateIPAddresses()];
            (List<string> emails, List<string> upns, List<string> uris) = EnumerateOtherNames(san.RawData);
            return new SubjectAlternativeNames(dns, ips, emails, upns, uris);
        }
        catch (CryptographicException ex)
        {
            throw new EstCodecException("The subjectAltName extension in the request is malformed.", ex);
        }
        catch (AsnContentException ex)
        {
            throw new EstCodecException("The subjectAltName extension in the request is malformed.", ex);
        }
    }

    /// <summary>
    /// Pulls rfc822Name, uniformResourceIdentifier and userPrincipalName otherName entries out of
    /// a GeneralNames sequence. The BCL surfaces only DNS and IP directly, but EST clients — device
    /// and user enrollment alike — routinely carry the others, and the re-enrollment identity check
    /// must see every name the certificate would assert.
    /// </summary>
    private static (List<string> Emails, List<string> Upns, List<string> Uris) EnumerateOtherNames(byte[] rawSan)
    {
        const string UpnOid = "1.3.6.1.4.1.311.20.2.3";

        List<string> emails = [];
        List<string> upns = [];
        List<string> uris = [];

        var reader = new AsnReader(rawSan, AsnEncodingRules.DER);
        AsnReader names = reader.ReadSequence();

        while (names.HasData)
        {
            Asn1Tag tag = names.PeekTag();

            if (tag.TagClass != TagClass.ContextSpecific)
            {
                names.ReadEncodedValue();
                continue;
            }

            switch (tag.TagValue)
            {
                case 0: // otherName [0] — used by UPN
                    ReadOtherName(names, tag, UpnOid, upns);
                    break;
                case 1: // rfc822Name [1] IA5String
                    emails.Add(names.ReadCharacterString(UniversalTagNumber.IA5String, tag));
                    break;
                case 6: // uniformResourceIdentifier [6] IA5String
                    uris.Add(names.ReadCharacterString(UniversalTagNumber.IA5String, tag));
                    break;
                default:
                    names.ReadEncodedValue();
                    break;
            }
        }

        return (emails, upns, uris);
    }

    private static void ReadOtherName(AsnReader names, Asn1Tag tag, string wantedOid, List<string> into)
    {
        AsnReader otherName = names.ReadSequence(tag);
        string oid = otherName.ReadObjectIdentifier();

        if (!otherName.HasData)
        {
            return;
        }

        AsnReader valueHolder = otherName.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

        if (oid == wantedOid && valueHolder.HasData)
        {
            Asn1Tag valueTag = valueHolder.PeekTag();
            if (valueTag.TagValue is (int)UniversalTagNumber.UTF8String)
            {
                into.Add(valueHolder.ReadCharacterString(UniversalTagNumber.UTF8String));
            }
        }
    }
}
