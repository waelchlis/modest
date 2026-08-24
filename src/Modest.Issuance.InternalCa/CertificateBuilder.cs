using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Modest.Codec;

namespace Modest.Issuance.InternalCa;

/// <summary>
/// Turns a verified CSR into a signed leaf certificate.
/// </summary>
/// <remarks>
/// <para>
/// The security-critical decision here is what to carry over from the CSR. A PKCS#10 request can
/// ask for any extension at all, including <c>basicConstraints CA:true</c>. A CA that copies the
/// requested extension list wholesale will hand out subordinate CA certificates to anyone who asks,
/// which is a full compromise of the PKI.
/// </para>
/// <para>
/// So nothing is copied by default. Subject and subjectAltName come across because they are the
/// identity the client is enrolling for; everything else — basicConstraints, keyUsage,
/// extendedKeyUsage, and any extension this code has never heard of — is set from local policy or
/// dropped.
/// </para>
/// </remarks>
public static class CertificateBuilder
{
    /// <summary>Builds and signs a leaf certificate for the given CSR.</summary>
    public static X509Certificate2 Build(ParsedCsr csr, X509Certificate2 issuer, InternalCaOptions options)
    {
        ArgumentNullException.ThrowIfNull(csr);
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(options);

        HashAlgorithmName hashAlgorithm = ParseHashAlgorithm(options.SignatureAlgorithm);
        CertificateRequest request = CreateRequestForKey(csr, hashAlgorithm);

        ApplyPolicyExtensions(request, csr, options);

        // authorityKeyIdentifier, tying the leaf to the specific CA key that signed it. RFC 5280
        // s4.2.1.1 requires it on every certificate that is not self-signed, and path builders lean
        // on it to pick the right issuer when a CA has re-keyed and several certificates share a
        // subject name.
        request.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromCertificate(
                issuer, includeKeyIdentifier: true, includeIssuerAndSerial: false));

        DateTimeOffset notBefore = DateTimeOffset.UtcNow - options.BackdateBy;
        DateTimeOffset notAfter = DateTimeOffset.UtcNow + options.ValidityPeriod;

        // Never hand out a certificate that outlives its issuer. Past the CA's own expiry the leaf
        // cannot be validated by anything, so the extra lifetime is not merely useless — it invites
        // an operator to trust an expiry date that was never real.
        if (notAfter > issuer.NotAfter)
        {
            notAfter = issuer.NotAfter;
        }

        using DisposingSignatureGenerator generator = CreateSignatureGenerator(issuer, hashAlgorithm);

        return request.Create(
            issuer.SubjectName,
            generator,
            notBefore,
            notAfter,
            GenerateSerialNumber());
    }

    /// <summary>
    /// A 20-byte random serial with the top bit cleared.
    /// </summary>
    /// <remarks>
    /// RFC 5280 s4.1.2.2 caps serials at 20 octets and requires a positive integer, hence masking
    /// the sign bit. Random rather than sequential: a counter would leak how many certificates the
    /// CA has issued and in what order.
    /// </remarks>
    public static byte[] GenerateSerialNumber()
    {
        byte[] serial = new byte[20];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F;

        // A leading zero byte would be stripped as redundant DER padding, shortening the serial.
        if (serial[0] == 0)
        {
            serial[0] = 0x01;
        }

        return serial;
    }

    private static CertificateRequest CreateRequestForKey(ParsedCsr csr, HashAlgorithmName hashAlgorithm)
    {
        // Rebuilding the request from the CSR's subject and public key — rather than reusing the
        // parsed CertificateRequest — guarantees no requested extension can survive by accident.
        if (Pkcs10CsrReader.IsRsa(csr))
        {
            return new CertificateRequest(
                csr.Subject,
                csr.PublicKey,
                hashAlgorithm,
                RSASignaturePadding.Pkcs1);
        }

        return new CertificateRequest(csr.Subject, csr.PublicKey, hashAlgorithm);
    }

    private static void ApplyPolicyExtensions(
        CertificateRequest request, ParsedCsr csr, InternalCaOptions options)
    {
        // End-entity, always. Critical, so a client cannot be talked into treating it as a CA.
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));

        X509KeyUsageFlags keyUsage = ParseKeyUsages(options.EffectiveKeyUsages);
        if (keyUsage != X509KeyUsageFlags.None)
        {
            request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, true));
        }

        if (options.EffectiveEnhancedKeyUsageOids.Count > 0)
        {
            OidCollection ekus = [];
            foreach (string oid in options.EffectiveEnhancedKeyUsageOids)
            {
                ekus.Add(new Oid(oid));
            }

            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(ekus, false));
        }

        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        if (options.CopySubjectAlternativeNames && !csr.SubjectAlternativeNames.IsEmpty)
        {
            request.CertificateExtensions.Add(BuildSanExtension(csr.SubjectAlternativeNames));
        }
    }

    private static X509Extension BuildSanExtension(SubjectAlternativeNames sans)
    {
        var builder = new SubjectAlternativeNameBuilder();

        foreach (string dns in sans.DnsNames)
        {
            builder.AddDnsName(dns);
        }

        foreach (IPAddress ip in sans.IPAddresses)
        {
            builder.AddIpAddress(ip);
        }

        foreach (string email in sans.EmailAddresses)
        {
            builder.AddEmailAddress(email);
        }

        foreach (string uri in sans.Uris)
        {
            // A uniformResourceIdentifier SAN is an IA5String, so a CSR can carry text there that is
            // not a URI at all. Uri's constructor answers that with UriFormatException — a
            // FormatException, which no caller upstream expects — so it is converted here into the
            // ArgumentException the issuer already maps to a 400.
            if (!Uri.TryCreate(uri, UriKind.Absolute, out Uri? parsed))
            {
                throw new ArgumentException(
                    $"The request carries a subjectAltName URI that is not a valid absolute URI: '{uri}'.",
                    nameof(sans));
            }

            builder.AddUri(parsed);
        }

        foreach (string upn in sans.UserPrincipalNames)
        {
            builder.AddUserPrincipalName(upn);
        }

        return builder.Build();
    }

    private static DisposingSignatureGenerator CreateSignatureGenerator(
        X509Certificate2 issuer, HashAlgorithmName hashAlgorithm)
    {
        RSA? rsa = issuer.GetRSAPrivateKey();
        if (rsa is not null)
        {
            return new DisposingSignatureGenerator(
                X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1), rsa);
        }

        ECDsa? ecdsa = issuer.GetECDsaPrivateKey();
        if (ecdsa is not null)
        {
            return new DisposingSignatureGenerator(X509SignatureGenerator.CreateForECDsa(ecdsa), ecdsa);
        }

        throw new CaKeyLoadException(
            "The CA private key is neither RSA nor ECDSA, so it cannot be used to sign certificates.");
    }

    private static HashAlgorithmName ParseHashAlgorithm(string name) =>
        name.ToUpperInvariant() switch
        {
            "SHA256" or "SHA-256" => HashAlgorithmName.SHA256,
            "SHA384" or "SHA-384" => HashAlgorithmName.SHA384,
            "SHA512" or "SHA-512" => HashAlgorithmName.SHA512,
            _ => throw new ArgumentOutOfRangeException(
                nameof(name), name, "Supported signature hash algorithms are SHA256, SHA384 and SHA512."),
        };

    private static X509KeyUsageFlags ParseKeyUsages(IEnumerable<string> usages)
    {
        X509KeyUsageFlags flags = X509KeyUsageFlags.None;

        foreach (string usage in usages)
        {
            flags |= usage.Replace("_", string.Empty, StringComparison.Ordinal).ToUpperInvariant() switch
            {
                "DIGITALSIGNATURE" => X509KeyUsageFlags.DigitalSignature,
                "NONREPUDIATION" => X509KeyUsageFlags.NonRepudiation,
                "KEYENCIPHERMENT" => X509KeyUsageFlags.KeyEncipherment,
                "DATAENCIPHERMENT" => X509KeyUsageFlags.DataEncipherment,
                "KEYAGREEMENT" => X509KeyUsageFlags.KeyAgreement,
                "KEYCERTSIGN" => throw new ArgumentOutOfRangeException(
                    nameof(usages), usage,
                    "keyCertSign must not be configured for end-entity certificates: it would let the holder issue certificates."),
                "CRLSIGN" => X509KeyUsageFlags.CrlSign,
                "ENCIPHERONLY" => X509KeyUsageFlags.EncipherOnly,
                "DECIPHERONLY" => X509KeyUsageFlags.DecipherOnly,
                _ => throw new ArgumentOutOfRangeException(nameof(usages), usage, "Unrecognised key usage."),
            };
        }

        return flags;
    }

    /// <summary>
    /// Keeps the private key alive for exactly as long as the generator that borrows it, so the
    /// caller has one thing to dispose rather than two with an ordering constraint between them.
    /// </summary>
    private sealed class DisposingSignatureGenerator : X509SignatureGenerator, IDisposable
    {
        private readonly X509SignatureGenerator _inner;
        private readonly IDisposable _key;

        public DisposingSignatureGenerator(X509SignatureGenerator inner, IDisposable key)
        {
            _inner = inner;
            _key = key;
        }

        public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm) =>
            _inner.GetSignatureAlgorithmIdentifier(hashAlgorithm);

        public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm) =>
            _inner.SignData(data, hashAlgorithm);

        protected override PublicKey BuildPublicKey() => _inner.PublicKey;

        public void Dispose() => _key.Dispose();
    }
}
