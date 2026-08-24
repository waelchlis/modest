using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace Modest.Codec;

/// <summary>
/// A PKCS#10 CertificationRequest that has been parsed and whose embedded self-signature has
/// been verified.
/// </summary>
/// <remarks>
/// Holding an instance is itself the proof-of-possession guarantee: <see cref="Pkcs10CsrReader"/>
/// is the only way to construct one, and it will not return without verifying the signature.
/// </remarks>
public sealed class ParsedCsr
{
    internal ParsedCsr(
        ReadOnlyMemory<byte> der,
        X500DistinguishedName subject,
        PublicKey publicKey,
        IReadOnlyList<X509Extension> requestedExtensions,
        SubjectAlternativeNames subjectAlternativeNames)
    {
        Der = der;
        Subject = subject;
        PublicKey = publicKey;
        RequestedExtensions = requestedExtensions;
        SubjectAlternativeNames = subjectAlternativeNames;
    }

    /// <summary>The exact DER bytes the client submitted, unmodified.</summary>
    public ReadOnlyMemory<byte> Der { get; }

    /// <summary>The requested subject distinguished name.</summary>
    public X500DistinguishedName Subject { get; }

    /// <summary>The public key whose private half the requester proved possession of.</summary>
    public PublicKey PublicKey { get; }

    /// <summary>
    /// Extensions the CSR asked for, via its extensionRequest attribute.
    /// </summary>
    /// <remarks>
    /// These are requests from an untrusted party, not facts. A CSR is free to ask for
    /// basicConstraints CA:true; an issuer that copies this list wholesale would mint a CA.
    /// Issuers must filter against an allow-list.
    /// </remarks>
    public IReadOnlyList<X509Extension> RequestedExtensions { get; }

    /// <summary>The subject alternative names requested, decomposed by type.</summary>
    public SubjectAlternativeNames SubjectAlternativeNames { get; }

    /// <summary>The public key algorithm OID (RSA, ECC, ...).</summary>
    public string PublicKeyAlgorithmOid => PublicKey.Oid.Value ?? string.Empty;
}

/// <summary>
/// Subject alternative names split by type. Types are kept apart deliberately: a DNS name and an
/// IP address that happen to render as the same string are different identities, and comparing
/// them as flat strings would let one impersonate the other.
/// </summary>
public sealed record SubjectAlternativeNames(
    IReadOnlyList<string> DnsNames,
    IReadOnlyList<IPAddress> IPAddresses,
    IReadOnlyList<string> EmailAddresses,
    IReadOnlyList<string> UserPrincipalNames,
    IReadOnlyList<string> Uris)
{
    public static SubjectAlternativeNames Empty { get; } = new([], [], [], [], []);

    /// <summary>True when no SAN of any type was requested.</summary>
    public bool IsEmpty =>
        DnsNames.Count == 0 &&
        IPAddresses.Count == 0 &&
        EmailAddresses.Count == 0 &&
        UserPrincipalNames.Count == 0 &&
        Uris.Count == 0;

    /// <summary>
    /// Type-tagged, order-independent comparison against another SAN set.
    /// </summary>
    public bool SetEquals(SubjectAlternativeNames other)
    {
        ArgumentNullException.ThrowIfNull(other);

        return SetEq(DnsNames, other.DnsNames, StringComparer.OrdinalIgnoreCase)
            && SetEq(EmailAddresses, other.EmailAddresses, StringComparer.OrdinalIgnoreCase)
            && SetEq(UserPrincipalNames, other.UserPrincipalNames, StringComparer.OrdinalIgnoreCase)
            && SetEq(Uris, other.Uris, StringComparer.Ordinal)
            && SetEq(
                IPAddresses.Select(static ip => ip.ToString()).ToList(),
                other.IPAddresses.Select(static ip => ip.ToString()).ToList(),
                StringComparer.OrdinalIgnoreCase);
    }

    private static bool SetEq(IReadOnlyList<string> a, IReadOnlyList<string> b, StringComparer comparer) =>
        new HashSet<string>(a, comparer).SetEquals(b);
}
