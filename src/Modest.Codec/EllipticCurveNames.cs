namespace Modest.Codec;

/// <summary>
/// Normalises the many spellings of a named elliptic curve to one canonical name.
/// </summary>
/// <remarks>
/// <para>
/// The same curve has at least five names in circulation. P-256 is <c>nistP256</c> to .NET's own
/// <c>ECCurve.NamedCurves</c>, <c>prime256v1</c> to OpenSSL, <c>secp256r1</c> to SEC, <c>P-256</c>
/// in the NIST documents, and — critically — <c>ECDSA_P256</c> in the <c>Oid.FriendlyName</c> that
/// .NET reports on Linux, which is where this server is meant to run.
/// </para>
/// <para>
/// Without normalisation an allow-list written in one vocabulary silently refuses every key
/// expressed in another. That failure is quiet and total: the configuration looks correct, and
/// every EC enrollment is rejected. Matching happens on the OID, which no platform disagrees about.
/// </para>
/// </remarks>
public static class EllipticCurveNames
{
    public const string P256Oid = "1.2.840.10045.3.1.7";
    public const string P384Oid = "1.3.132.0.34";
    public const string P521Oid = "1.3.132.0.35";

    private static readonly Dictionary<string, string> AliasToOid =
        new(StringComparer.OrdinalIgnoreCase)
        {
            [P256Oid] = P256Oid,
            ["nistP256"] = P256Oid,
            ["ECDSA_P256"] = P256Oid,
            ["prime256v1"] = P256Oid,
            ["secp256r1"] = P256Oid,
            ["P-256"] = P256Oid,
            ["P256"] = P256Oid,

            [P384Oid] = P384Oid,
            ["nistP384"] = P384Oid,
            ["ECDSA_P384"] = P384Oid,
            ["prime384v1"] = P384Oid,
            ["secp384r1"] = P384Oid,
            ["P-384"] = P384Oid,
            ["P384"] = P384Oid,

            [P521Oid] = P521Oid,
            ["nistP521"] = P521Oid,
            ["ECDSA_P521"] = P521Oid,
            ["prime521v1"] = P521Oid,
            ["secp521r1"] = P521Oid,
            ["P-521"] = P521Oid,
            ["P521"] = P521Oid,
        };

    private static readonly Dictionary<string, string> OidToCanonical =
        new(StringComparer.Ordinal)
        {
            [P256Oid] = "nistP256",
            [P384Oid] = "nistP384",
            [P521Oid] = "nistP521",
        };

    /// <summary>
    /// Maps any recognised curve name or OID to its canonical name, or returns the input unchanged
    /// when it names a curve this table does not know.
    /// </summary>
    /// <remarks>
    /// Unknown input is passed through rather than rejected so that an operator can allow a curve
    /// this build has never heard of by naming it exactly as the platform reports it.
    /// </remarks>
    public static string Canonicalise(string nameOrOid)
    {
        ArgumentNullException.ThrowIfNull(nameOrOid);

        string trimmed = nameOrOid.Trim();

        return AliasToOid.TryGetValue(trimmed, out string? oid) && OidToCanonical.TryGetValue(oid, out string? canonical)
            ? canonical
            : trimmed;
    }

    /// <summary>Whether two curve identifiers name the same curve, in any spelling.</summary>
    public static bool AreSameCurve(string left, string right) =>
        string.Equals(Canonicalise(left), Canonicalise(right), StringComparison.OrdinalIgnoreCase);
}
