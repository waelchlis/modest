using System.ComponentModel.DataAnnotations;

namespace Modest.Issuance.InternalCa;

/// <summary>
/// Configuration for the internal CA issuer, bound from the <c>Issuance:InternalCa</c> section.
/// </summary>
public sealed class InternalCaOptions
{
    public const string SectionName = "Issuance:InternalCa";

    /// <summary>Path to the PKCS#12 file holding the CA certificate and its private key.</summary>
    [Required(AllowEmptyStrings = false)]
    public string CertificatePath { get; set; } = string.Empty;

    /// <summary>
    /// Path to a file containing the PFX password.
    /// </summary>
    /// <remarks>
    /// A path rather than the password itself: an inline value would surface in process listings,
    /// container inspection output and configuration-management diffs. Leave unset for a PFX with
    /// no password.
    /// </remarks>
    public string? CertificatePasswordFile { get; set; }

    /// <summary>
    /// Additional certificates — typically the root above an issuing intermediate — to append to
    /// the chain served from /cacerts and returned with issued certificates.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every collection option on this type is nullable, and null means "the operator configured
    /// nothing, use the built-in default". Defaults are applied by <see cref="Defaults"/> rather
    /// than by property initialisers.
    /// </para>
    /// <para>
    /// This is not stylistic. The configuration binder <em>appends</em> to a collection that already
    /// holds items — for both <c>List&lt;T&gt;</c> and arrays — so an initialiser default would be
    /// silently unioned with whatever the operator configured. For <see cref="AllowedEllipticCurves"/>
    /// that is a security hole: an operator narrowing the accepted curves would still find every
    /// default curve permitted, with nothing in the configuration to suggest it. It was caught when a
    /// smoke test produced a certificate carrying its extended key usage twice.
    /// </para>
    /// </remarks>
    public string[]? AdditionalChainCertificatePaths { get; set; }

    /// <summary>Hash algorithm used to sign issued certificates.</summary>
    public string SignatureAlgorithm { get; set; } = "SHA256";

    /// <summary>Lifetime of issued certificates.</summary>
    [Range(typeof(TimeSpan), "00:05:00", "3650.00:00:00")]
    public TimeSpan ValidityPeriod { get; set; } = TimeSpan.FromDays(90);

    /// <summary>
    /// Clock skew allowance applied backwards to notBefore, so a freshly issued certificate is not
    /// rejected by a client whose clock runs slightly behind the server's.
    /// </summary>
    public TimeSpan BackdateBy { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Smallest acceptable RSA modulus, in bits.</summary>
    [Range(1024, 16384)]
    public int MinimumRsaKeySizeBits { get; set; } = 2048;

    /// <summary>
    /// Elliptic curves accepted in a CSR, by friendly name. An explicitly empty list refuses EC keys.
    /// </summary>
    public string[]? AllowedEllipticCurves { get; set; }

    /// <summary>Whether RSA keys are accepted at all.</summary>
    public bool AllowRsa { get; set; } = true;

    /// <summary>Whether elliptic curve keys are accepted at all.</summary>
    public bool AllowEllipticCurve { get; set; } = true;

    /// <summary>
    /// Extended key usage OIDs placed on issued certificates. An explicitly empty list omits the
    /// extension entirely.
    /// </summary>
    public string[]? EnhancedKeyUsageOids { get; set; }

    /// <summary>Key usage flags placed on issued certificates.</summary>
    public string[]? KeyUsages { get; set; }

    /// <summary>
    /// Whether subject alternative names requested in the CSR are carried onto the issued
    /// certificate.
    /// </summary>
    /// <remarks>
    /// SANs are the one extension category copied from client input, because EST clients legitimately
    /// need to state the names they will be reached by. Every other requested extension is dropped:
    /// see <see cref="CertificateBuilder"/>.
    /// </remarks>
    public bool CopySubjectAlternativeNames { get; set; } = true;

    /// <summary>
    /// Reject a CSR whose subject distinguished name is empty and which requests no SANs, since the
    /// resulting certificate would identify nobody.
    /// </summary>
    public bool RequireSubjectOrSan { get; set; } = true;

    /// <summary>Built-in defaults, applied where the operator configured nothing.</summary>
    public static class Defaults
    {
        public static string[] EllipticCurves => ["nistP256", "nistP384", "nistP521"];

        /// <summary>clientAuth.</summary>
        public static string[] EnhancedKeyUsageOids => ["1.3.6.1.5.5.7.3.2"];

        public static string[] KeyUsages => ["DigitalSignature", "KeyEncipherment"];
    }

    /// <summary>The elliptic curves to accept, with the default applied when unconfigured.</summary>
    public IReadOnlyList<string> EffectiveAllowedEllipticCurves =>
        AllowedEllipticCurves ?? Defaults.EllipticCurves;

    /// <summary>The extended key usages to issue, with the default applied when unconfigured.</summary>
    public IReadOnlyList<string> EffectiveEnhancedKeyUsageOids =>
        EnhancedKeyUsageOids ?? Defaults.EnhancedKeyUsageOids;

    /// <summary>The key usages to issue, with the default applied when unconfigured.</summary>
    public IReadOnlyList<string> EffectiveKeyUsages =>
        KeyUsages ?? Defaults.KeyUsages;

    /// <summary>Additional chain certificate paths, empty when unconfigured.</summary>
    public IReadOnlyList<string> EffectiveAdditionalChainCertificatePaths =>
        AdditionalChainCertificatePaths ?? [];
}
