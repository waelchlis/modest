using System.ComponentModel.DataAnnotations;

namespace Modest.Issuance.HttpDelegate;

/// <summary>
/// Configuration for the delegating issuer, bound from the <c>Issuance:HttpDelegate</c> section.
/// </summary>
public sealed class HttpDelegateOptions
{
    public const string SectionName = "Issuance:HttpDelegate";

    /// <summary>Base address of the upstream issuance API.</summary>
    [Required(AllowEmptyStrings = false)]
    [Url]
    public string BaseAddress { get; set; } = string.Empty;

    /// <summary>Path appended to <see cref="BaseAddress"/> for the issuance call.</summary>
    [Required(AllowEmptyStrings = false)]
    public string IssuePath { get; set; } = "/api/v1/issue";

    /// <summary>Username for HTTP Basic authentication against the upstream API.</summary>
    public string? BasicAuthUsername { get; set; }

    /// <summary>
    /// Path to a file containing the upstream Basic authentication password.
    /// </summary>
    /// <remarks>A path rather than the secret itself, for the same reasons as the CA PFX password.</remarks>
    public string? BasicAuthPasswordFile { get; set; }

    /// <summary>
    /// Path to a PEM file holding the CA chain to publish from /cacerts.
    /// </summary>
    /// <remarks>
    /// Statically configured rather than harvested from issuance responses, because /cacerts has to
    /// answer a client that has never enrolled — that is precisely the bootstrap case — and a cache
    /// populated by past issuances would be empty at exactly that moment.
    /// </remarks>
    [Required(AllowEmptyStrings = false)]
    public string StaticCaChainPath { get; set; } = string.Empty;

    /// <summary>Per-attempt timeout for the upstream call.</summary>
    [Range(1, 600)]
    public int TimeoutSeconds { get; set; } = 30;

    /// <summary>Retry attempts for transient upstream failures, beyond the first try.</summary>
    [Range(0, 10)]
    public int MaxRetryAttempts { get; set; } = 3;

    /// <summary>Largest CSR accepted, checked before any outbound call is made.</summary>
    [Range(256, 1024 * 1024)]
    public int MaxCsrSizeBytes { get; set; } = 16 * 1024;
}
