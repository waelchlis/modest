using System.ComponentModel.DataAnnotations;

namespace Modest.Server.Configuration;

/// <summary>Which issuance backend this instance runs.</summary>
public enum IssuanceMode
{
    /// <summary>Sign with a CA key held by this process.</summary>
    InternalCa,

    /// <summary>Forward CSRs to an external HTTP issuance API.</summary>
    HttpDelegate,
}

/// <summary>Top-level issuance configuration, bound from the <c>Issuance</c> section.</summary>
public sealed class IssuanceSelectionOptions
{
    public const string SectionName = "Issuance";

    /// <summary>Which issuer implementation to register at startup.</summary>
    public IssuanceMode Mode { get; set; } = IssuanceMode.InternalCa;
}

/// <summary>
/// Rules applied to /simplereenroll, bound from <c>Issuance:Reenrollment</c>.
/// </summary>
public sealed class ReenrollmentOptions
{
    public const string SectionName = "Issuance:Reenrollment";

    /// <summary>
    /// Require that the authenticated client certificate asserts the same identity the CSR asks for.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Re-enrollment means "renew what I already hold". Without this check, any client holding any
    /// valid certificate could re-enroll for somebody else's name, which turns a renewal endpoint
    /// into an impersonation endpoint. Enabled by default.
    /// </para>
    /// <para>
    /// When enabled, a Basic-authenticated re-enrollment is refused: there is no certificate to
    /// establish continuity with, so the check cannot be satisfied. Disable this option if
    /// credential-based re-enrollment is genuinely wanted.
    /// </para>
    /// </remarks>
    public bool RequireMatchingIdentity { get; set; } = true;
}

/// <summary>Inbound EST client authentication settings, bound from <c>Authentication</c>.</summary>
public sealed class EstAuthenticationOptions
{
    public const string SectionName = "Authentication";

    /// <summary>Whether TLS client certificate authentication is accepted.</summary>
    public bool AllowClientCertificate { get; set; } = true;

    /// <summary>Whether HTTP Basic authentication is accepted.</summary>
    public bool AllowHttpBasic { get; set; } = true;

    /// <summary>Realm advertised in the WWW-Authenticate challenge.</summary>
    public string BasicRealm { get; set; } = "modest";

    /// <summary>
    /// Path to a PEM bundle of trust anchors for validating client certificates.
    /// </summary>
    /// <remarks>
    /// Kept separate from both the server's own TLS trust and the issuing CA's root. RFC 7030 s2
    /// distinguishes explicit from implicit trust anchors precisely because the certificate a client
    /// authenticates with may come from an entirely different, pre-existing PKI than the one Modest
    /// issues from. When unset, client certificates are validated against the platform trust store.
    /// </remarks>
    public string? ClientCertificateTrustStorePath { get; set; }

    /// <summary>
    /// Accept any client certificate that parses, skipping chain validation.
    /// </summary>
    /// <remarks>
    /// For development only. Startup logs a warning when this is on.
    /// </remarks>
    public bool AllowUntrustedClientCertificates { get; set; }

    /// <summary>Static credential list used when Basic authentication is enabled.</summary>
    public BasicCredentialOptions[] BasicCredentials { get; set; } = [];
}

/// <summary>One username plus a PBKDF2 verifier. Plaintext passwords are never configured.</summary>
public sealed class BasicCredentialOptions
{
    [Required(AllowEmptyStrings = false)]
    public string Username { get; set; } = string.Empty;

    /// <summary>Base64 PBKDF2-HMAC-SHA256 derived key.</summary>
    [Required(AllowEmptyStrings = false)]
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>Base64 salt used to derive <see cref="PasswordHash"/>.</summary>
    [Required(AllowEmptyStrings = false)]
    public string Salt { get; set; } = string.Empty;

    /// <summary>PBKDF2 iteration count used to derive <see cref="PasswordHash"/>.</summary>
    [Range(10_000, 10_000_000)]
    public int Iterations { get; set; } = 210_000;
}

/// <summary>Protocol-level limits, bound from <c>Est</c>.</summary>
public sealed class EstProtocolOptions
{
    public const string SectionName = "Est";

    /// <summary>
    /// Largest enrollment request body accepted, before base64 decoding.
    /// </summary>
    /// <remarks>
    /// Bounded well below the default request limits so that an oversized body is refused before any
    /// base64 decoding or ASN.1 parsing work is done on it.
    /// </remarks>
    [Range(512, 4 * 1024 * 1024)]
    public int MaxRequestBodyBytes { get; set; } = 64 * 1024;
}
