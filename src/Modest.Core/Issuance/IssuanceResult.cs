using System.Security.Cryptography.X509Certificates;

namespace Modest.Core.Issuance;

/// <summary>
/// Why an issuer declined to issue. Maps to an HTTP status at the protocol layer.
/// </summary>
public enum IssuanceRejectionKind
{
    /// <summary>The CSR itself is unacceptable (key too small, disallowed algorithm, bad subject).</summary>
    InvalidCsr,

    /// <summary>CA policy declined this request.</summary>
    PolicyDenied,

    /// <summary>The caller authenticated but is not authorized for this issuance.</summary>
    Unauthorized,

    /// <summary>A delegated issuer could not reach or get a usable answer from its upstream CA.</summary>
    UpstreamUnavailable,
}

/// <summary>
/// The outcome of an issuance attempt. A closed union rather than exceptions: "policy said no"
/// and "upstream is down" are ordinary outcomes for an EST server, not exceptional ones.
/// Exceptions remain reserved for genuine faults and become HTTP 500.
/// </summary>
public abstract record IssuanceResult
{
    private IssuanceResult()
    {
    }

    /// <summary>A certificate was issued.</summary>
    /// <param name="Certificate">The issued leaf certificate.</param>
    /// <param name="Chain">Issuing chain, leaf excluded, ordered from the immediate issuer upward.</param>
    public sealed record Issued(X509Certificate2 Certificate, IReadOnlyList<X509Certificate2> Chain) : IssuanceResult;

    /// <summary>
    /// Issuance is under way but not finished; the client should retry the identical request.
    /// Surfaces as HTTP 202 with Retry-After (RFC 7030 s4.2.3). No v1 issuer returns this, but
    /// the protocol layer implements it so an asynchronous issuer needs no interface change.
    /// </summary>
    public sealed record Pending(TimeSpan RetryAfter) : IssuanceResult;

    /// <summary>Issuance was declined.</summary>
    public sealed record Rejected(string Reason, IssuanceRejectionKind Kind) : IssuanceResult;
}
