using System.Security.Cryptography.X509Certificates;

namespace Modest.Core.Issuance;

/// <summary>
/// The pluggable issuance boundary. Everything above this interface speaks EST; everything
/// below it speaks to a CA. Implementations must not know anything about HTTP or EST wire
/// formats, and the protocol layer must never touch CA key material directly.
/// </summary>
public interface ICertificateIssuer
{
    /// <summary>
    /// The CA chain this issuer signs with (or, for a delegating issuer, the chain it reports as
    /// authoritative). Served from /cacerts, so it must be answerable before any enrollment has
    /// ever happened — a client bootstrapping trust calls this first.
    /// </summary>
    Task<CaChainResult> GetCaChainAsync(CancellationToken cancellationToken);

    /// <summary>Issue or re-issue a certificate for the supplied CSR.</summary>
    Task<IssuanceResult> IssueAsync(IssuanceRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Whether this issuer is ready to serve. Backs /readyz. Implementations should answer from
    /// local state and avoid probing a remote dependency on every call — flapping readiness
    /// causes needless pod restarts under Kubernetes.
    /// </summary>
    Task<bool> IsReadyAsync(CancellationToken cancellationToken);
}

/// <summary>The CA certificate chain served from /cacerts.</summary>
/// <param name="Chain">Ordered chain: issuing CA first, root last.</param>
public sealed record CaChainResult(IReadOnlyList<X509Certificate2> Chain);
