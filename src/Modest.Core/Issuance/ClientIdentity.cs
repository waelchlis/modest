using System.Security.Cryptography.X509Certificates;

namespace Modest.Core.Issuance;

/// <summary>
/// How an EST client authenticated itself for this request.
/// </summary>
public enum ClientAuthMethod
{
    /// <summary>No credentials presented. Only valid for the bootstrap operations (/cacerts, /csrattrs).</summary>
    None,

    /// <summary>TLS client certificate — the RECOMMENDED method per RFC 7030 s3.3.2.</summary>
    ClientCertificate,

    /// <summary>HTTP Basic authentication over TLS (RFC 7030 s3.2.3).</summary>
    HttpBasic,
}

/// <summary>
/// The authenticated identity behind an EST request, threaded through to the issuer so
/// issuance policy and the audit log can see who asked.
/// </summary>
/// <param name="Method">Which credential the client actually presented.</param>
/// <param name="Subject">Client certificate subject DN, or the Basic auth username. Null when unauthenticated.</param>
/// <param name="ClientCertificate">The validated client certificate, when one was presented.</param>
public sealed record ClientIdentity(
    ClientAuthMethod Method,
    string? Subject,
    X509Certificate2? ClientCertificate)
{
    /// <summary>An unauthenticated identity.</summary>
    public static ClientIdentity Anonymous { get; } = new(ClientAuthMethod.None, null, null);

    /// <summary>True when any credential was successfully validated.</summary>
    public bool IsAuthenticated => Method != ClientAuthMethod.None;
}
