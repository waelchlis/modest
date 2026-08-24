namespace Modest.Core.Est;

/// <summary>
/// The RFC 7030 well-known URI structure. The optional [label] path segment for multi-CA
/// deployments is deliberately not implemented in v1 (see planning/01-rfc7030-reference.md),
/// but routing is grouped under <see cref="Prefix"/> so a label segment can be inserted later.
/// </summary>
public static class EstUriPaths
{
    /// <summary>Fixed well-known path prefix (RFC 7030 s3.2.2, RFC 5785).</summary>
    public const string Prefix = "/.well-known/est";

    public const string CaCerts = "/cacerts";
    public const string SimpleEnroll = "/simpleenroll";
    public const string SimpleReenroll = "/simplereenroll";
    public const string CsrAttrs = "/csrattrs";
}
