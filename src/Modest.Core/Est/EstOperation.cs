namespace Modest.Core.Est;

/// <summary>
/// The EST enrollment operation a request represents.
/// </summary>
public enum EstOperation
{
    /// <summary>RFC 7030 /simpleenroll.</summary>
    Enroll,

    /// <summary>RFC 7030 /simplereenroll.</summary>
    Reenroll,
}
