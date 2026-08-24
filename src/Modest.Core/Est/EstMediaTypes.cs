namespace Modest.Core.Est;

/// <summary>
/// Media types fixed by RFC 7030. EST does not use Accept-header negotiation: each
/// operation has exactly one request and one response content type.
/// </summary>
public static class EstMediaTypes
{
    /// <summary>Request body type for /simpleenroll and /simplereenroll (RFC 7030 s3.2.1).</summary>
    public const string Pkcs10 = "application/pkcs10";

    /// <summary>Response body type for /cacerts and enrollment responses.</summary>
    public const string Pkcs7CertsOnly = "application/pkcs7-mime; smime-type=certs-only";

    /// <summary>Bare PKCS#7 type without the smime-type parameter, for comparisons.</summary>
    public const string Pkcs7Mime = "application/pkcs7-mime";

    /// <summary>Response body type for /csrattrs.</summary>
    public const string CsrAttrs = "application/csrattrs";

    /// <summary>Plain text, used for human-readable error bodies (RFC 7030 s4.4).</summary>
    public const string PlainText = "text/plain; charset=utf-8";

    /// <summary>Value of the Content-Transfer-Encoding header on all binary EST payloads.</summary>
    public const string Base64TransferEncoding = "base64";
}
