using Modest.Core.Est;
using Modest.Core.Issuance;

namespace Modest.Server.Endpoints;

/// <summary>
/// Builds the HTTP responses RFC 7030 specifies.
/// </summary>
public static class EstResults
{
    /// <summary>
    /// Writes a base64 certs-only PKCS#7 body with the headers RFC 7030 requires.
    /// </summary>
    public static async Task WriteCertsOnlyAsync(HttpContext context, byte[] der)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(der);

        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = EstMediaTypes.Pkcs7CertsOnly;
        context.Response.Headers["Content-Transfer-Encoding"] = EstMediaTypes.Base64TransferEncoding;

        await context.Response.WriteAsync(Modest.Codec.Base64Wire.Encode(der)).ConfigureAwait(false);
    }

    /// <summary>Writes a plain-text error body (RFC 7030 s4.4).</summary>
    public static async Task WriteProblemAsync(HttpContext context, int statusCode, string message)
    {
        ArgumentNullException.ThrowIfNull(context);

        context.Response.StatusCode = statusCode;
        context.Response.ContentType = EstMediaTypes.PlainText;
        await context.Response.WriteAsync(message).ConfigureAwait(false);
    }

    /// <summary>Writes the 401 challenge, advertising Basic authentication.</summary>
    public static async Task WriteUnauthorizedAsync(HttpContext context, string realm, string message)
    {
        ArgumentNullException.ThrowIfNull(context);

        context.Response.Headers.WWWAuthenticate = $"Basic realm=\"{realm}\"";
        await WriteProblemAsync(context, StatusCodes.Status401Unauthorized, message).ConfigureAwait(false);
    }

    /// <summary>Writes the 202 Accepted retry response for asynchronous issuance (RFC 7030 s4.2.3).</summary>
    public static Task WriteRetryAfterAsync(HttpContext context, TimeSpan retryAfter)
    {
        ArgumentNullException.ThrowIfNull(context);

        int seconds = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds));
        context.Response.StatusCode = StatusCodes.Status202Accepted;
        context.Response.Headers.RetryAfter = seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        context.Response.ContentLength = 0;

        return Task.CompletedTask;
    }

    /// <summary>
    /// Maps an issuer's rejection to an HTTP status code.
    /// </summary>
    /// <remarks>
    /// Pure and separate from the pipeline so the mapping can be tested on its own. Note that
    /// <see cref="IssuanceRejectionKind.Unauthorized"/> is a 403 and not a 401: the caller did
    /// authenticate, they are simply not permitted this issuance, and a 401 would wrongly invite
    /// them to retry with different credentials.
    /// </remarks>
    public static int MapRejectionToStatusCode(IssuanceRejectionKind kind) => kind switch
    {
        IssuanceRejectionKind.InvalidCsr => StatusCodes.Status400BadRequest,
        IssuanceRejectionKind.PolicyDenied => StatusCodes.Status403Forbidden,
        IssuanceRejectionKind.Unauthorized => StatusCodes.Status403Forbidden,
        IssuanceRejectionKind.UpstreamUnavailable => StatusCodes.Status502BadGateway,
        _ => StatusCodes.Status500InternalServerError,
    };
}
