using System.Security.Cryptography.X509Certificates;
using Modest.Codec;

namespace Modest.Server.Tests;

/// <summary>
/// Assertions and decoding helpers shared by the endpoint tests.
/// </summary>
public static class EstResponse
{
    /// <summary>
    /// Reads a header without caring whether the client stack filed it under the message or the
    /// content.
    /// </summary>
    /// <remarks>
    /// <c>Content-Transfer-Encoding</c> is not one of the headers <see cref="HttpClient"/> knows, so
    /// which collection it lands in is an implementation detail of the client — not something an EST
    /// server's behaviour should be asserted through.
    /// </remarks>
    public static string? Header(HttpResponseMessage response, string name)
    {
        ArgumentNullException.ThrowIfNull(response);

        if (response.Headers.TryGetValues(name, out IEnumerable<string>? values) ||
            response.Content.Headers.TryGetValues(name, out values))
        {
            return string.Join(", ", values);
        }

        return null;
    }

    /// <summary>Reads the body and asserts it is base64 text, then returns the decoded bytes.</summary>
    /// <remarks>
    /// RFC 7030 s3.2.1 carries binary payloads as base64 with no mandated line length, so the check
    /// is "every character is base64 or whitespace" rather than anything about wrapping. The point is
    /// to catch a server that writes raw DER to the socket, which would still decode into something
    /// on a lenient client and go unnoticed.
    /// </remarks>
    public static async Task<byte[]> ReadBase64BodyAsync(HttpResponseMessage response)
    {
        ArgumentNullException.ThrowIfNull(response);

        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        body.ShouldNotBeNullOrWhiteSpace();

        foreach (char c in body)
        {
            bool legal = char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '=' || char.IsWhiteSpace(c);
            legal.ShouldBeTrue(
                $"The response body should be base64 text but contains U+{(int)c:X4}, " +
                "which suggests raw binary was written to the socket.");
        }

        return Base64Wire.DecodeTolerant(body);
    }

    /// <summary>Reads a certs-only PKCS#7 response body and returns the certificates it carries.</summary>
    public static async Task<IReadOnlyList<X509Certificate2>> ReadCertsOnlyAsync(HttpResponseMessage response)
    {
        byte[] der = await ReadBase64BodyAsync(response).ConfigureAwait(false);
        return Pkcs7CertsOnlyWriter.Read(der);
    }

    /// <summary>Asserts the headers RFC 7030 requires on a certs-only response.</summary>
    public static void ShouldBeCertsOnlyResponse(HttpResponseMessage response)
    {
        ArgumentNullException.ThrowIfNull(response);

        // Read into a local first: `ContentType?.ToString().ShouldBe(...)` would silently assert
        // nothing at all when the header is missing, which is the case most worth catching.
        string? contentType = response.Content.Headers.ContentType?.ToString();
        contentType.ShouldBe("application/pkcs7-mime; smime-type=certs-only");

        Header(response, "Content-Transfer-Encoding").ShouldBe("base64");
    }
}
