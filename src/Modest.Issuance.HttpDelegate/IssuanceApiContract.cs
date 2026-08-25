using System.Text.Json.Serialization;

namespace Modest.Issuance.HttpDelegate;

/// <summary>
/// Request body sent to the upstream issuance API.
/// </summary>
/// <param name="Csr">
/// Base64 of the PEM-encoded PKCS#10 request (i.e. base64 of the full
/// <c>-----BEGIN CERTIFICATE REQUEST-----</c> text, not of the raw DER bytes underneath it) — see
/// 09-open-questions.md #1.
/// </param>
/// <remarks>
/// This is re-encoded from the decoded DER rather than forwarding the EST request body verbatim.
/// The body arriving from an EST client may carry line wrapping and whitespace, which is fine for
/// EST's own base64 framing but would be passed on to an upstream that may not tolerate it.
/// Encoding from bytes gives one canonical form regardless of what the client sent.
/// </remarks>
public sealed record IssuanceApiRequest(
    [property: JsonPropertyName("CSR")] string Csr);

/// <summary>
/// Response body expected from the upstream issuance API.
/// </summary>
/// <param name="Certificate">The issued leaf certificate, PEM encoded.</param>
/// <param name="Issuer">
/// The issuing chain as concatenated PEM certificates, ordered intermediate(s) then root. The leaf
/// is not repeated here.
/// </param>
public sealed record IssuanceApiResponse(
    [property: JsonPropertyName("certificate")] string? Certificate,
    [property: JsonPropertyName("issuer")] string? Issuer);
