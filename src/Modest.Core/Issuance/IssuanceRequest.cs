using Modest.Core.Est;

namespace Modest.Core.Issuance;

/// <summary>
/// A request to issue a certificate, handed from the EST protocol layer to an
/// <see cref="ICertificateIssuer"/>.
/// </summary>
/// <param name="Pkcs10Der">
/// The raw, already base64-decoded DER bytes of the client's PKCS#10 CertificationRequest.
/// Passed as bytes rather than a parsed object so a delegating issuer can forward exactly the
/// bytes the client sent, with no re-encoding drift.
/// </param>
/// <param name="Operation">Whether this arrived at /simpleenroll or /simplereenroll.</param>
/// <param name="Identity">The authenticated client identity.</param>
/// <param name="CorrelationKey">
/// Stable key derived from the CSR bytes and client identity. RFC 7030 s4.2.3 makes the client
/// stateless across an HTTP 202 retry — it resends a byte-identical request — so an asynchronous
/// issuer must correlate retries by content, not by any token it handed the client.
/// </param>
public sealed record IssuanceRequest(
    ReadOnlyMemory<byte> Pkcs10Der,
    EstOperation Operation,
    ClientIdentity Identity,
    string CorrelationKey);
