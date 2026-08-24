using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Modest.Codec;
using Modest.Core.Issuance;
using Modest.Server.Configuration;

namespace Modest.Server.Endpoints;

/// <summary>
/// Enforces that a re-enrollment renews the caller's own identity rather than someone else's.
/// </summary>
/// <remarks>
/// <para>
/// RFC 7030 s3.3.2 frames re-enrollment as a client proving continuity by presenting the
/// certificate it already holds. Nothing in the protocol forces the requested subject to match
/// that certificate, so without this check any holder of any valid certificate could re-enroll
/// under another party's name — a renewal endpoint that quietly doubles as an impersonation one.
/// </para>
/// <para>
/// Both the subject distinguished name and the complete SAN set must match. Checking only the
/// subject would leave the far more security-relevant names — the DNS names and IP addresses a
/// TLS peer is actually validated against — unconstrained.
/// </para>
/// </remarks>
public sealed class ReenrollmentIdentityChecker
{
    private readonly IOptionsMonitor<ReenrollmentOptions> _options;
    private readonly ILogger<ReenrollmentIdentityChecker> _logger;

    public ReenrollmentIdentityChecker(
        IOptionsMonitor<ReenrollmentOptions> options,
        ILogger<ReenrollmentIdentityChecker> logger)
    {
        _options = options;
        _logger = logger;
    }

    /// <summary>Whether the check is currently switched on.</summary>
    public bool IsEnabled => _options.CurrentValue.RequireMatchingIdentity;

    /// <summary>
    /// Checks a re-enrollment request.
    /// </summary>
    /// <returns>A rejection when the identities do not match, or null when the request may proceed.</returns>
    public IssuanceResult.Rejected? Check(ClientIdentity identity, ParsedCsr csr)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(csr);

        if (!IsEnabled)
        {
            return null;
        }

        X509Certificate2? clientCertificate = identity.ClientCertificate;

        if (clientCertificate is null)
        {
            // Re-enrollment's premise is continuity with an existing certificate. A caller who
            // authenticated with a username and password has nothing to show continuity with, so
            // while the check is enabled there is no way for them to satisfy it.
            _logger.LogInformation(
                "Refused re-enrollment for {Identity}: no client certificate was presented and " +
                "Issuance:Reenrollment:RequireMatchingIdentity is enabled.",
                identity.Subject ?? "anonymous");

            return new IssuanceResult.Rejected(
                "Re-enrollment requires authentication with the certificate being renewed.",
                IssuanceRejectionKind.Unauthorized);
        }

        if (!SubjectsMatch(clientCertificate.SubjectName, csr.Subject))
        {
            _logger.LogInformation(
                "Refused re-enrollment: client certificate subject {CertSubject} does not match requested subject {CsrSubject}.",
                clientCertificate.Subject,
                csr.Subject.Name);

            return new IssuanceResult.Rejected(
                "The subject in the certificate signing request does not match the subject of the certificate presented for authentication.",
                IssuanceRejectionKind.Unauthorized);
        }

        SubjectAlternativeNames certificateSans = ExtractSans(clientCertificate);

        if (!certificateSans.SetEquals(csr.SubjectAlternativeNames))
        {
            _logger.LogInformation(
                "Refused re-enrollment for {Subject}: the requested subject alternative names differ from those in the presented certificate.",
                clientCertificate.Subject);

            return new IssuanceResult.Rejected(
                "The subject alternative names in the certificate signing request do not match those of the certificate presented for authentication.",
                IssuanceRejectionKind.Unauthorized);
        }

        return null;
    }

    private static bool SubjectsMatch(X500DistinguishedName certificateSubject, X500DistinguishedName csrSubject)
    {
        // Compare the encoded form rather than the rendered string: two DNs that print identically
        // can differ in attribute encoding or ordering, and string comparison would either accept a
        // mismatch or reject an exact match depending on how each was formatted.
        if (certificateSubject.RawData.AsSpan().SequenceEqual(csrSubject.RawData))
        {
            return true;
        }

        // Fall back to a normalised textual comparison, which tolerates a client that re-encoded an
        // equivalent DN — for example PrintableString where the original used UTF8String.
        return string.Equals(
            Normalise(certificateSubject),
            Normalise(csrSubject),
            StringComparison.OrdinalIgnoreCase);
    }

    private static string Normalise(X500DistinguishedName name) =>
        string.Join(
            ',',
            name.Name
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Order(StringComparer.OrdinalIgnoreCase));

    private static SubjectAlternativeNames ExtractSans(X509Certificate2 certificate)
    {
        X509SubjectAlternativeNameExtension? san = certificate.Extensions
            .OfType<X509SubjectAlternativeNameExtension>()
            .FirstOrDefault();

        if (san is null)
        {
            X509Extension? raw = certificate.Extensions
                .FirstOrDefault(static e => e.Oid?.Value == "2.5.29.17");

            if (raw is null)
            {
                return SubjectAlternativeNames.Empty;
            }

            san = new X509SubjectAlternativeNameExtension(raw.RawData, raw.Critical);
        }

        // Reuse the codec's SAN decomposition so certificate and CSR names are extracted by exactly
        // the same code, leaving no room for the two paths to disagree about what a name is.
        return Pkcs10CsrReader.ExtractSubjectAlternativeNames(san);
    }
}
