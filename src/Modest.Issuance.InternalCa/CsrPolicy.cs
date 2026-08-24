using Modest.Codec;
using Modest.Core.Issuance;

namespace Modest.Issuance.InternalCa;

/// <summary>
/// Local CA policy applied to a CSR before anything is signed.
/// </summary>
public static class CsrPolicy
{
    /// <summary>
    /// Checks a CSR against policy.
    /// </summary>
    /// <returns>A rejection when the CSR is unacceptable, or null when it passes.</returns>
    public static IssuanceResult.Rejected? Evaluate(ParsedCsr csr, InternalCaOptions options)
    {
        ArgumentNullException.ThrowIfNull(csr);
        ArgumentNullException.ThrowIfNull(options);

        if (Pkcs10CsrReader.IsRsa(csr))
        {
            return EvaluateRsa(csr, options);
        }

        if (Pkcs10CsrReader.IsEllipticCurve(csr))
        {
            return EvaluateEc(csr, options);
        }

        return Reject(
            $"Public key algorithm {csr.PublicKeyAlgorithmOid} is not supported. Use RSA or ECDSA.");
    }

    private static IssuanceResult.Rejected? EvaluateRsa(ParsedCsr csr, InternalCaOptions options)
    {
        if (!options.AllowRsa)
        {
            return Reject("RSA keys are not accepted by this certificate authority.");
        }

        int keySize = Pkcs10CsrReader.GetKeySizeBits(csr);
        if (keySize < options.MinimumRsaKeySizeBits)
        {
            return Reject(
                $"CSR public key type RSA-{keySize} is below the configured minimum of RSA-{options.MinimumRsaKeySizeBits}.");
        }

        return EvaluateIdentity(csr, options);
    }

    private static IssuanceResult.Rejected? EvaluateEc(ParsedCsr csr, InternalCaOptions options)
    {
        if (!options.AllowEllipticCurve)
        {
            return Reject("Elliptic curve keys are not accepted by this certificate authority.");
        }

        string? curve = Pkcs10CsrReader.GetCurveName(csr);
        if (curve is null)
        {
            return Reject("The CSR uses an elliptic curve that could not be identified. Use a named curve.");
        }

        // Compared through the normaliser so that an allow-list written as "P-256", "prime256v1" or
        // "1.2.840.10045.3.1.7" all match, and so the comparison does not depend on which spelling
        // the host platform happens to report.
        bool allowed = options.EffectiveAllowedEllipticCurves
            .Any(c => EllipticCurveNames.AreSameCurve(c, curve));

        if (!allowed)
        {
            return Reject(
                $"Elliptic curve {curve} is not accepted. Allowed curves: {string.Join(", ", options.EffectiveAllowedEllipticCurves)}.");
        }

        return EvaluateIdentity(csr, options);
    }

    private static IssuanceResult.Rejected? EvaluateIdentity(ParsedCsr csr, InternalCaOptions options)
    {
        if (!options.RequireSubjectOrSan)
        {
            return null;
        }

        bool hasSubject = !string.IsNullOrWhiteSpace(csr.Subject.Name);
        if (!hasSubject && csr.SubjectAlternativeNames.IsEmpty)
        {
            return Reject(
                "The CSR requests neither a subject distinguished name nor any subject alternative name, " +
                "so the resulting certificate would identify nobody.");
        }

        return null;
    }

    private static IssuanceResult.Rejected Reject(string reason) =>
        new(reason, IssuanceRejectionKind.InvalidCsr);
}
