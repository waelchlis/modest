using System.Security.Cryptography;
using System.Text;

namespace Modest.Core.Issuance;

/// <summary>
/// Derives the stable correlation key for an issuance request.
/// </summary>
/// <remarks>
/// RFC 7030 s4.2.3: after an HTTP 202, the client retries by resending a byte-identical request.
/// It carries no ticket, so the only thing that can tie a retry to the original attempt is the
/// request content itself — the CSR bytes plus who asked for it.
/// </remarks>
public static class CorrelationKey
{
    /// <summary>Computes the correlation key for a CSR and the identity that submitted it.</summary>
    public static string Compute(ReadOnlySpan<byte> pkcs10Der, ClientIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(pkcs10Der);
        hash.AppendData(Encoding.UTF8.GetBytes($"|{identity.Method}|{identity.Subject ?? string.Empty}"));
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }
}
