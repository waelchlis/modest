using System.Security.Cryptography.X509Certificates;
using Modest.Core.Issuance;
using Modest.TestSupport;

namespace Modest.Issuance.HttpDelegate.Tests;

/// <summary>
/// One CA, one leaf and one CSR, generated once for the whole assembly.
/// </summary>
/// <remarks>
/// RSA key generation dominates the runtime of this suite otherwise. Nothing here is mutated by a
/// test, and the issuer parses its own certificate instances out of PEM, so sharing is safe.
/// </remarks>
public static class SharedPki
{
    private static readonly Lazy<TestCertificateAuthority> LazyCa =
        new(static () => TestCertificateAuthority.CreateWithIntermediate(), isThreadSafe: true);

    private static readonly Lazy<X509Certificate2> LazyLeaf =
        new(static () => Ca.IssueLeaf("CN=device01.example.com"), isThreadSafe: true);

    private static readonly Lazy<byte[]> LazyCsr =
        new(static () => CsrFactory.CreateRsa("CN=device01.example.com"), isThreadSafe: true);

    /// <summary>A CA with a root and an intermediate; <c>Chain</c> is [intermediate, root].</summary>
    public static TestCertificateAuthority Ca => LazyCa.Value;

    /// <summary>A leaf certificate standing in for whatever the upstream would have issued.</summary>
    public static X509Certificate2 Leaf => LazyLeaf.Value;

    /// <summary>A well-formed 2048-bit RSA PKCS#10 CSR in DER form.</summary>
    public static byte[] CsrDer => LazyCsr.Value;

    /// <summary>Builds the issuance request the EST layer would hand to the issuer.</summary>
    public static IssuanceRequest RequestFor(byte[] der)
    {
        ClientIdentity identity = ClientIdentity.Anonymous;
        return new IssuanceRequest(
            der,
            Core.Est.EstOperation.Enroll,
            identity,
            CorrelationKey.Compute(der, identity));
    }

    /// <summary>The standard request, built over <see cref="CsrDer"/>.</summary>
    public static IssuanceRequest Request() => RequestFor(CsrDer);
}
