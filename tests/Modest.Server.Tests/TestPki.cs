using System.Security.Cryptography.X509Certificates;
using Modest.TestSupport;

namespace Modest.Server.Tests;

/// <summary>
/// One certificate authority and one TLS server certificate, generated once for the whole assembly.
/// </summary>
/// <remarks>
/// <para>
/// These tests start real Kestrel listeners, so every host needs a real server certificate and every
/// mutual-TLS test needs a real client certificate. Generating a fresh 3072-bit CA per host would
/// dominate the runtime of the suite, and nothing here is mutated by a test: the server loads its
/// certificate from an exported PFX, and clients hold their own instances.
/// </para>
/// <para>
/// The CA has an intermediate deliberately. A root-only CA would let a chain bug pass unnoticed —
/// the interesting ordering questions in <c>/cacerts</c> and in enrollment responses only exist when
/// there is more than one certificate to order.
/// </para>
/// </remarks>
public static class TestPki
{
    /// <summary>Password used for every PFX this suite writes to disk.</summary>
    public const string PfxPassword = "modest-test-password";

    private static readonly Lazy<TestCertificateAuthority> LazyCa =
        new(static () => TestCertificateAuthority.CreateWithIntermediate(), isThreadSafe: true);

    private static readonly Lazy<X509Certificate2> LazyServerCertificate =
        new(static () => Ca.IssueServerCertificate("CN=localhost", "localhost"), isThreadSafe: true);

    private static readonly Lazy<byte[]> LazyServerPfx =
        new(static () => ServerCertificate.Export(X509ContentType.Pfx, PfxPassword), isThreadSafe: true);

    /// <summary>The shared CA. <c>Chain</c> is [intermediate, root]; the intermediate signs leaves.</summary>
    public static TestCertificateAuthority Ca => LazyCa.Value;

    /// <summary>The TLS certificate every harness serves the EST listener with.</summary>
    public static X509Certificate2 ServerCertificate => LazyServerCertificate.Value;

    /// <summary>The same certificate as a PKCS#12 blob, for Kestrel's file-based configuration.</summary>
    public static byte[] ServerPfx => LazyServerPfx.Value;

    /// <summary>
    /// Builds a chain for <paramref name="leaf"/> anchored on <paramref name="anchors"/> and nothing
    /// else, so a test proves the leaf chains to the advertised CA rather than to whatever the
    /// machine happens to trust.
    /// </summary>
    public static (bool Built, string Status) TryBuildChain(
        X509Certificate2 leaf, IEnumerable<X509Certificate2> anchors)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

        foreach (X509Certificate2 anchor in anchors)
        {
            chain.ChainPolicy.CustomTrustStore.Add(anchor);
        }

        bool built = chain.Build(leaf);
        string status = string.Join(
            "; ",
            chain.ChainStatus.Select(static s => $"{s.Status}: {s.StatusInformation.Trim()}"));

        return (built, status);
    }
}
