using System.Security.Cryptography.X509Certificates;
using Modest.TestSupport;

namespace Modest.Issuance.InternalCa.Tests;

/// <summary>
/// Loading the CA key is startup-fatal work: every failure has to surface as a
/// <see cref="CaKeyLoadException"/> carrying something an operator can act on, because epic 4's
/// Program.cs catches exactly this type and exits non-zero with that message.
/// </summary>
public sealed class CaKeyLoaderTests
{
    // ------------------------------------------------------------------ happy path

    [Fact]
    public void Load_ReadsTheIssuingCertificateFromThePfx()
    {
        using DiskCa ca = DiskCa.Create();

        CaMaterial material = Test.Loader().Load(ca.Options(o => o.AdditionalChainCertificatePaths = []));

        material.Certificate.Subject.ShouldBe(ca.Ca.Issuer.Subject);
        material.Certificate.Thumbprint.ShouldBe(ca.Ca.Issuer.Thumbprint);
        material.Certificate.HasPrivateKey.ShouldBeTrue();
        material.AdditionalChain.ShouldBeEmpty();
        material.FullChain.Count.ShouldBe(1);
    }

    [Fact]
    public void Load_PutsTheSigningCaFirstAndAdditionalChainCertificatesAfterIt()
    {
        using DiskCa ca = DiskCa.Create();

        CaMaterial material = Test.Loader().Load(ca.Options());

        material.FullChain.Count.ShouldBe(2);
        material.FullChain[0].Thumbprint.ShouldBe(ca.Ca.Intermediate!.Thumbprint);
        material.FullChain[1].Thumbprint.ShouldBe(ca.Ca.Root.Thumbprint);
    }

    [Fact]
    public void Load_AcceptsAPemFileHoldingSeveralCertificates()
    {
        using DiskCa ca = DiskCa.Create();
        string bundle = ca.Ca.WriteChainPem(ca.Directory.Path, "bundle.pem");

        CaMaterial material = Test.Loader()
            .Load(ca.Options(o => o.AdditionalChainCertificatePaths = [bundle]));

        // The bundle is issuer+root, so the full chain is the signing CA followed by both.
        material.FullChain.Count.ShouldBe(3);
        material.FullChain[0].Thumbprint.ShouldBe(ca.Ca.Issuer.Thumbprint);
        material.FullChain[1].Thumbprint.ShouldBe(ca.Ca.Intermediate!.Thumbprint);
        material.FullChain[2].Thumbprint.ShouldBe(ca.Ca.Root.Thumbprint);
    }

    [Fact]
    public void Load_AcceptsAPasswordFileWithATrailingNewline()
    {
        // Shell redirection and Kubernetes secrets both append one; treating it as part of the
        // password would be an unexplainable "wrong password" for a correctly configured operator.
        using DiskCa ca = DiskCa.Create();
        File.WriteAllText(ca.PasswordPath, DiskCa.Password + "\n");

        Should.NotThrow(() => Test.Loader().Load(ca.Options()));
    }

    [Fact]
    public void Load_AcceptsAPasswordFileWithATrailingCarriageReturnNewline()
    {
        using DiskCa ca = DiskCa.Create();
        File.WriteAllText(ca.PasswordPath, DiskCa.Password + "\r\n");

        Should.NotThrow(() => Test.Loader().Load(ca.Options()));
    }

    [Fact]
    public void Load_DoesNotTrimLeadingWhitespaceFromThePassword()
    {
        // Only trailing newlines are forgiven. A password that genuinely starts with a space is
        // still that password; silently trimming both ends would weaken a legitimate secret.
        using DiskCa ca = DiskCa.Create(password: " padded ");
        File.WriteAllText(ca.PasswordPath, " padded ");

        Should.NotThrow(() => Test.Loader().Load(ca.Options()));
    }

    [Fact]
    public void Load_AcceptsAPfxWithNoPasswordWhenNoPasswordFileIsConfigured()
    {
        using DiskCa ca = DiskCa.Create(password: string.Empty);

        CaMaterial material = Test.Loader().Load(ca.Options(o =>
        {
            o.CertificatePasswordFile = null;
            o.AdditionalChainCertificatePaths = [];
        }));

        material.Certificate.HasPrivateKey.ShouldBeTrue();
    }

    // ------------------------------------------------------------------ failure paths

    [Fact]
    public void Load_ThrowsWhenThePfxIsMissing()
    {
        using DiskCa ca = DiskCa.Create();
        string missing = ca.Directory.MissingFile("nope.pfx");

        CaKeyLoadException ex = Should.Throw<CaKeyLoadException>(
            () => Test.Loader().Load(ca.Options(o => o.CertificatePath = missing)));

        ex.Message.ShouldContain(missing);
        ex.Message.ShouldContain("CertificatePath");
    }

    [Fact]
    public void Load_ThrowsWhenThePasswordIsWrong()
    {
        using DiskCa ca = DiskCa.Create();
        File.WriteAllText(ca.PasswordPath, "not-the-password");

        CaKeyLoadException ex = Should.Throw<CaKeyLoadException>(() => Test.Loader().Load(ca.Options()));

        ex.Message.ShouldContain(ca.PfxPath);
        ex.Message.ShouldContain("password", Case.Insensitive);
        ex.InnerException.ShouldNotBeNull();
    }

    [Fact]
    public void Load_ThrowsWhenNoPasswordIsSuppliedForAnEncryptedPfx()
    {
        using DiskCa ca = DiskCa.Create();

        Should.Throw<CaKeyLoadException>(
            () => Test.Loader().Load(ca.Options(o => o.CertificatePasswordFile = null)));
    }

    [Fact]
    public void Load_ThrowsWhenThePasswordFileIsMissing()
    {
        using DiskCa ca = DiskCa.Create();
        string missing = ca.Directory.MissingFile("ca.pass.absent");

        CaKeyLoadException ex = Should.Throw<CaKeyLoadException>(
            () => Test.Loader().Load(ca.Options(o => o.CertificatePasswordFile = missing)));

        ex.Message.ShouldContain(missing);
        ex.Message.ShouldContain("password", Case.Insensitive);
    }

    [Fact]
    public void Load_ThrowsWhenAnAdditionalChainFileIsMissing()
    {
        using DiskCa ca = DiskCa.Create();
        string missing = ca.Directory.MissingFile("intermediate.pem");

        CaKeyLoadException ex = Should.Throw<CaKeyLoadException>(
            () => Test.Loader().Load(ca.Options(o => o.AdditionalChainCertificatePaths = [missing])));

        ex.Message.ShouldContain(missing);
    }

    [Fact]
    public void Load_ThrowsWhenAnAdditionalChainFileIsNotACertificate()
    {
        using DiskCa ca = DiskCa.Create();
        string garbage = ca.Directory.File("garbage.pem");
        File.WriteAllText(garbage, "this file is not a certificate at all\n");

        CaKeyLoadException ex = Should.Throw<CaKeyLoadException>(
            () => Test.Loader().Load(ca.Options(o => o.AdditionalChainCertificatePaths = [garbage])));

        ex.Message.ShouldContain(garbage);
    }

    [Fact]
    public void Load_ThrowsWhenThePfxIsCorrupt()
    {
        using DiskCa ca = DiskCa.Create();
        File.WriteAllBytes(ca.PfxPath, [0x00, 0x01, 0x02, 0x03, 0x04]);

        Should.Throw<CaKeyLoadException>(() => Test.Loader().Load(ca.Options()));
    }

    [Fact]
    public void Load_ThrowsWhenThePfxHasNoPrivateKey()
    {
        // A cert-only PFX: nothing to sign with, so this must fail at startup rather than at the
        // first enrollment.
        using DiskCa ca = DiskCa.Create();
        using X509Certificate2 publicOnly = X509CertificateLoader.LoadCertificate(ca.Ca.Issuer.RawData);
        File.WriteAllBytes(ca.PfxPath, publicOnly.Export(X509ContentType.Pfx, DiskCa.Password));

        CaKeyLoadException ex = Should.Throw<CaKeyLoadException>(() => Test.Loader().Load(ca.Options()));

        ex.Message.ShouldContain("private key", Case.Insensitive);
    }

    [Fact]
    public void Load_RefusesACertificateThatIsNotACertificateAuthority()
    {
        using DiskCa ca = DiskCa.Create();
        using X509Certificate2 leaf = ca.Ca.IssueLeaf("CN=not-a-ca.example.com");
        File.WriteAllBytes(ca.PfxPath, leaf.Export(X509ContentType.Pfx, DiskCa.Password));

        CaKeyLoadException ex = Should.Throw<CaKeyLoadException>(() => Test.Loader().Load(ca.Options()));

        ex.Message.ShouldContain("CA=false");
    }

    [Fact]
    public void Load_ThrowsArgumentNullExceptionForNullOptions()
    {
        Should.Throw<ArgumentNullException>(() => Test.Loader().Load(null!));
    }

    // ------------------------------------------------------------------ permission warning

    [Fact]
    public void Load_WarnsWhenKeyMaterialIsReadableBeyondItsOwner()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using DiskCa ca = DiskCa.Create();
        File.SetUnixFileMode(
            ca.PfxPath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

        var logger = new CapturingLogger<CaKeyLoader>();
        new CaKeyLoader(logger).Load(ca.Options());

        logger.Text.ShouldContain("[Warning]");
        logger.Text.ShouldContain(ca.PfxPath);
    }

    [Fact]
    public void Load_DoesNotWarnWhenKeyMaterialIsOwnerOnly()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using DiskCa ca = DiskCa.Create();
        File.SetUnixFileMode(ca.PfxPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.SetUnixFileMode(ca.PasswordPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.SetUnixFileMode(ca.RootPemPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        var logger = new CapturingLogger<CaKeyLoader>();
        new CaKeyLoader(logger).Load(ca.Options());

        logger.Text.ShouldNotContain("[Warning]");
    }

    [Fact]
    public void Load_NeverLogsThePasswordOrPrivateKeyMaterial()
    {
        using DiskCa ca = DiskCa.Create();
        var logger = new CapturingLogger<CaKeyLoader>();

        new CaKeyLoader(logger).Load(ca.Options());

        logger.Text.ShouldNotContain(DiskCa.Password);
        foreach (string secret in Test.PrivateKeyFingerprints(ca.Ca.Issuer))
        {
            logger.Text.ShouldNotContain(secret);
        }
    }
}
