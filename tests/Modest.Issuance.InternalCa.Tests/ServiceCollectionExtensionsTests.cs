using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Modest.Core.Issuance;
using Modest.TestSupport;

namespace Modest.Issuance.InternalCa.Tests;

/// <summary>
/// The registration extension is what a host actually calls, so the binding of the
/// <c>Issuance:InternalCa</c> section is exercised through configuration rather than by hand.
/// </summary>
public sealed class ServiceCollectionExtensionsTests
{
    private static ServiceProvider BuildProvider(DiskCa ca, params (string Key, string Value)[] extra)
    {
        Dictionary<string, string?> settings = new(StringComparer.Ordinal)
        {
            ["Issuance:InternalCa:CertificatePath"] = ca.PfxPath,
            ["Issuance:InternalCa:CertificatePasswordFile"] = ca.PasswordPath,
            ["Issuance:InternalCa:AdditionalChainCertificatePaths:0"] = ca.RootPemPath,
        };

        foreach ((string key, string value) in extra)
        {
            settings[key] = value;
        }

        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddInternalCaIssuer(configuration);

        return services.BuildServiceProvider();
    }

    [Fact]
    public void AddInternalCaIssuer_ResolvesAWorkingIssuer()
    {
        using DiskCa ca = DiskCa.Create();
        using ServiceProvider provider = BuildProvider(ca);

        var issuer = provider.GetRequiredService<ICertificateIssuer>();

        issuer.ShouldBeOfType<InternalCaIssuer>();
    }

    [Fact]
    public void AddInternalCaIssuer_RegistersTheIssuerAsASingleton()
    {
        using DiskCa ca = DiskCa.Create();
        using ServiceProvider provider = BuildProvider(ca);

        // Two resolutions must share one loaded CA key rather than reading the PFX twice.
        provider.GetRequiredService<ICertificateIssuer>()
            .ShouldBeSameAs(provider.GetRequiredService<InternalCaIssuer>());
    }

    [Fact]
    public void AddInternalCaIssuer_BindsConfiguredValues()
    {
        using DiskCa ca = DiskCa.Create();
        using ServiceProvider provider = BuildProvider(
            ca,
            ("Issuance:InternalCa:ValidityPeriod", "30.00:00:00"),
            ("Issuance:InternalCa:MinimumRsaKeySizeBits", "3072"),
            ("Issuance:InternalCa:SignatureAlgorithm", "SHA384"),
            ("Issuance:InternalCa:CopySubjectAlternativeNames", "false"));

        InternalCaOptions options = provider.GetRequiredService<IOptions<InternalCaOptions>>().Value;

        options.ValidityPeriod.ShouldBe(TimeSpan.FromDays(30));
        options.MinimumRsaKeySizeBits.ShouldBe(3072);
        options.SignatureAlgorithm.ShouldBe("SHA384");
        options.CopySubjectAlternativeNames.ShouldBeFalse();
        options.AdditionalChainCertificatePaths.ShouldBe([ca.RootPemPath]);
    }

    [Fact]
    public void AddInternalCaIssuer_FailsToResolveWhenTheCertificatePathIsWrong()
    {
        using DiskCa ca = DiskCa.Create();
        using ServiceProvider provider = BuildProvider(
            ca, ("Issuance:InternalCa:CertificatePath", ca.Directory.MissingFile("absent.pfx")));

        // Resolution, not registration, is where the key is read; the host turns this into a
        // non-zero exit rather than starting a server that cannot sign.
        Exception ex = Should.Throw<Exception>(() => provider.GetRequiredService<ICertificateIssuer>());

        (ex as CaKeyLoadException ?? ex.InnerException as CaKeyLoadException).ShouldNotBeNull();
    }

    [Fact]
    public void AddInternalCaIssuer_RejectsAnEmptyCertificatePathThroughDataAnnotations()
    {
        using DiskCa ca = DiskCa.Create();
        using ServiceProvider provider = BuildProvider(ca, ("Issuance:InternalCa:CertificatePath", string.Empty));

        Should.Throw<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<InternalCaOptions>>().Value);
    }

    [Fact]
    public void AddInternalCaIssuer_ThrowsForNullArguments()
    {
        IConfiguration configuration = new ConfigurationBuilder().Build();

        Should.Throw<ArgumentNullException>(() => ((IServiceCollection)null!).AddInternalCaIssuer(configuration));
        Should.Throw<ArgumentNullException>(() => new ServiceCollection().AddInternalCaIssuer(null!));
    }
}
