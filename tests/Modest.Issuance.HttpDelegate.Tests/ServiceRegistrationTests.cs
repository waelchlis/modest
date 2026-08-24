using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Modest.Core.Issuance;

namespace Modest.Issuance.HttpDelegate.Tests;

/// <summary>
/// The DI extension itself: what it registers, and what it refuses to accept.
/// </summary>
public sealed class ServiceRegistrationTests
{
    [Fact]
    public void The_issuer_is_registered_as_a_singleton_behind_ICertificateIssuer()
    {
        using var harness = IssuerHarness.Create();

        harness.AsInterface.ShouldBeOfType<HttpDelegateIssuer>();

        // One instance, not two: the cached CA chain and the named HttpClient both assume it.
        harness.AsInterface.ShouldBeSameAs(harness.Issuer);
        harness.Issuer.ShouldBeSameAs(harness.Issuer);
    }

    [Fact]
    public void Options_bind_from_the_Issuance_HttpDelegate_section()
    {
        HttpDelegateOptions options = BuildOptions(new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["Issuance:HttpDelegate:BaseAddress"] = "https://ca.example.com",
            ["Issuance:HttpDelegate:IssuePath"] = "/pki/enroll",
            ["Issuance:HttpDelegate:StaticCaChainPath"] = "/etc/modest/chain.pem",
            ["Issuance:HttpDelegate:BasicAuthUsername"] = "modest",
            ["Issuance:HttpDelegate:TimeoutSeconds"] = "12",
            ["Issuance:HttpDelegate:MaxRetryAttempts"] = "5",
            ["Issuance:HttpDelegate:MaxCsrSizeBytes"] = "4096",
        });

        options.BaseAddress.ShouldBe("https://ca.example.com");
        options.IssuePath.ShouldBe("/pki/enroll");
        options.StaticCaChainPath.ShouldBe("/etc/modest/chain.pem");
        options.BasicAuthUsername.ShouldBe("modest");
        options.TimeoutSeconds.ShouldBe(12);
        options.MaxRetryAttempts.ShouldBe(5);
        options.MaxCsrSizeBytes.ShouldBe(4096);
    }

    [Fact]
    public void Options_carry_the_documented_defaults()
    {
        HttpDelegateOptions options = BuildOptions(new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["Issuance:HttpDelegate:BaseAddress"] = "https://ca.example.com",
            ["Issuance:HttpDelegate:StaticCaChainPath"] = "/etc/modest/chain.pem",
        });

        options.IssuePath.ShouldBe("/api/v1/issue");
        options.TimeoutSeconds.ShouldBe(30);
        options.MaxCsrSizeBytes.ShouldBe(16 * 1024);
    }

    [Theory]
    [InlineData("BaseAddress")]
    [InlineData("StaticCaChainPath")]
    public void A_missing_required_setting_fails_validation(string omitted)
    {
        var settings = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["Issuance:HttpDelegate:BaseAddress"] = "https://ca.example.com",
            ["Issuance:HttpDelegate:StaticCaChainPath"] = "/etc/modest/chain.pem",
        };
        settings.Remove("Issuance:HttpDelegate:" + omitted);

        Should.Throw<OptionsValidationException>(() => BuildOptions(settings));
    }

    [Fact]
    public void A_non_URL_base_address_fails_validation()
    {
        Should.Throw<OptionsValidationException>(() => BuildOptions(
            new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["Issuance:HttpDelegate:BaseAddress"] = "not a url",
                ["Issuance:HttpDelegate:StaticCaChainPath"] = "/etc/modest/chain.pem",
            }));
    }

    [Fact]
    public void A_configured_password_file_that_does_not_exist_fails_loudly()
    {
        // Failing at the first enrollment with a 401 nobody can explain is worse than failing here.
        using var harness = IssuerHarness.Create(writePasswordFile: false);

        Should.Throw<PkiConfigurationException>(
            () => harness.Issuer.IssueAsync(SharedPki.Request(), CancellationToken.None).GetAwaiter().GetResult());
    }

    private static HttpDelegateOptions BuildOptions(Dictionary<string, string?> settings)
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHttpDelegateIssuer(configuration);

        using ServiceProvider provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IOptions<HttpDelegateOptions>>().Value;
    }
}
