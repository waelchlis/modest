using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Modest.Core.Issuance;

namespace Modest.Issuance.InternalCa;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the internal CA issuer, which signs certificates with a locally held CA key.
    /// </summary>
    public static IServiceCollection AddInternalCaIssuer(
        this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services
            .AddOptions<InternalCaOptions>()
            .Bind(configuration.GetSection(InternalCaOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddSingleton<CaKeyLoader>();
        services.AddSingleton<InternalCaIssuer>();
        services.AddSingleton<ICertificateIssuer>(sp => sp.GetRequiredService<InternalCaIssuer>());

        return services;
    }
}
