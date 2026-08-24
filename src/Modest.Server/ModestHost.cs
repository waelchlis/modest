using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Modest.Core.Est;
using Modest.Core.Issuance;
using Modest.Issuance.HttpDelegate;
using Modest.Issuance.InternalCa;
using Modest.Server.Authentication;
using Modest.Server.Configuration;
using Modest.Server.Endpoints;

namespace Modest.Server;

/// <summary>
/// Builds the Modest application.
/// </summary>
/// <remarks>
/// Composition lives here rather than inline in <c>Program.cs</c> so that startup — including its
/// failure paths — can be exercised by tests without spawning a process.
/// </remarks>
public static class ModestHost
{
    /// <summary>Port on which EST is served over TLS, unless overridden by configuration.</summary>
    public const int DefaultEstPort = 8443;

    /// <summary>Port on which health endpoints are served over plain HTTP.</summary>
    public const int DefaultOpsPort = 8080;

    public static WebApplication Build(string[] args)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
        ConfigureServices(builder);
        ConfigureKestrel(builder);
        return BuildApp(builder);
    }

    public static void ConfigureServices(WebApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        IConfiguration configuration = builder.Configuration;
        IServiceCollection services = builder.Services;

        services.AddOptions<EstAuthenticationOptions>()
            .Bind(configuration.GetSection(EstAuthenticationOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<EstProtocolOptions>()
            .Bind(configuration.GetSection(EstProtocolOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<ReenrollmentOptions>()
            .Bind(configuration.GetSection(ReenrollmentOptions.SectionName));

        services.AddSingleton<IBasicCredentialValidator, StaticConfigBasicCredentialValidator>();
        services.AddSingleton<IClientCertificateValidator, ClientCertificateValidator>();
        services.AddSingleton<ReenrollmentIdentityChecker>();

        RegisterIssuer(services, configuration);

        services.AddRouting();
    }

    /// <summary>
    /// Registers exactly one issuer, chosen at startup by configuration.
    /// </summary>
    /// <remarks>
    /// One issuer per instance. Routing between several would be a multi-CA feature, which the
    /// RFC's optional <c>[label]</c> path segment exists for and which this version does not
    /// implement.
    /// </remarks>
    public static IssuanceMode RegisterIssuer(IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        IConfigurationSection section = configuration.GetSection(IssuanceSelectionOptions.SectionName);
        string? rawMode = section["Mode"];

        IssuanceMode mode;
        if (string.IsNullOrWhiteSpace(rawMode))
        {
            mode = IssuanceMode.InternalCa;
        }
        else if (!Enum.TryParse(rawMode, ignoreCase: true, out mode))
        {
            throw new InvalidOperationException(
                $"Issuance:Mode has the unrecognised value '{rawMode}'. " +
                $"Valid values are '{nameof(IssuanceMode.InternalCa)}' and '{nameof(IssuanceMode.HttpDelegate)}'.");
        }

        switch (mode)
        {
            case IssuanceMode.InternalCa:
                services.AddInternalCaIssuer(configuration);
                break;
            case IssuanceMode.HttpDelegate:
                services.AddHttpDelegateIssuer(configuration);
                break;
            default:
                throw new InvalidOperationException($"Unhandled issuance mode {mode}.");
        }

        return mode;
    }

    public static void ConfigureKestrel(WebApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        IConfiguration configuration = builder.Configuration;

        int estPort = configuration.GetValue("Kestrel:Est:Port", DefaultEstPort);
        int opsPort = configuration.GetValue("Kestrel:Ops:Port", DefaultOpsPort);
        string? certificatePath = configuration["Kestrel:Est:CertificatePath"];
        string? certificatePasswordFile = configuration["Kestrel:Est:CertificatePasswordFile"];

        builder.WebHost.ConfigureKestrel(options =>
        {
            // EST listener: TLS, and it asks for a client certificate without insisting on one.
            // Requiring one at the handshake would lock out both the unauthenticated bootstrap
            // operations and clients that authenticate with a username and password.
            options.ListenAnyIP(estPort, listen =>
            {
                listen.UseHttps(https =>
                {
                    https.ClientCertificateMode = ClientCertificateMode.AllowCertificate;

                    // CA5398 asks for SslProtocols.None so the OS chooses. Declined deliberately:
                    // RFC 7030 s3.1 sets a floor on the TLS version an EST server may accept, and an
                    // OS-chosen default can drift below it without anyone noticing. The floor is
                    // 1.2 rather than the RFC's 1.1 because 1.1 is deprecated and unavailable in
                    // modern .NET; that deviation is recorded in planning/01-rfc7030-reference.md.
#pragma warning disable CA5398
                    https.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
#pragma warning restore CA5398

                    // Validation is deferred to the EST authentication middleware, which can fall
                    // back to Basic credentials. Rejecting at the TLS layer would deny that fallback.
                    https.ClientCertificateValidation = static (_, _, _) => true;

                    X509Certificate2? serverCertificate =
                        LoadServerCertificate(certificatePath, certificatePasswordFile);

                    if (serverCertificate is not null)
                    {
                        https.ServerCertificate = serverCertificate;
                    }
                });
            });

            // Ops listener: plain HTTP, no TLS, no client certificate negotiation, so that probes
            // stay trivial. Bind it to a network the outside world cannot reach.
            options.ListenAnyIP(opsPort);
        });
    }

    public static WebApplication BuildApp(WebApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        WebApplication app = builder.Build();

        int opsPort = app.Configuration.GetValue("Kestrel:Ops:Port", DefaultOpsPort);

        app.UseMiddleware<EstAuthenticationMiddleware>();

        // Route isolation between the two listeners. Kestrel gives one route table to every
        // binding, so without this the EST endpoints would also answer on the plain-HTTP ops port —
        // handing out certificate enrollment with no transport security at all.
        app.MapWhen(
            context => IsOpsPort(context, opsPort),
            ops =>
            {
                ops.UseRouting();
                ops.UseEndpoints(static endpoints => endpoints.MapHealthEndpoints());
            });

        app.MapWhen(
            context => !IsOpsPort(context, opsPort),
            est =>
            {
                est.UseRouting();
                est.UseEndpoints(static endpoints => endpoints.MapEstEndpoints());
            });

        return app;
    }

    private static bool IsOpsPort(HttpContext context, int opsPort) =>
        context.Connection.LocalPort == opsPort;

    private static X509Certificate2? LoadServerCertificate(string? path, string? passwordFile)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            // Left to Kestrel's own configuration, which covers the ASP.NET Core dev certificate.
            return null;
        }

        if (!File.Exists(path))
        {
            throw new InvalidOperationException(
                $"The TLS server certificate was not found at '{path}'. Check Kestrel:Est:CertificatePath.");
        }

        string? password = null;
        if (!string.IsNullOrWhiteSpace(passwordFile))
        {
            if (!File.Exists(passwordFile))
            {
                throw new InvalidOperationException(
                    $"The TLS server certificate password file was not found at '{passwordFile}'.");
            }

            password = File.ReadAllText(passwordFile).TrimEnd('\r', '\n');
        }

        return X509CertificateLoader.LoadPkcs12FromFile(
            path, password, X509KeyStorageFlags.EphemeralKeySet);
    }
}
