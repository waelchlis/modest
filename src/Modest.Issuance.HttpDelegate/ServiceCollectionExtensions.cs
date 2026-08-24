using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Modest.Core.Issuance;
using Polly;

namespace Modest.Issuance.HttpDelegate;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the delegating issuer, which forwards CSRs to an external HTTP issuance API.
    /// </summary>
    public static IServiceCollection AddHttpDelegateIssuer(
        this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services
            .AddOptions<HttpDelegateOptions>()
            .Bind(configuration.GetSection(HttpDelegateOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services
            .AddHttpClient(HttpDelegateIssuer.HttpClientName, (sp, client) =>
            {
                HttpDelegateOptions options = sp.GetRequiredService<IOptions<HttpDelegateOptions>>().Value;

                client.BaseAddress = new Uri(options.BaseAddress, UriKind.Absolute);

                // Left generous relative to the resilience pipeline's per-attempt timeout below, which
                // is the one that actually governs an attempt. This is only a final backstop.
                client.Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds * 4);

                AuthenticationHeaderValue? basic = BuildBasicAuthHeader(options);
                if (basic is not null)
                {
                    client.DefaultRequestHeaders.Authorization = basic;
                }
            })
            .AddResilienceHandler("modest-issuance", (builder, context) =>
            {
                HttpDelegateOptions options = context.ServiceProvider
                    .GetRequiredService<IOptions<HttpDelegateOptions>>().Value;

                // Polly rejects MaxRetryAttempts below 1, and does so when the strategy first runs
                // rather than at startup — so configuring 0, which this option documents as the
                // legal way to say "never retry", would blow up on the first enrollment instead.
                // An operator fronting a non-idempotent CA has good reason to set it, so honour it
                // by omitting the retry strategy entirely.
                if (options.MaxRetryAttempts > 0)
                {
                    builder.AddRetry(new Microsoft.Extensions.Http.Resilience.HttpRetryStrategyOptions
                    {
                        MaxRetryAttempts = options.MaxRetryAttempts,
                        BackoffType = DelayBackoffType.Exponential,
                        UseJitter = true,
                        Delay = TimeSpan.FromMilliseconds(500),

                        // Retry only what a retry can fix. A 4xx is the upstream deliberately refusing
                        // this CSR; repeating it cannot change the answer, and would duplicate work — or
                        // duplicate issuance — against an upstream that is not idempotent.
                        ShouldHandle = args => ValueTask.FromResult(
                            args.Outcome.Exception is HttpRequestException ||
                            args.Outcome.Result is { StatusCode: >= HttpStatusCode.InternalServerError } ||
                            args.Outcome.Result is { StatusCode: HttpStatusCode.RequestTimeout }),
                    });
                }

                builder.AddTimeout(TimeSpan.FromSeconds(options.TimeoutSeconds));
            });

        services.AddSingleton<HttpDelegateIssuer>();
        services.AddSingleton<ICertificateIssuer>(sp => sp.GetRequiredService<HttpDelegateIssuer>());

        return services;
    }

    private static AuthenticationHeaderValue? BuildBasicAuthHeader(HttpDelegateOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.BasicAuthUsername))
        {
            return null;
        }

        string password = ReadPassword(options.BasicAuthPasswordFile);
        string credential = Convert.ToBase64String(
            Encoding.UTF8.GetBytes($"{options.BasicAuthUsername}:{password}"));

        return new AuthenticationHeaderValue("Basic", credential);
    }

    private static string ReadPassword(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        if (!File.Exists(path))
        {
            throw new PkiConfigurationException(
                $"The upstream Basic authentication password file was not found at '{path}'.");
        }

        // Trailing newline stripped: shell redirection and Kubernetes secrets both add one, and
        // silently sending it as part of the password produces a baffling 401.
        return File.ReadAllText(path).TrimEnd('\r', '\n');
    }
}
