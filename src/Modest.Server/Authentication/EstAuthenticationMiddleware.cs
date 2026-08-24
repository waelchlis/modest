using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Options;
using Modest.Core.Issuance;
using Modest.Server.Configuration;

namespace Modest.Server.Authentication;

/// <summary>
/// Resolves the EST client identity for each request: TLS client certificate first, then HTTP
/// Basic, then anonymous.
/// </summary>
/// <remarks>
/// <para>
/// Written directly rather than as an <c>AuthenticationHandler</c> scheme. EST's model is
/// "try a certificate, else try Basic, else stay anonymous but restricted to the bootstrap
/// operations", evaluated inline. ASP.NET Core's authentication schemes are built around
/// challenge and redirect flows that do not fit that shape, and bending them to it would produce
/// more code that is harder to test than this.
/// </para>
/// <para>
/// A client certificate that fails validation falls through to Basic rather than failing the
/// request outright. The two mechanisms are independent in RFC 7030, so a client presenting a
/// certificate Modest does not trust, plus credentials it does, is legitimately authenticated.
/// </para>
/// </remarks>
public sealed class EstAuthenticationMiddleware
{
    /// <summary>Key under which the resolved identity is stored in <see cref="HttpContext.Items"/>.</summary>
    public const string IdentityItemKey = "EstClientIdentity";

    private readonly RequestDelegate _next;
    private readonly IBasicCredentialValidator _basicValidator;
    private readonly IClientCertificateValidator _certificateValidator;
    private readonly IOptionsMonitor<EstAuthenticationOptions> _options;
    private readonly ILogger<EstAuthenticationMiddleware> _logger;

    public EstAuthenticationMiddleware(
        RequestDelegate next,
        IBasicCredentialValidator basicValidator,
        IClientCertificateValidator certificateValidator,
        IOptionsMonitor<EstAuthenticationOptions> options,
        ILogger<EstAuthenticationMiddleware> logger)
    {
        _next = next;
        _basicValidator = basicValidator;
        _certificateValidator = certificateValidator;
        _options = options;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        context.Items[IdentityItemKey] = Resolve(context);
        await _next(context).ConfigureAwait(false);
    }

    private ClientIdentity Resolve(HttpContext context)
    {
        EstAuthenticationOptions options = _options.CurrentValue;

        ClientIdentity? fromCertificate = TryClientCertificate(context, options);
        if (fromCertificate is not null)
        {
            return fromCertificate;
        }

        ClientIdentity? fromBasic = TryHttpBasic(context, options);
        if (fromBasic is not null)
        {
            return fromBasic;
        }

        return ClientIdentity.Anonymous;
    }

    private ClientIdentity? TryClientCertificate(HttpContext context, EstAuthenticationOptions options)
    {
        if (!options.AllowClientCertificate)
        {
            return null;
        }

        X509Certificate2? certificate = context.Connection.ClientCertificate;
        if (certificate is null)
        {
            return null;
        }

        if (!_certificateValidator.Validate(certificate, out string? failureReason))
        {
            _logger.LogInformation(
                "Client certificate {Subject} was not accepted ({Reason}); falling back to other credentials.",
                certificate.Subject,
                failureReason);
            return null;
        }

        return new ClientIdentity(ClientAuthMethod.ClientCertificate, certificate.Subject, certificate);
    }

    private ClientIdentity? TryHttpBasic(HttpContext context, EstAuthenticationOptions options)
    {
        if (!options.AllowHttpBasic)
        {
            return null;
        }

        string? header = context.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(header))
        {
            return null;
        }

        if (!AuthenticationHeaderValue.TryParse(header, out AuthenticationHeaderValue? parsed) ||
            !string.Equals(parsed.Scheme, "Basic", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrEmpty(parsed.Parameter))
        {
            return null;
        }

        string decoded;
        try
        {
            decoded = Encoding.UTF8.GetString(Convert.FromBase64String(parsed.Parameter));
        }
        catch (FormatException)
        {
            return null;
        }

        int separator = decoded.IndexOf(':', StringComparison.Ordinal);
        if (separator < 0)
        {
            return null;
        }

        string username = decoded[..separator];
        string password = decoded[(separator + 1)..];

        if (!_basicValidator.Validate(username, password))
        {
            _logger.LogInformation("Basic authentication failed for user {Username}.", username);
            return null;
        }

        return new ClientIdentity(ClientAuthMethod.HttpBasic, username, null);
    }
}
