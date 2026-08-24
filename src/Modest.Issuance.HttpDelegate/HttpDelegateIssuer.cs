using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Modest.Core.Issuance;
using Polly.Timeout;

namespace Modest.Issuance.HttpDelegate;

/// <summary>
/// Issues certificates by forwarding the CSR to an external HTTP API.
/// </summary>
/// <remarks>
/// No CA private key exists on this host in this mode; that is the point of it. Modest acts as an
/// EST protocol front end onto whatever PKI already issues certificates in the environment.
/// </remarks>
public sealed class HttpDelegateIssuer : ICertificateIssuer, IDisposable
{
    /// <summary>Name of the <see cref="IHttpClientFactory"/> client used for upstream calls.</summary>
    public const string HttpClientName = "modest-issuance-upstream";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly HttpDelegateOptions _options;
    private readonly ILogger<HttpDelegateIssuer> _logger;
    private readonly Lazy<IReadOnlyList<X509Certificate2>> _caChain;
    private bool _disposed;

    /// <summary>
    /// Serialiser settings for the outbound call.
    /// </summary>
    /// <remarks>
    /// The default web encoder escapes '+' as + as armour against HTML embedding. That is
    /// valid JSON and any conforming parser decodes it, but base64 produces '+' in almost every
    /// CSR, and this payload goes to a third-party API that may parse it by hand rather than into
    /// a browser. Emitting the plain characters keeps the body byte-for-byte what the contract
    /// documents.
    /// </remarks>
    private static readonly JsonSerializerOptions OutboundJson = new(JsonSerializerDefaults.Web)
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public HttpDelegateIssuer(
        IHttpClientFactory httpClientFactory,
        IOptions<HttpDelegateOptions> options,
        ILogger<HttpDelegateIssuer> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _logger = logger;
        _caChain = new Lazy<IReadOnlyList<X509Certificate2>>(LoadStaticCaChain);
    }

    /// <inheritdoc />
    public Task<CaChainResult> GetCaChainAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new CaChainResult(_caChain.Value));

    /// <inheritdoc />
    public Task<bool> IsReadyAsync(CancellationToken cancellationToken)
    {
        // Deliberately local: probing the upstream on every readiness check would let a transient
        // blip upstream cycle this pod, turning someone else's brief outage into our own.
        try
        {
            return Task.FromResult(_caChain.Value.Count > 0);
        }
        catch (PkiConfigurationException)
        {
            return Task.FromResult(false);
        }
    }

    /// <inheritdoc />
    public async Task<IssuanceResult> IssueAsync(
        IssuanceRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (request.Pkcs10Der.Length > _options.MaxCsrSizeBytes)
        {
            return new IssuanceResult.Rejected(
                $"The certificate signing request is {request.Pkcs10Der.Length} bytes, above the {_options.MaxCsrSizeBytes} byte limit.",
                IssuanceRejectionKind.InvalidCsr);
        }

        var payload = new IssuanceApiRequest(Convert.ToBase64String(request.Pkcs10Der.Span));

        HttpResponseMessage response;
        try
        {
            HttpClient client = _httpClientFactory.CreateClient(HttpClientName);
            response = await client
                .PostAsJsonAsync(_options.IssuePath, payload, OutboundJson, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Upstream issuance API at {Path} could not be reached.", _options.IssuePath);
            return new IssuanceResult.Rejected(
                "The upstream certificate authority could not be reached.",
                IssuanceRejectionKind.UpstreamUnavailable);
        }
        catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            _logger.LogError(ex, "Upstream issuance API at {Path} timed out.", _options.IssuePath);
            return new IssuanceResult.Rejected(
                "The upstream certificate authority did not respond in time.",
                IssuanceRejectionKind.UpstreamUnavailable);
        }
        catch (TimeoutRejectedException ex)
        {
            // The resilience pipeline's per-attempt timeout throws this rather than
            // TaskCanceledException, and it derives from ExecutionRejectedException, so neither
            // handler above catches it. A slow upstream is the likeliest production failure there
            // is, and it is exactly what TimeoutSeconds exists to bound — letting this escape would
            // turn the handled case into a 500.
            _logger.LogError(
                ex,
                "Upstream issuance API at {Path} exceeded the {Timeout}s per-attempt timeout.",
                _options.IssuePath,
                _options.TimeoutSeconds);

            return new IssuanceResult.Rejected(
                "The upstream certificate authority did not respond in time.",
                IssuanceRejectionKind.UpstreamUnavailable);
        }

        using (response)
        {
            return await InterpretAsync(response, request, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<IssuanceResult> InterpretAsync(
        HttpResponseMessage response, IssuanceRequest request, CancellationToken cancellationToken)
    {
        if (!response.IsSuccessStatusCode)
        {
            return await RejectFromStatusAsync(response, cancellationToken).ConfigureAwait(false);
        }

        IssuanceApiResponse? body;
        try
        {
            body = await response.Content
                .ReadFromJsonAsync<IssuanceApiResponse>(cancellationToken)
                .ConfigureAwait(false);
        }
        catch (JsonException ex)
        {
            // A 200 carrying unparseable JSON is a contract violation upstream, not a client
            // mistake. Log it loudly — retrying the same CSR will not help until someone fixes it.
            _logger.LogError(ex, "Upstream issuance API returned a 200 with a body that is not valid JSON.");
            return new IssuanceResult.Rejected(
                "The upstream certificate authority returned an unparseable response.",
                IssuanceRejectionKind.InvalidCsr);
        }

        if (body is null || string.IsNullOrWhiteSpace(body.Certificate))
        {
            _logger.LogError(
                "Upstream issuance API returned a 200 without a 'certificate' field.");
            return new IssuanceResult.Rejected(
                "The upstream certificate authority returned a response with no certificate.",
                IssuanceRejectionKind.InvalidCsr);
        }

        try
        {
            X509Certificate2 leaf = LoadSinglePem(body.Certificate, "certificate");

            IReadOnlyList<X509Certificate2> chain;
            if (string.IsNullOrWhiteSpace(body.Issuer))
            {
                chain = [];
            }
            else
            {
                chain = LoadPemChain(body.Issuer);

                // ImportFromPem ignores input it does not recognise as a PEM block rather than
                // failing, so unparseable content yields an empty collection instead of an
                // exception. Without this guard the client would receive a leaf with no path to a
                // root and no indication anything went wrong.
                if (chain.Count == 0)
                {
                    throw new PkiConfigurationException(
                        "The 'issuer' field was present but contained no parseable PEM certificate.");
                }
            }

            _logger.LogInformation(
                "Upstream issued certificate {Serial} for {Subject} ({Operation}) to {Identity}.",
                leaf.SerialNumber,
                leaf.Subject,
                request.Operation,
                request.Identity.Subject ?? "anonymous");

            return new IssuanceResult.Issued(leaf, chain);
        }
        catch (PkiConfigurationException ex)
        {
            _logger.LogError(ex, "Upstream issuance API returned PEM that could not be parsed.");
            return new IssuanceResult.Rejected(
                "The upstream certificate authority returned a certificate that could not be parsed.",
                IssuanceRejectionKind.InvalidCsr);
        }
    }

    private async Task<IssuanceResult> RejectFromStatusAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        string detail = await SafeReadAsync(response, cancellationToken).ConfigureAwait(false);

        // A 401 or 403 from upstream means *our* credentials were refused, not the client's. Reporting
        // that to the EST client as "forbidden" would blame them for our misconfiguration, and would
        // send an operator looking at the wrong end of the system. It is a gateway fault.
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
        {
            _logger.LogError(
                "Upstream issuance API rejected Modest's own credentials with {Status}. " +
                "Check Issuance:HttpDelegate:BasicAuthUsername and the password file.",
                (int)response.StatusCode);

            return new IssuanceResult.Rejected(
                "The upstream certificate authority is unavailable.",
                IssuanceRejectionKind.UpstreamUnavailable);
        }

        // Any other 4xx is the upstream applying its own policy: a deliberate refusal of this CSR.
        // 5xx is the upstream being broken, which we surface as a bad gateway.
        if ((int)response.StatusCode is >= 400 and < 500)
        {
            _logger.LogInformation(
                "Upstream issuance API declined the request with {Status}: {Detail}",
                (int)response.StatusCode,
                detail);

            return new IssuanceResult.Rejected(
                "The upstream certificate authority declined to issue a certificate for this request.",
                IssuanceRejectionKind.PolicyDenied);
        }

        _logger.LogError(
            "Upstream issuance API failed with {Status}: {Detail}",
            (int)response.StatusCode,
            detail);

        return new IssuanceResult.Rejected(
            "The upstream certificate authority is unavailable.",
            IssuanceRejectionKind.UpstreamUnavailable);
    }

    private static async Task<string> SafeReadAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            string content = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return content.Length > 512 ? content[..512] : content;
        }
        catch (HttpRequestException)
        {
            return "<unreadable>";
        }
        catch (TaskCanceledException)
        {
            return "<unreadable>";
        }
    }

    private IReadOnlyList<X509Certificate2> LoadStaticCaChain()
    {
        if (!File.Exists(_options.StaticCaChainPath))
        {
            throw new PkiConfigurationException(
                $"The configured CA chain file was not found at '{_options.StaticCaChainPath}'. " +
                "In delegated mode this file supplies the /cacerts response, which clients need before their first enrollment.");
        }

        string pem = File.ReadAllText(_options.StaticCaChainPath);
        IReadOnlyList<X509Certificate2> chain = LoadPemChain(pem);

        if (chain.Count == 0)
        {
            throw new PkiConfigurationException(
                $"The CA chain file at '{_options.StaticCaChainPath}' contains no certificates.");
        }

        return chain;
    }

    private static X509Certificate2 LoadSinglePem(string pem, string fieldName)
    {
        IReadOnlyList<X509Certificate2> certificates = LoadPemChain(pem);

        if (certificates.Count == 0)
        {
            throw new PkiConfigurationException($"The '{fieldName}' field contained no PEM certificate.");
        }

        // Extra certificates in a field documented to hold one are ignored rather than treated as an
        // error, since the first is unambiguously the one meant.
        return certificates[0];
    }

    private static IReadOnlyList<X509Certificate2> LoadPemChain(string pem)
    {
        try
        {
            var collection = new X509Certificate2Collection();
            collection.ImportFromPem(pem);
            return [.. collection.Cast<X509Certificate2>()];
        }
        catch (CryptographicException ex)
        {
            throw new PkiConfigurationException("The PEM data could not be parsed as certificates.", ex);
        }
        catch (ArgumentException ex)
        {
            throw new PkiConfigurationException("The PEM data could not be parsed as certificates.", ex);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (!_caChain.IsValueCreated)
        {
            return;
        }

        foreach (X509Certificate2 certificate in _caChain.Value)
        {
            certificate.Dispose();
        }
    }
}

/// <summary>Thrown when PKI material supplied by configuration or an upstream cannot be used.</summary>
public sealed class PkiConfigurationException : Exception
{
    public PkiConfigurationException(string message)
        : base(message)
    {
    }

    public PkiConfigurationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
