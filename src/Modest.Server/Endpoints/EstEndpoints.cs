using System.Diagnostics;
using Microsoft.Extensions.Options;
using Modest.Codec;
using Modest.Core.Est;
using Modest.Core.Issuance;
using Modest.Server.Authentication;
using Modest.Server.Configuration;

namespace Modest.Server.Endpoints;

/// <summary>
/// The RFC 7030 endpoint handlers.
/// </summary>
public static class EstEndpoints
{
    /// <summary>Maps the EST operations under the well-known prefix.</summary>
    public static void MapEstEndpoints(this IEndpointRouteBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        RouteGroupBuilder est = builder.MapGroup(EstUriPaths.Prefix);

        est.MapGet(EstUriPaths.CaCerts, HandleCaCertsAsync);
        est.MapGet(EstUriPaths.CsrAttrs, HandleCsrAttrsAsync);
        est.MapPost(EstUriPaths.SimpleEnroll, HandleEnrollAsync);
        est.MapPost(EstUriPaths.SimpleReenroll, HandleReenrollAsync);
    }

    /// <summary>
    /// GET /cacerts — publishes the CA chain. Deliberately unauthenticated: a client bootstrapping
    /// trust has no credentials yet, which is the whole reason this operation exists
    /// (RFC 7030 s4.1).
    /// </summary>
    public static async Task HandleCaCertsAsync(
        HttpContext context,
        ICertificateIssuer issuer,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken)
    {
        ILogger logger = loggerFactory.CreateLogger("Modest.Est.CaCerts");

        try
        {
            CaChainResult chain = await issuer.GetCaChainAsync(cancellationToken).ConfigureAwait(false);

            if (chain.Chain.Count == 0)
            {
                logger.LogError("The configured issuer returned an empty CA chain; /cacerts cannot be served.");
                await EstResults.WriteProblemAsync(
                    context, StatusCodes.Status500InternalServerError, "The CA chain is not available.")
                    .ConfigureAwait(false);
                return;
            }

            byte[] der = Pkcs7CertsOnlyWriter.BuildForCaChain(chain.Chain);
            await EstResults.WriteCertsOnlyAsync(context, der).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The caller is unauthenticated here, so the reason stays in the log rather than the body.
            logger.LogError(ex, "Failed to build the /cacerts response.");
            await EstResults.WriteProblemAsync(
                context, StatusCodes.Status500InternalServerError, "The CA chain is not available.")
                .ConfigureAwait(false);
        }
    }

    /// <summary>
    /// GET /csrattrs — states which attributes the CA wants in a CSR. This build has no such
    /// requirements, which RFC 7030 s4.5 lets us signal with 204 No Content.
    /// </summary>
    public static Task HandleCsrAttrsAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        context.Response.StatusCode = StatusCodes.Status204NoContent;
        return Task.CompletedTask;
    }

    /// <summary>POST /simpleenroll — initial enrollment.</summary>
    public static Task HandleEnrollAsync(
        HttpContext context,
        ICertificateIssuer issuer,
        ReenrollmentIdentityChecker reenrollmentChecker,
        IOptionsMonitor<EstProtocolOptions> protocolOptions,
        IOptionsMonitor<EstAuthenticationOptions> authOptions,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken) =>
        HandleEnrollmentAsync(
            context, issuer, reenrollmentChecker, protocolOptions, authOptions, loggerFactory,
            EstOperation.Enroll, cancellationToken);

    /// <summary>POST /simplereenroll — renewal of an existing certificate.</summary>
    public static Task HandleReenrollAsync(
        HttpContext context,
        ICertificateIssuer issuer,
        ReenrollmentIdentityChecker reenrollmentChecker,
        IOptionsMonitor<EstProtocolOptions> protocolOptions,
        IOptionsMonitor<EstAuthenticationOptions> authOptions,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken) =>
        HandleEnrollmentAsync(
            context, issuer, reenrollmentChecker, protocolOptions, authOptions, loggerFactory,
            EstOperation.Reenroll, cancellationToken);

    private static async Task HandleEnrollmentAsync(
        HttpContext context,
        ICertificateIssuer issuer,
        ReenrollmentIdentityChecker reenrollmentChecker,
        IOptionsMonitor<EstProtocolOptions> protocolOptions,
        IOptionsMonitor<EstAuthenticationOptions> authOptions,
        ILoggerFactory loggerFactory,
        EstOperation operation,
        CancellationToken cancellationToken)
    {
        ILogger logger = loggerFactory.CreateLogger($"Modest.Est.{operation}");
        long startedAt = Stopwatch.GetTimestamp();

        ClientIdentity identity = context.GetEstClientIdentity();

        if (!identity.IsAuthenticated)
        {
            await EstResults.WriteUnauthorizedAsync(
                context,
                authOptions.CurrentValue.BasicRealm,
                "Authentication is required for certificate enrollment.")
                .ConfigureAwait(false);
            return;
        }

        if (!IsPkcs10ContentType(context.Request.ContentType))
        {
            await EstResults.WriteProblemAsync(
                context,
                StatusCodes.Status415UnsupportedMediaType,
                $"Expected Content-Type {EstMediaTypes.Pkcs10}.")
                .ConfigureAwait(false);
            return;
        }

        int maxBytes = protocolOptions.CurrentValue.MaxRequestBodyBytes;

        string body;
        try
        {
            body = await ReadBodyAsync(context.Request, maxBytes, cancellationToken).ConfigureAwait(false);
        }
        catch (BodyTooLargeException)
        {
            await EstResults.WriteProblemAsync(
                context,
                StatusCodes.Status413PayloadTooLarge,
                $"The request body exceeds the {maxBytes} byte limit.")
                .ConfigureAwait(false);
            return;
        }

        ParsedCsr csr;
        try
        {
            // Parsing verifies the CSR's own signature, which is RFC 7030's proof that the requester
            // holds the private key. It happens here, before any issuer is involved, so that every
            // issuer gets the guarantee without having to remember to ask for it.
            csr = Pkcs10CsrReader.ParseBase64(body);
        }
        catch (EstCodecException ex)
        {
            logger.LogInformation(
                "Rejected {Operation} from {Identity}: {Reason}", operation, identity.Subject, ex.Message);

            await EstResults.WriteProblemAsync(context, StatusCodes.Status400BadRequest, ex.Message)
                .ConfigureAwait(false);
            return;
        }

        if (operation == EstOperation.Reenroll)
        {
            IssuanceResult.Rejected? mismatch = reenrollmentChecker.Check(identity, csr);
            if (mismatch is not null)
            {
                await WriteRejectionAsync(context, mismatch).ConfigureAwait(false);
                return;
            }
        }

        var request = new IssuanceRequest(
            csr.Der,
            operation,
            identity,
            CorrelationKey.Compute(csr.Der.Span, identity));

        IssuanceResult result;
        try
        {
            result = await issuer.IssueAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(
                ex,
                "Issuance failed unexpectedly for {Subject} ({Operation}), correlation {Correlation}.",
                csr.Subject.Name,
                operation,
                request.CorrelationKey);

            await EstResults.WriteProblemAsync(
                context,
                StatusCodes.Status500InternalServerError,
                $"Certificate issuance failed. Trace identifier: {context.TraceIdentifier}")
                .ConfigureAwait(false);
            return;
        }

        TimeSpan elapsed = Stopwatch.GetElapsedTime(startedAt);

        switch (result)
        {
            case IssuanceResult.Issued issued:
                logger.LogInformation(
                    "{Operation} succeeded for {Subject} via {AuthMethod} identity {Identity}: " +
                    "serial {Serial}, thumbprint {Thumbprint}, expires {NotAfter:o}, took {ElapsedMs}ms.",
                    operation,
                    csr.Subject.Name,
                    identity.Method,
                    identity.Subject,
                    issued.Certificate.SerialNumber,
                    issued.Certificate.Thumbprint,
                    issued.Certificate.NotAfter,
                    (int)elapsed.TotalMilliseconds);

                byte[] der = Pkcs7CertsOnlyWriter.Build(issued.Certificate, issued.Chain);
                await EstResults.WriteCertsOnlyAsync(context, der).ConfigureAwait(false);
                break;

            case IssuanceResult.Pending pending:
                logger.LogInformation(
                    "{Operation} for {Subject} is pending; asked client to retry in {RetryAfter}.",
                    operation,
                    csr.Subject.Name,
                    pending.RetryAfter);

                await EstResults.WriteRetryAfterAsync(context, pending.RetryAfter).ConfigureAwait(false);
                break;

            case IssuanceResult.Rejected rejected:
                logger.LogInformation(
                    "{Operation} rejected for {Subject} from identity {Identity} ({Kind}): {Reason}",
                    operation,
                    csr.Subject.Name,
                    identity.Subject,
                    rejected.Kind,
                    rejected.Reason);

                await WriteRejectionAsync(context, rejected).ConfigureAwait(false);
                break;

            default:
                throw new UnreachableException($"Unhandled issuance result {result.GetType().Name}.");
        }
    }

    private static Task WriteRejectionAsync(HttpContext context, IssuanceResult.Rejected rejected) =>
        EstResults.WriteProblemAsync(
            context,
            EstResults.MapRejectionToStatusCode(rejected.Kind),
            rejected.Reason);

    private static bool IsPkcs10ContentType(string? contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
        {
            return false;
        }

        // Compare only the media type; clients legitimately append parameters such as charset.
        ReadOnlySpan<char> span = contentType.AsSpan();
        int semicolon = span.IndexOf(';');
        if (semicolon >= 0)
        {
            span = span[..semicolon];
        }

        return span.Trim().Equals(EstMediaTypes.Pkcs10, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<string> ReadBodyAsync(
        HttpRequest request, int maxBytes, CancellationToken cancellationToken)
    {
        // Refuse an oversized body from the declared length before reading a byte of it.
        if (request.ContentLength is > 0 && request.ContentLength > maxBytes)
        {
            throw new BodyTooLargeException();
        }

        byte[] buffer = new byte[maxBytes + 1];
        int total = 0;

        while (total < buffer.Length)
        {
            int read = await request.Body
                .ReadAsync(buffer.AsMemory(total), cancellationToken)
                .ConfigureAwait(false);

            if (read == 0)
            {
                break;
            }

            total += read;
        }

        // A chunked request can lie about or omit its length, so the cap is enforced again here on
        // what actually arrived.
        if (total > maxBytes)
        {
            throw new BodyTooLargeException();
        }

        return System.Text.Encoding.UTF8.GetString(buffer, 0, total);
    }

    private sealed class BodyTooLargeException : Exception;
}
