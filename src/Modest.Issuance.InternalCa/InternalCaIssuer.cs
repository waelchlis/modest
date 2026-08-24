using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Modest.Codec;
using Modest.Core.Issuance;

namespace Modest.Issuance.InternalCa;

/// <summary>
/// Issues certificates directly, using a CA private key held by this process.
/// </summary>
public sealed class InternalCaIssuer : ICertificateIssuer, IDisposable
{
    private readonly InternalCaOptions _options;
    private readonly CaMaterial _ca;
    private readonly ILogger<InternalCaIssuer> _logger;
    private bool _disposed;

    public InternalCaIssuer(
        IOptions<InternalCaOptions> options,
        CaKeyLoader loader,
        ILogger<InternalCaIssuer> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(loader);

        _options = options.Value;
        _logger = logger;
        _ca = loader.Load(_options);
    }

    /// <inheritdoc />
    public Task<CaChainResult> GetCaChainAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new CaChainResult(_ca.FullChain));

    /// <inheritdoc />
    public Task<bool> IsReadyAsync(CancellationToken cancellationToken) =>
        // Construction loads and validates the key; reaching this point means we can sign.
        Task.FromResult(!_disposed);

    /// <inheritdoc />
    public Task<IssuanceResult> IssueAsync(IssuanceRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ObjectDisposedException.ThrowIf(_disposed, this);

        ParsedCsr csr;
        try
        {
            csr = Pkcs10CsrReader.Parse(request.Pkcs10Der);
        }
        catch (EstCodecException ex)
        {
            // The protocol layer parses first and would normally have rejected this already; an
            // issuer must still not trust that it was called correctly.
            return Task.FromResult<IssuanceResult>(
                new IssuanceResult.Rejected(ex.Message, IssuanceRejectionKind.InvalidCsr));
        }

        IssuanceResult.Rejected? rejection = CsrPolicy.Evaluate(csr, _options);
        if (rejection is not null)
        {
            _logger.LogInformation(
                "Rejected {Operation} for subject {Subject} from {Identity}: {Reason}",
                request.Operation,
                csr.Subject.Name,
                request.Identity.Subject ?? "anonymous",
                rejection.Reason);

            return Task.FromResult<IssuanceResult>(rejection);
        }

        try
        {
            X509Certificate2 issued = CertificateBuilder.Build(csr, _ca.Certificate, _options);

            _logger.LogInformation(
                "Issued certificate {Serial} for {Subject} ({Operation}) to {Identity}, expires {NotAfter:o}.",
                issued.SerialNumber,
                issued.Subject,
                request.Operation,
                request.Identity.Subject ?? "anonymous",
                issued.NotAfter);

            return Task.FromResult<IssuanceResult>(
                new IssuanceResult.Issued(issued, _ca.FullChain));
        }
        catch (CryptographicException ex)
        {
            _logger.LogError(ex, "Signing failed for subject {Subject}.", csr.Subject.Name);
            return Task.FromResult<IssuanceResult>(
                new IssuanceResult.Rejected(
                    "The certificate could not be signed.", IssuanceRejectionKind.InvalidCsr));
        }
        catch (ArgumentException ex)
        {
            // Malformed SAN values and unrecognised policy settings land here.
            _logger.LogError(ex, "Certificate construction failed for subject {Subject}.", csr.Subject.Name);
            return Task.FromResult<IssuanceResult>(
                new IssuanceResult.Rejected(
                    "The request contained a value that cannot be represented in a certificate.",
                    IssuanceRejectionKind.InvalidCsr));
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _ca.Certificate.Dispose();
        foreach (X509Certificate2 certificate in _ca.AdditionalChain)
        {
            certificate.Dispose();
        }
    }
}
