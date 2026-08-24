using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Modest.Server.Configuration;

namespace Modest.Server.Authentication;

/// <summary>Decides whether a presented TLS client certificate is acceptable.</summary>
public interface IClientCertificateValidator
{
    /// <summary>Validates the certificate, reporting why it failed when it does.</summary>
    bool Validate(X509Certificate2 certificate, out string? failureReason);
}

/// <summary>
/// Validates client certificates by chain-building against a configured trust anchor bundle.
/// </summary>
/// <remarks>
/// Revocation is not checked in this version. That is a real gap for production use and is
/// recorded as such in the README and roadmap rather than silently ignored.
/// </remarks>
public sealed class ClientCertificateValidator : IClientCertificateValidator, IDisposable
{
    private readonly EstAuthenticationOptions _options;
    private readonly ILogger<ClientCertificateValidator> _logger;
    private readonly X509Certificate2Collection _trustAnchors = [];
    private bool _disposed;

    public ClientCertificateValidator(
        IOptions<EstAuthenticationOptions> options,
        ILogger<ClientCertificateValidator> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options.Value;
        _logger = logger;

        LoadTrustAnchors();
    }

    /// <inheritdoc />
    public bool Validate(X509Certificate2 certificate, out string? failureReason)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        if (_options.AllowUntrustedClientCertificates)
        {
            failureReason = null;
            return true;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (now < certificate.NotBefore || now > certificate.NotAfter)
        {
            failureReason = "the certificate is outside its validity period";
            return false;
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

        if (_trustAnchors.Count > 0)
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.AddRange(_trustAnchors);
        }

        bool valid;
        try
        {
            valid = chain.Build(certificate);
        }
        catch (CryptographicException ex)
        {
            failureReason = $"chain building threw: {ex.Message}";
            return false;
        }

        if (!valid)
        {
            failureReason = string.Join(
                "; ",
                chain.ChainStatus.Select(static s => s.StatusInformation.Trim()).Where(static s => s.Length > 0));

            if (string.IsNullOrEmpty(failureReason))
            {
                failureReason = "the certificate chain could not be validated";
            }

            return false;
        }

        failureReason = null;
        return true;
    }

    private void LoadTrustAnchors()
    {
        if (_options.AllowUntrustedClientCertificates)
        {
            _logger.LogWarning(
                "Authentication:AllowUntrustedClientCertificates is enabled. Any client certificate will be " +
                "accepted without chain validation. Do not run this way in production.");
            return;
        }

        if (string.IsNullOrWhiteSpace(_options.ClientCertificateTrustStorePath))
        {
            _logger.LogInformation(
                "No client certificate trust store configured; client certificates will be validated " +
                "against the platform trust store.");
            return;
        }

        if (!File.Exists(_options.ClientCertificateTrustStorePath))
        {
            throw new InvalidOperationException(
                $"The client certificate trust store was not found at '{_options.ClientCertificateTrustStorePath}'. " +
                "Set Authentication:ClientCertificateTrustStorePath to a PEM bundle of trust anchors, or clear it " +
                "to use the platform trust store.");
        }

        _trustAnchors.ImportFromPemFile(_options.ClientCertificateTrustStorePath);

        if (_trustAnchors.Count == 0)
        {
            throw new InvalidOperationException(
                $"The client certificate trust store at '{_options.ClientCertificateTrustStorePath}' contains no certificates.");
        }

        _logger.LogInformation(
            "Loaded {Count} client certificate trust anchor(s) from {Path}.",
            _trustAnchors.Count,
            _options.ClientCertificateTrustStorePath);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (X509Certificate2 anchor in _trustAnchors)
        {
            anchor.Dispose();
        }

        _trustAnchors.Clear();
    }
}
