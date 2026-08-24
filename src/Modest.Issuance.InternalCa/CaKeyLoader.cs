using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace Modest.Issuance.InternalCa;

/// <summary>
/// Loads the CA certificate, its private key, and any additional chain certificates from disk.
/// </summary>
public sealed class CaKeyLoader
{
    private readonly ILogger<CaKeyLoader> _logger;

    public CaKeyLoader(ILogger<CaKeyLoader> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Loads the CA signing certificate and the chain to publish alongside it.
    /// </summary>
    /// <exception cref="CaKeyLoadException">
    /// The PFX is missing, the password is wrong, or the certificate cannot sign other certificates.
    /// </exception>
    public CaMaterial Load(InternalCaOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!File.Exists(options.CertificatePath))
        {
            throw new CaKeyLoadException(
                $"CA certificate file not found at '{options.CertificatePath}'. " +
                "Set Issuance:InternalCa:CertificatePath to a PKCS#12 file containing the CA certificate and private key.");
        }

        WarnIfPermissive(options.CertificatePath);

        string? password = ReadPassword(options);

        X509Certificate2 caCertificate;
        try
        {
            caCertificate = X509CertificateLoader.LoadPkcs12FromFile(
                options.CertificatePath,
                password,
                X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
        }
        catch (CryptographicException ex)
        {
            throw new CaKeyLoadException(
                $"Could not load the CA PKCS#12 file at '{options.CertificatePath}'. " +
                "The file may be corrupt or the password incorrect.",
                ex);
        }

        ValidateUsableAsCa(caCertificate, options.CertificatePath);

        List<X509Certificate2> additional = LoadAdditionalChain(options);

        _logger.LogInformation(
            "Loaded internal CA certificate {Subject} (thumbprint {Thumbprint}) with {ChainCount} additional chain certificate(s).",
            caCertificate.Subject,
            caCertificate.Thumbprint,
            additional.Count);

        return new CaMaterial(caCertificate, additional);
    }

    private static void ValidateUsableAsCa(X509Certificate2 certificate, string path)
    {
        if (!certificate.HasPrivateKey)
        {
            certificate.Dispose();
            throw new CaKeyLoadException(
                $"The certificate in '{path}' has no private key, so it cannot sign certificates.");
        }

        X509BasicConstraintsExtension? basicConstraints =
            certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();

        if (basicConstraints is not null && !basicConstraints.CertificateAuthority)
        {
            certificate.Dispose();
            throw new CaKeyLoadException(
                $"The certificate in '{path}' is not a CA certificate: its basicConstraints extension says CA=false.");
        }

        X509KeyUsageExtension? keyUsage =
            certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();

        if (keyUsage is not null && !keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign))
        {
            certificate.Dispose();
            throw new CaKeyLoadException(
                $"The certificate in '{path}' does not carry the keyCertSign key usage, so it may not sign certificates.");
        }
    }

    private List<X509Certificate2> LoadAdditionalChain(InternalCaOptions options)
    {
        List<X509Certificate2> chain = [];

        foreach (string path in options.EffectiveAdditionalChainCertificatePaths)
        {
            if (!File.Exists(path))
            {
                foreach (X509Certificate2 loaded in chain)
                {
                    loaded.Dispose();
                }

                throw new CaKeyLoadException($"Additional chain certificate file not found at '{path}'.");
            }

            try
            {
                var collection = new X509Certificate2Collection();
                collection.ImportFromPemFile(path);

                if (collection.Count == 0)
                {
                    collection.Add(X509CertificateLoader.LoadCertificateFromFile(path));
                }

                chain.AddRange(collection.Cast<X509Certificate2>());
            }
            catch (CryptographicException ex)
            {
                foreach (X509Certificate2 loaded in chain)
                {
                    loaded.Dispose();
                }

                throw new CaKeyLoadException($"Could not read chain certificate(s) from '{path}'.", ex);
            }
        }

        return chain;
    }

    private string? ReadPassword(InternalCaOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.CertificatePasswordFile))
        {
            return null;
        }

        if (!File.Exists(options.CertificatePasswordFile))
        {
            throw new CaKeyLoadException(
                $"CA certificate password file not found at '{options.CertificatePasswordFile}'.");
        }

        WarnIfPermissive(options.CertificatePasswordFile);

        // Trailing newlines are near-universal in files written by shell redirection or a
        // Kubernetes secret; treating one as part of the password would be a baffling failure.
        return File.ReadAllText(options.CertificatePasswordFile).TrimEnd('\r', '\n');
    }

    private void WarnIfPermissive(string path)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return;
        }

        try
        {
            UnixFileMode mode = File.GetUnixFileMode(path);
            const UnixFileMode Permissive =
                UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                UnixFileMode.OtherRead | UnixFileMode.OtherWrite;

            if ((mode & Permissive) != 0)
            {
                _logger.LogWarning(
                    "Key material at {Path} is readable or writable beyond its owner (mode {Mode}). " +
                    "Restrict it to 0600 owned by the service account.",
                    path,
                    mode);
            }
        }
        catch (IOException)
        {
            // Permission inspection is a courtesy check; never let it stop startup.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

/// <summary>The loaded CA signing certificate and the chain published with it.</summary>
public sealed record CaMaterial(X509Certificate2 Certificate, IReadOnlyList<X509Certificate2> AdditionalChain)
{
    /// <summary>The full chain to publish: signing CA first, then everything above it.</summary>
    public IReadOnlyList<X509Certificate2> FullChain => [Certificate, .. AdditionalChain];
}
