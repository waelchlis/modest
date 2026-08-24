using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Modest.Codec;
using Modest.Core.Est;
using Modest.Core.Issuance;
using Modest.TestSupport;

namespace Modest.Issuance.InternalCa.Tests;

/// <summary>A throwaway directory under the system temp path, deleted on dispose.</summary>
internal sealed class TempDirectory : IDisposable
{
    public TempDirectory()
    {
        Path = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), "modest-internalca-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public string File(string name) => System.IO.Path.Combine(Path, name);

    /// <summary>A path inside the directory that deliberately does not exist.</summary>
    public string MissingFile(string name = "absent.bin") => System.IO.Path.Combine(Path, name);

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

/// <summary>
/// An <see cref="ILogger{T}"/> that keeps every rendered message plus its structured state, so a
/// test can assert on what was — and more importantly, what was never — written to the log.
/// </summary>
internal sealed class CapturingLogger<T> : ILogger<T>
{
    private readonly List<string> _lines = [];

    public IReadOnlyList<string> Lines
    {
        get
        {
            lock (_lines)
            {
                return [.. _lines];
            }
        }
    }

    /// <summary>Everything captured, rendered as one blob for substring assertions.</summary>
    public string Text => string.Join("\n", Lines);

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        ArgumentNullException.ThrowIfNull(formatter);

        string line = $"[{logLevel}] {formatter(state, exception)}";

        // Structured properties travel separately from the rendered message in most sinks, so a
        // secret could leak through a property even when the message template looks innocent.
        if (state is IReadOnlyList<KeyValuePair<string, object?>> properties)
        {
            line += " {" + string.Join(", ", properties.Select(p => $"{p.Key}={p.Value}")) + "}";
        }

        if (exception is not null)
        {
            line += " " + exception;
        }

        lock (_lines)
        {
            _lines.Add(line);
        }
    }
}

/// <summary>
/// A test CA whose key material has been written to disk, plus the options that point at it.
/// </summary>
internal sealed class DiskCa : IDisposable
{
    public const string Password = "correct horse battery staple";

    private DiskCa(TestCertificateAuthority ca, TempDirectory directory, string pfxPath, string passwordPath)
    {
        Ca = ca;
        Directory = directory;
        PfxPath = pfxPath;
        PasswordPath = passwordPath;

        RootPemPath = directory.File("root.pem");
        System.IO.File.WriteAllText(RootPemPath, ca.Root.ExportCertificatePem());
    }

    public TestCertificateAuthority Ca { get; }

    public TempDirectory Directory { get; }

    public string PfxPath { get; }

    public string PasswordPath { get; }

    /// <summary>The root on its own, as PEM — what an operator would list as an extra chain cert.</summary>
    public string RootPemPath { get; }

    public static DiskCa Create(bool withIntermediate = true, string password = Password)
    {
        TestCertificateAuthority ca = withIntermediate
            ? TestCertificateAuthority.CreateWithIntermediate()
            : TestCertificateAuthority.CreateRootOnly();

        var directory = new TempDirectory();
        (string pfxPath, string passwordPath) = ca.WriteIssuerPfx(directory.Path, password);

        return new DiskCa(ca, directory, pfxPath, passwordPath);
    }

    public InternalCaOptions Options(Action<InternalCaOptions>? configure = null)
    {
        var options = new InternalCaOptions
        {
            CertificatePath = PfxPath,
            CertificatePasswordFile = PasswordPath,
            AdditionalChainCertificatePaths = [RootPemPath],
        };

        configure?.Invoke(options);
        return options;
    }

    public InternalCaIssuer CreateIssuer(
        Action<InternalCaOptions>? configure = null,
        ILogger<InternalCaIssuer>? logger = null) =>
        new(
            Microsoft.Extensions.Options.Options.Create(Options(configure)),
            new CaKeyLoader(NullLogger<CaKeyLoader>.Instance),
            logger ?? NullLogger<InternalCaIssuer>.Instance);

    public void Dispose()
    {
        Ca.Dispose();
        Directory.Dispose();
    }
}

/// <summary>Shorthands used across the issuer tests.</summary>
internal static class Test
{
    public static CaKeyLoader Loader(ILogger<CaKeyLoader>? logger = null) =>
        new(logger ?? NullLogger<CaKeyLoader>.Instance);

    public static IOptions<InternalCaOptions> Wrap(InternalCaOptions options) =>
        Microsoft.Extensions.Options.Options.Create(options);

    public static ParsedCsr Parse(byte[] der) => Pkcs10CsrReader.Parse(der);

    public static IssuanceRequest Request(
        byte[] der,
        EstOperation operation = EstOperation.Enroll,
        ClientIdentity? identity = null)
    {
        ClientIdentity who = identity ?? new ClientIdentity(ClientAuthMethod.HttpBasic, "device01", null);
        return new IssuanceRequest(der, operation, who, CorrelationKey.Compute(der, who));
    }

    /// <summary>Finds an extension on a certificate by OID, or null.</summary>
    public static X509Extension? Extension(X509Certificate2 certificate, string oid) =>
        certificate.Extensions.FirstOrDefault(e => e.Oid?.Value == oid);

    public static X509BasicConstraintsExtension BasicConstraints(X509Certificate2 certificate)
    {
        X509Extension raw = Extension(certificate, "2.5.29.19")
            ?? throw new InvalidOperationException("The certificate has no basicConstraints extension.");

        return new X509BasicConstraintsExtension(new AsnEncodedData(raw.RawData), raw.Critical);
    }

    public static X509KeyUsageExtension KeyUsage(X509Certificate2 certificate)
    {
        X509Extension raw = Extension(certificate, "2.5.29.15")
            ?? throw new InvalidOperationException("The certificate has no keyUsage extension.");

        return new X509KeyUsageExtension(new AsnEncodedData(raw.RawData), raw.Critical);
    }

    public static X509EnhancedKeyUsageExtension Eku(X509Certificate2 certificate)
    {
        X509Extension raw = Extension(certificate, "2.5.29.37")
            ?? throw new InvalidOperationException("The certificate has no extendedKeyUsage extension.");

        return new X509EnhancedKeyUsageExtension(new AsnEncodedData(raw.RawData), raw.Critical);
    }

    public static X509SubjectAlternativeNameExtension San(X509Certificate2 certificate)
    {
        X509Extension raw = Extension(certificate, "2.5.29.17")
            ?? throw new InvalidOperationException("The certificate has no subjectAltName extension.");

        return new X509SubjectAlternativeNameExtension(raw.RawData, raw.Critical);
    }

    /// <summary>
    /// Hand-rolls a subjectAltName extension containing a single uniformResourceIdentifier whose
    /// content is not a valid absolute URI. No BCL builder will produce this, but nothing stops a
    /// hostile client from putting arbitrary IA5String bytes on the wire.
    /// </summary>
    public static X509Extension MalformedUriSan(string value = "this is not a uri")
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteCharacterString(
                UniversalTagNumber.IA5String, value, new Asn1Tag(TagClass.ContextSpecific, 6));
        }

        return new X509Extension(new Oid("2.5.29.17"), writer.Encode(), critical: false);
    }

    /// <summary>Builds a certificate chain against the test root as the only trust anchor.</summary>
    public static (bool Built, string Status) BuildChain(
        X509Certificate2 leaf, TestCertificateAuthority ca)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(ca.Root);

        if (ca.Intermediate is not null)
        {
            chain.ChainPolicy.ExtraStore.Add(ca.Intermediate);
        }

        bool built = chain.Build(leaf);
        string status = string.Join(
            "; ", chain.ChainStatus.Select(s => $"{s.Status}: {s.StatusInformation.Trim()}"));

        return (built, status);
    }

    /// <summary>The CA's private key, rendered the several ways it could plausibly leak into a log.</summary>
    public static IReadOnlyList<string> PrivateKeyFingerprints(X509Certificate2 caCertificate)
    {
        using RSA key = caCertificate.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("Test CA is expected to hold an RSA private key.");

        RSAParameters parameters = key.ExportParameters(includePrivateParameters: true);
        byte[] pkcs8 = key.ExportPkcs8PrivateKey();

        return
        [
            Convert.ToHexString(parameters.D!),
            Convert.ToBase64String(parameters.D!),
            Convert.ToHexString(parameters.P!),
            Convert.ToBase64String(parameters.P!),
            Convert.ToHexString(pkcs8),
            Convert.ToBase64String(pkcs8),
            key.ExportPkcs8PrivateKeyPem(),
        ];
    }
}
