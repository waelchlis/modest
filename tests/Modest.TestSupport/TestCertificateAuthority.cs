using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Modest.TestSupport;

/// <summary>
/// A throwaway certificate authority for tests: generates a root, optional intermediate, TLS
/// server certificates and client certificates, all chaining correctly.
/// </summary>
/// <remarks>
/// Every test project draws its PKI material from here so that cert generation is written once
/// and correctly, rather than re-invented per test file. Keys are ephemeral and in-memory.
/// </remarks>
public sealed class TestCertificateAuthority : IDisposable
{
    private readonly List<X509Certificate2> _owned = [];
    private bool _disposed;

    private TestCertificateAuthority(X509Certificate2 root, X509Certificate2? intermediate)
    {
        Root = Track(root);
        Intermediate = intermediate is null ? null : Track(intermediate);
    }

    /// <summary>The self-signed root.</summary>
    public X509Certificate2 Root { get; }

    /// <summary>The intermediate, when this CA was created with one.</summary>
    public X509Certificate2? Intermediate { get; }

    /// <summary>The certificate that actually signs leaves: the intermediate if present, else the root.</summary>
    public X509Certificate2 Issuer => Intermediate ?? Root;

    /// <summary>The chain served from /cacerts: issuer first, root last.</summary>
    public IReadOnlyList<X509Certificate2> Chain =>
        Intermediate is null ? [Root] : [Intermediate, Root];

    /// <summary>Creates a CA with a self-signed root only.</summary>
    public static TestCertificateAuthority CreateRootOnly(string subject = "CN=Modest Test Root CA")
    {
        X509Certificate2 root = CreateSelfSignedCa(subject);
        return new TestCertificateAuthority(root, intermediate: null);
    }

    /// <summary>Creates a CA with a root and one intermediate; the intermediate signs leaves.</summary>
    public static TestCertificateAuthority CreateWithIntermediate(
        string rootSubject = "CN=Modest Test Root CA",
        string intermediateSubject = "CN=Modest Test Issuing CA")
    {
        X509Certificate2 root = CreateSelfSignedCa(rootSubject);
        X509Certificate2 intermediate = CreateSubordinateCa(root, intermediateSubject);
        return new TestCertificateAuthority(root, intermediate);
    }

    /// <summary>Issues a leaf certificate with its private key attached.</summary>
    public X509Certificate2 IssueLeaf(
        string subject,
        IEnumerable<string>? dnsNames = null,
        IEnumerable<string>? ipAddresses = null,
        X509KeyUsageFlags keyUsage = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
        OidCollection? enhancedKeyUsages = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        OidCollection ekus = enhancedKeyUsages ?? [new Oid("1.3.6.1.5.5.7.3.2")]; // clientAuth
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(ekus, false));

        AddSanIfAny(request, dnsNames, ipAddresses);

        X509Certificate2 issued = request.Create(
            Issuer,
            notBefore ?? DateTimeOffset.UtcNow.AddMinutes(-5),
            notAfter ?? DateTimeOffset.UtcNow.AddDays(90),
            RandomSerial());

        return Track(issued.CopyWithPrivateKey(key));
    }

    /// <summary>Issues a TLS server certificate for the given host names.</summary>
    public X509Certificate2 IssueServerCertificate(string subject = "CN=localhost", params string[] dnsNames)
    {
        string[] names = dnsNames.Length > 0 ? dnsNames : ["localhost"];
        return IssueLeaf(
            subject,
            dnsNames: names,
            ipAddresses: ["127.0.0.1"],
            enhancedKeyUsages: [new Oid("1.3.6.1.5.5.7.3.1")]); // serverAuth
    }

    /// <summary>Exports the issuing CA (certificate plus private key) as a PFX.</summary>
    public byte[] ExportIssuerPfx(string password) =>
        Issuer.Export(X509ContentType.Pfx, password);

    /// <summary>Writes the issuing CA PFX and its password to disk, for tests that exercise file loading.</summary>
    public (string PfxPath, string PasswordPath) WriteIssuerPfx(string directory, string password = "test-password")
    {
        Directory.CreateDirectory(directory);
        string pfxPath = Path.Combine(directory, "ca.pfx");
        string passwordPath = Path.Combine(directory, "ca.pass");

        File.WriteAllBytes(pfxPath, ExportIssuerPfx(password));
        File.WriteAllText(passwordPath, password);

        return (pfxPath, passwordPath);
    }

    /// <summary>Writes the full chain as a concatenated PEM file.</summary>
    public string WriteChainPem(string directory, string fileName = "chain.pem")
    {
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, fileName);
        File.WriteAllText(path, ChainPem());
        return path;
    }

    /// <summary>The full chain as concatenated PEM text.</summary>
    public string ChainPem() =>
        string.Join('\n', Chain.Select(static c => c.ExportCertificatePem()));

    private static X509Certificate2 CreateSelfSignedCa(string subject)
    {
        using RSA key = RSA.Create(3072);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        // CreateSelfSigned already binds the generating key to the certificate it returns, unlike
        // Create(issuer, ...) below; passing it through CopyWithPrivateKey would throw
        // "The certificate already has an associated private key."
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
    }

    private static X509Certificate2 CreateSubordinateCa(X509Certificate2 issuer, string subject)
    {
        using RSA key = RSA.Create(3072);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        X509Certificate2 cert = request.Create(
            issuer,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(5),
            RandomSerial());

        return cert.CopyWithPrivateKey(key);
    }

    private static void AddSanIfAny(
        CertificateRequest request, IEnumerable<string>? dnsNames, IEnumerable<string>? ipAddresses)
    {
        string[] dns = dnsNames?.ToArray() ?? [];
        string[] ips = ipAddresses?.ToArray() ?? [];

        if (dns.Length == 0 && ips.Length == 0)
        {
            return;
        }

        var builder = new SubjectAlternativeNameBuilder();
        foreach (string name in dns)
        {
            builder.AddDnsName(name);
        }

        foreach (string ip in ips)
        {
            builder.AddIpAddress(IPAddress.Parse(ip));
        }

        request.CertificateExtensions.Add(builder.Build());
    }

    private static byte[] RandomSerial()
    {
        byte[] serial = new byte[20];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F;
        return serial;
    }

    private X509Certificate2 Track(X509Certificate2 certificate)
    {
        _owned.Add(certificate);
        return certificate;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (X509Certificate2 certificate in _owned)
        {
            certificate.Dispose();
        }

        _owned.Clear();
    }
}
