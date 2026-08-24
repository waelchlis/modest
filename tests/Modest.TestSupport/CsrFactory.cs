using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Modest.TestSupport;

/// <summary>
/// Builds PKCS#10 certificate signing requests the way an EST client would, for use as test input.
/// </summary>
public static class CsrFactory
{
    /// <summary>Creates an RSA CSR and returns its DER bytes.</summary>
    public static byte[] CreateRsa(
        string subject = "CN=device01.example.com",
        int keySizeBits = 2048,
        IEnumerable<string>? dnsNames = null,
        IEnumerable<string>? ipAddresses = null,
        IEnumerable<string>? emailAddresses = null,
        X509Extension[]? extraExtensions = null)
    {
        using RSA key = RSA.Create(keySizeBits);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        PopulateExtensions(request, dnsNames, ipAddresses, emailAddresses, extraExtensions);
        return request.CreateSigningRequest();
    }

    /// <summary>Creates an RSA CSR, returning both the DER and the private key for later use.</summary>
    public static (byte[] Der, RSA Key) CreateRsaWithKey(
        string subject = "CN=device01.example.com",
        int keySizeBits = 2048,
        IEnumerable<string>? dnsNames = null,
        IEnumerable<string>? ipAddresses = null)
    {
        RSA key = RSA.Create(keySizeBits);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        PopulateExtensions(request, dnsNames, ipAddresses, emailAddresses: null, extraExtensions: null);
        return (request.CreateSigningRequest(), key);
    }

    /// <summary>Creates an ECDSA CSR on the given named curve.</summary>
    public static byte[] CreateEcdsa(
        string subject = "CN=device01.example.com",
        string curveName = "nistP256",
        IEnumerable<string>? dnsNames = null,
        IEnumerable<string>? ipAddresses = null)
    {
        ECCurve curve = curveName switch
        {
            "nistP256" => ECCurve.NamedCurves.nistP256,
            "nistP384" => ECCurve.NamedCurves.nistP384,
            "nistP521" => ECCurve.NamedCurves.nistP521,
            _ => throw new ArgumentOutOfRangeException(nameof(curveName), curveName, "Unsupported test curve."),
        };

        using ECDsa key = ECDsa.Create(curve);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject), key, HashAlgorithmName.SHA256);

        PopulateExtensions(request, dnsNames, ipAddresses, emailAddresses: null, extraExtensions: null);
        return request.CreateSigningRequest();
    }

    /// <summary>
    /// Creates a CSR that asks for basicConstraints CA:true — the request a client would make if it
    /// were trying to talk the CA into minting it a subordinate authority.
    /// </summary>
    public static byte[] CreateRequestingCaPrivileges(string subject = "CN=hostile.example.com") =>
        CreateRsa(subject, extraExtensions: [new X509BasicConstraintsExtension(true, true, 3, true)]);

    /// <summary>
    /// Corrupts a CSR's signature bytes so that proof-of-possession verification must fail, while
    /// leaving the DER structurally intact.
    /// </summary>
    public static byte[] WithBrokenSignature(byte[] der)
    {
        ArgumentNullException.ThrowIfNull(der);

        byte[] tampered = (byte[])der.Clone();
        tampered[^5] ^= 0xFF;
        return tampered;
    }

    private static void PopulateExtensions(
        CertificateRequest request,
        IEnumerable<string>? dnsNames,
        IEnumerable<string>? ipAddresses,
        IEnumerable<string>? emailAddresses,
        X509Extension[]? extraExtensions)
    {
        string[] dns = dnsNames?.ToArray() ?? [];
        string[] ips = ipAddresses?.ToArray() ?? [];
        string[] emails = emailAddresses?.ToArray() ?? [];

        if (dns.Length > 0 || ips.Length > 0 || emails.Length > 0)
        {
            var builder = new SubjectAlternativeNameBuilder();
            foreach (string name in dns)
            {
                builder.AddDnsName(name);
            }

            foreach (string ip in ips)
            {
                builder.AddIpAddress(IPAddress.Parse(ip));
            }

            foreach (string email in emails)
            {
                builder.AddEmailAddress(email);
            }

            request.CertificateExtensions.Add(builder.Build());
        }

        foreach (X509Extension extension in extraExtensions ?? [])
        {
            request.CertificateExtensions.Add(extension);
        }
    }
}
