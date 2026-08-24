using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Modest.Tooling;

/// <summary>
/// Generates a self-signed CA keypair for internal-CA mode.
/// </summary>
/// <remarks>
/// Intended for development, labs and small deployments. A production CA key belongs in an HSM or
/// KMS, which this version does not yet support.
/// </remarks>
public static class InitCaCommand
{
    public static async Task<int> RunAsync(string[] args)
    {
        string outputDirectory = CommandRouter.RequiredOption(args, "--out");
        string subject = CommandRouter.Option(args, "--subject") ?? "CN=Modest Internal CA";
        string password = CommandRouter.Option(args, "--password") ?? GeneratePassword();
        int days = ParseInt(CommandRouter.Option(args, "--days"), 3650);
        int keySize = ParseInt(CommandRouter.Option(args, "--key-size"), 3072);

        Directory.CreateDirectory(outputDirectory);

        using RSA key = RSA.Create(keySize);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        using X509Certificate2 ca = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(days));

        string pfxPath = Path.Combine(outputDirectory, "ca.pfx");
        string passwordPath = Path.Combine(outputDirectory, "ca.pfx.pass");
        string certPath = Path.Combine(outputDirectory, "ca.crt");

        await File.WriteAllBytesAsync(pfxPath, ca.Export(X509ContentType.Pfx, password)).ConfigureAwait(false);
        await File.WriteAllTextAsync(passwordPath, password).ConfigureAwait(false);
        await File.WriteAllTextAsync(certPath, ca.ExportCertificatePem() + Environment.NewLine).ConfigureAwait(false);

        RestrictToOwner(pfxPath);
        RestrictToOwner(passwordPath);

        Console.WriteLine($"Created CA {ca.Subject}");
        Console.WriteLine($"  thumbprint : {ca.Thumbprint}");
        Console.WriteLine($"  expires    : {ca.NotAfter:u}");
        Console.WriteLine($"  keypair    : {pfxPath}");
        Console.WriteLine($"  password   : {passwordPath}");
        Console.WriteLine($"  public cert: {certPath}");
        Console.WriteLine();
        Console.WriteLine("Point the server at it with:");
        Console.WriteLine($"  Issuance__InternalCa__CertificatePath={pfxPath}");
        Console.WriteLine($"  Issuance__InternalCa__CertificatePasswordFile={passwordPath}");

        return 0;
    }

    private static string GeneratePassword() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));

    private static int ParseInt(string? value, int fallback) =>
        value is not null && int.TryParse(value, CultureInfo.InvariantCulture, out int parsed)
            ? parsed
            : fallback;

    private static void RestrictToOwner(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (IOException)
        {
            Console.Error.WriteLine($"warning: could not restrict permissions on {path}; set them to 0600 yourself.");
        }
        catch (UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"warning: could not restrict permissions on {path}; set them to 0600 yourself.");
        }
    }
}
