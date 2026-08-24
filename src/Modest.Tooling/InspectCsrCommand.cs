using System.Text;
using Modest.Codec;

namespace Modest.Tooling;

/// <summary>
/// Parses a CSR and reports what it asks for, including whether its self-signature verifies.
/// </summary>
public static class InspectCsrCommand
{
    public static async Task<int> RunAsync(string[] args)
    {
        string path = CommandRouter.RequiredOption(args, "--file");

        if (!File.Exists(path))
        {
            Console.Error.WriteLine($"modest: file not found: {path}");
            return 1;
        }

        byte[] raw = await File.ReadAllBytesAsync(path).ConfigureAwait(false);
        byte[] der = LooksLikeDer(raw) ? raw : Base64Wire.DecodeTolerant(StripPemArmour(raw));

        ParsedCsr csr;
        try
        {
            csr = Pkcs10CsrReader.Parse(der);
        }
        catch (EstCodecException ex)
        {
            Console.Error.WriteLine($"modest: {ex.Message}");
            return 1;
        }

        Console.WriteLine($"subject        : {(string.IsNullOrEmpty(csr.Subject.Name) ? "<empty>" : csr.Subject.Name)}");
        Console.WriteLine($"key algorithm  : {csr.PublicKey.Oid.FriendlyName ?? csr.PublicKeyAlgorithmOid}");
        Console.WriteLine($"key size       : {Pkcs10CsrReader.GetKeySizeBits(csr)} bits");

        if (Pkcs10CsrReader.GetCurveName(csr) is { } curve)
        {
            Console.WriteLine($"curve          : {curve}");
        }

        Console.WriteLine("signature      : verified (parsing enforces proof of possession)");

        SubjectAlternativeNames sans = csr.SubjectAlternativeNames;
        if (sans.IsEmpty)
        {
            Console.WriteLine("subjectAltName : <none>");
        }
        else
        {
            Console.WriteLine("subjectAltName :");
            foreach (string dns in sans.DnsNames)
            {
                Console.WriteLine($"  DNS   {dns}");
            }

            foreach (System.Net.IPAddress ip in sans.IPAddresses)
            {
                Console.WriteLine($"  IP    {ip}");
            }

            foreach (string email in sans.EmailAddresses)
            {
                Console.WriteLine($"  email {email}");
            }

            foreach (string upn in sans.UserPrincipalNames)
            {
                Console.WriteLine($"  UPN   {upn}");
            }

            foreach (string uri in sans.Uris)
            {
                Console.WriteLine($"  URI   {uri}");
            }
        }

        if (csr.RequestedExtensions.Count > 0)
        {
            Console.WriteLine("requested extensions (note: the CA applies its own policy and does not simply copy these):");
            foreach (System.Security.Cryptography.X509Certificates.X509Extension extension in csr.RequestedExtensions)
            {
                Console.WriteLine(
                    $"  {extension.Oid?.Value} {extension.Oid?.FriendlyName} critical={extension.Critical}");
            }
        }

        return 0;
    }

    // A DER SEQUENCE always opens with 0x30; PEM and base64 text never do.
    private static bool LooksLikeDer(byte[] data) => data.Length > 0 && data[0] == 0x30;

    private static string StripPemArmour(byte[] raw)
    {
        string text = Encoding.UTF8.GetString(raw);

        return string.Concat(
            text.Split('\n')
                .Where(static line => !line.StartsWith("-----", StringComparison.Ordinal))
                .Select(static line => line.Trim()));
    }
}
