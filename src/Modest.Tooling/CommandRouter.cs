namespace Modest.Tooling;

/// <summary>
/// Entry point for the operator CLI.
/// </summary>
public static class CommandRouter
{
    public static async Task<int> RunAsync(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            PrintUsage();
            return args.Length == 0 ? 1 : 0;
        }

        try
        {
            return args[0] switch
            {
                "init-ca" => await InitCaCommand.RunAsync(args[1..]).ConfigureAwait(false),
                "hash-password" => HashPasswordCommand.Run(args[1..]),
                "inspect-csr" => await InspectCsrCommand.RunAsync(args[1..]).ConfigureAwait(false),
                _ => Unknown(args[0]),
            };
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine($"modest: {ex.Message}");
            return 1;
        }
        catch (IOException ex)
        {
            Console.Error.WriteLine($"modest: {ex.Message}");
            return 1;
        }
    }

    private static int Unknown(string command)
    {
        Console.Error.WriteLine($"modest: unknown command '{command}'");
        PrintUsage();
        return 1;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
            modest - operator tooling for the Modest EST server

            Usage:
              modest init-ca --out <dir> [--subject <dn>] [--password <pw>] [--days <n>] [--key-size <bits>]
                  Generate a self-signed CA keypair for internal-CA mode, writing ca.pfx,
                  ca.pfx.pass and ca.crt into <dir>. For development and small deployments.

              modest hash-password --password <pw> [--iterations <n>]
                  Produce the PBKDF2 verifier fields for an Authentication:BasicCredentials entry.
                  The plaintext password is never stored in configuration.

              modest inspect-csr --file <path>
                  Parse a PKCS#10 CSR (DER, PEM or base64) and print what it requests, including
                  whether its self-signature verifies.
            """);
    }

    /// <summary>Reads a named option such as <c>--out</c> from an argument list.</summary>
    internal static string? Option(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], name, StringComparison.Ordinal))
            {
                return args[i + 1];
            }
        }

        return null;
    }

    internal static string RequiredOption(string[] args, string name) =>
        Option(args, name) ?? throw new ArgumentException($"missing required option {name}");
}
