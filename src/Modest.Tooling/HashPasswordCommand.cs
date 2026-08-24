using System.Globalization;
using System.Security.Cryptography;

namespace Modest.Tooling;

/// <summary>
/// Produces the PBKDF2 verifier fields for an <c>Authentication:BasicCredentials</c> entry, so that
/// configuration never has to hold a plaintext password.
/// </summary>
public static class HashPasswordCommand
{
    private const int DefaultIterations = 210_000;

    public static int Run(string[] args)
    {
        string password = CommandRouter.RequiredOption(args, "--password");
        string username = CommandRouter.Option(args, "--username") ?? "<username>";

        int iterations = CommandRouter.Option(args, "--iterations") is { } raw &&
                         int.TryParse(raw, CultureInfo.InvariantCulture, out int parsed)
            ? parsed
            : DefaultIterations;

        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            password, salt, iterations, HashAlgorithmName.SHA256, 32);

        Console.WriteLine("Add this to Authentication:BasicCredentials:");
        Console.WriteLine();
        Console.WriteLine("{");
        Console.WriteLine($"  \"Username\": \"{username}\",");
        Console.WriteLine($"  \"PasswordHash\": \"{Convert.ToBase64String(hash)}\",");
        Console.WriteLine($"  \"Salt\": \"{Convert.ToBase64String(salt)}\",");
        Console.WriteLine($"  \"Iterations\": {iterations}");
        Console.WriteLine("}");

        return 0;
    }
}
