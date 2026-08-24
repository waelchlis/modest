using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Modest.Server.Configuration;

namespace Modest.Server.Authentication;

/// <summary>
/// Validates Basic credentials against a PBKDF2 verifier list supplied by configuration.
/// </summary>
public sealed class StaticConfigBasicCredentialValidator : IBasicCredentialValidator
{
    private readonly IOptionsMonitor<EstAuthenticationOptions> _options;
    private readonly ILogger<StaticConfigBasicCredentialValidator> _logger;

    public StaticConfigBasicCredentialValidator(
        IOptionsMonitor<EstAuthenticationOptions> options,
        ILogger<StaticConfigBasicCredentialValidator> logger)
    {
        _options = options;
        _logger = logger;
    }

    /// <inheritdoc />
    public bool Validate(string username, string password)
    {
        if (string.IsNullOrEmpty(username))
        {
            return false;
        }

        EstAuthenticationOptions options = _options.CurrentValue;

        BasicCredentialOptions? credential = options.BasicCredentials
            .FirstOrDefault(c => string.Equals(c.Username, username, StringComparison.Ordinal));

        if (credential is null)
        {
            // Derive against a dummy salt anyway so that an unknown username costs the same time as
            // a known one with a wrong password. Otherwise response timing enumerates valid usernames.
            _ = Derive(password, DummySalt, DefaultIterations, DummyHashLength);
            return false;
        }

        byte[] expected;
        byte[] salt;
        try
        {
            expected = Convert.FromBase64String(credential.PasswordHash);
            salt = Convert.FromBase64String(credential.Salt);
        }
        catch (FormatException)
        {
            _logger.LogError(
                "Basic credential for user {Username} has a PasswordHash or Salt that is not valid base64.",
                username);
            return false;
        }

        if (expected.Length == 0 || salt.Length == 0)
        {
            return false;
        }

        byte[] actual = Derive(password, salt, credential.Iterations, expected.Length);

        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    /// <summary>
    /// Derives a verifier for a password, for provisioning new credentials.
    /// </summary>
    public static (string PasswordHash, string Salt, int Iterations) CreateVerifier(
        string password, int iterations = DefaultIterations)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] hash = Derive(password, salt, iterations, 32);
        return (Convert.ToBase64String(hash), Convert.ToBase64String(salt), iterations);
    }

    internal const int DefaultIterations = 210_000;

    private const int DummyHashLength = 32;
    private static readonly byte[] DummySalt = new byte[16];

    private static byte[] Derive(string password, byte[] salt, int iterations, int length) =>
        Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations <= 0 ? DefaultIterations : iterations,
            HashAlgorithmName.SHA256,
            length);
}
