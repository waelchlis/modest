namespace Modest.Server.Authentication;

/// <summary>
/// Validates HTTP Basic credentials presented by an EST client.
/// </summary>
/// <remarks>
/// An interface so the static configured list can be swapped for a real directory or credential
/// service without touching the authentication middleware.
/// </remarks>
public interface IBasicCredentialValidator
{
    /// <summary>Returns true when the username and password are valid.</summary>
    bool Validate(string username, string password);
}
