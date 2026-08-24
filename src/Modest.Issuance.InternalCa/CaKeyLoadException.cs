namespace Modest.Issuance.InternalCa;

/// <summary>
/// Thrown when the CA key material cannot be loaded.
/// </summary>
/// <remarks>
/// This is a startup-fatal condition by design. An EST server that cannot sign should not start
/// and report itself healthy; it should fail loudly so the operator fixes the configuration. The
/// host catches this specific type to print an actionable message rather than a stack trace.
/// </remarks>
public sealed class CaKeyLoadException : Exception
{
    public CaKeyLoadException(string message)
        : base(message)
    {
    }

    public CaKeyLoadException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
