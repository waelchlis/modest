namespace Modest.Codec;

/// <summary>
/// Thrown when client-supplied EST wire data is malformed, unparseable, or fails its own
/// integrity checks.
/// </summary>
/// <remarks>
/// This is the only exception type the codec raises for input-shaped problems, so the protocol
/// layer can map it to a 4xx without catching broadly. A genuine platform or crypto-provider
/// fault is deliberately left to propagate as whatever the BCL threw: that is a 5xx, and
/// conflating the two would report server faults to clients as their own mistake.
/// </remarks>
public sealed class EstCodecException : Exception
{
    public EstCodecException(string message)
        : base(message)
    {
    }

    public EstCodecException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
