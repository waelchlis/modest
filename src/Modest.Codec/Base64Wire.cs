using System.Buffers;

namespace Modest.Codec;

/// <summary>
/// Base64 handling for EST payloads.
/// </summary>
/// <remarks>
/// RFC 7030 s3.2.1 carries every binary payload as base64 text. It does not mandate a line
/// length, and clients vary: some wrap at 64 like classic PEM, some at 76 like MIME, some send
/// one unbroken line. Decoding therefore has to tolerate arbitrary whitespace, while encoding
/// picks one form and stays consistent.
/// </remarks>
public static class Base64Wire
{
    private static readonly SearchValues<char> Whitespace = SearchValues.Create(" \t\r\n");

    /// <summary>
    /// Decodes base64 text, ignoring any whitespace, including internal line breaks.
    /// </summary>
    /// <exception cref="EstCodecException">The input is not valid base64.</exception>
    public static byte[] DecodeTolerant(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            throw new EstCodecException("Expected a base64-encoded body but it was empty.");
        }

        string compact = Compact(input);

        if (compact.Length == 0)
        {
            throw new EstCodecException("Expected a base64-encoded body but it contained only whitespace.");
        }

        try
        {
            return Convert.FromBase64String(compact);
        }
        catch (FormatException ex)
        {
            throw new EstCodecException("Body is not valid base64.", ex);
        }
    }

    /// <summary>Encodes bytes as a single unwrapped base64 line.</summary>
    public static string Encode(ReadOnlySpan<byte> data) => Convert.ToBase64String(data);

    /// <summary>Encodes bytes as base64 wrapped at <paramref name="lineLength"/> characters.</summary>
    public static string EncodeWrapped(ReadOnlySpan<byte> data, int lineLength = 64)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(lineLength, 4);

        string raw = Convert.ToBase64String(data);
        if (raw.Length <= lineLength)
        {
            return raw;
        }

        var sb = new System.Text.StringBuilder(raw.Length + (raw.Length / lineLength) + 2);
        for (int i = 0; i < raw.Length; i += lineLength)
        {
            if (i > 0)
            {
                sb.Append('\n');
            }

            sb.Append(raw.AsSpan(i, Math.Min(lineLength, raw.Length - i)));
        }

        return sb.ToString();
    }

    private static string Compact(string input)
    {
        if (input.AsSpan().IndexOfAny(Whitespace) < 0)
        {
            return input;
        }

        return string.Create(input.Length, input, static (dest, src) =>
        {
            int n = 0;
            foreach (char c in src)
            {
                if (!char.IsWhiteSpace(c))
                {
                    dest[n++] = c;
                }
            }

            // Convert.FromBase64String ignores nothing, so the unused tail must not reach it.
            // Filling with '\0' would be rejected; the caller slices via the returned length
            // instead, so pad with a character the trim below removes.
            dest[n..].Fill(' ');
        }).TrimEnd(' ');
    }
}
