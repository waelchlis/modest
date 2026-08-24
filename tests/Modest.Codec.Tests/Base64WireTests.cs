using System.Text;

namespace Modest.Codec.Tests;

/// <summary>
/// RFC 7030 s3.2.1 carries every payload as base64 text without mandating a line length, so the
/// decoder has to accept whatever a client sends and the encoder has to be predictable.
/// </summary>
public sealed class Base64WireTests
{
    private static readonly byte[] Payload = CreatePayload(200);

    // ---------------------------------------------------------------- decode: whitespace forms

    [Fact]
    public void DecodeTolerant_AcceptsUnwrappedInput()
    {
        string encoded = Convert.ToBase64String(Payload);

        Base64Wire.DecodeTolerant(encoded).ShouldBe(Payload);
    }

    [Theory]
    [InlineData(64, "\n")]
    [InlineData(64, "\r\n")]
    [InlineData(76, "\n")]
    [InlineData(76, "\r\n")]
    public void DecodeTolerant_AcceptsWrappedInput(int width, string newLine)
    {
        string wrapped = Wrap(Convert.ToBase64String(Payload), width, newLine);

        // Sanity: the fixture really is wrapped, otherwise the test proves nothing.
        wrapped.ShouldContain(newLine);

        Base64Wire.DecodeTolerant(wrapped).ShouldBe(Payload);
    }

    [Fact]
    public void DecodeTolerant_AcceptsLeadingAndTrailingWhitespace()
    {
        string encoded = "  \r\n\t" + Convert.ToBase64String(Payload) + "\t \r\n  ";

        Base64Wire.DecodeTolerant(encoded).ShouldBe(Payload);
    }

    [Fact]
    public void DecodeTolerant_AcceptsWhitespaceAroundThePaddingCharacters()
    {
        // A payload whose encoding ends in "==", split so that whitespace lands between the last
        // data character and the padding. Trailing-whitespace trimming must not eat the padding.
        byte[] data = CreatePayload(10); // 10 % 3 == 1 -> two padding characters
        string encoded = Convert.ToBase64String(data);
        encoded.ShouldEndWith("==");

        string mangled = encoded[..^2] + "\n  \r\n" + "==" + "\n";

        Base64Wire.DecodeTolerant(mangled).ShouldBe(data);
    }

    [Fact]
    public void DecodeTolerant_AcceptsInternalTabsAndSpaces()
    {
        string encoded = Convert.ToBase64String(Payload);
        var sb = new StringBuilder();
        for (int i = 0; i < encoded.Length; i++)
        {
            sb.Append(encoded[i]);
            if (i % 7 == 0)
            {
                sb.Append(" \t");
            }
        }

        Base64Wire.DecodeTolerant(sb.ToString()).ShouldBe(Payload);
    }

    // ---------------------------------------------------------------- decode: round trip

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(257)]
    [InlineData(4096)]
    public void EncodeThenDecodeTolerant_RoundTrips(int length)
    {
        byte[] data = CreatePayload(length);

        string encoded = Base64Wire.Encode(data);

        if (length == 0)
        {
            // Convert.ToBase64String of nothing is the empty string, which the decoder rejects as
            // an empty body rather than round-tripping. That asymmetry is deliberate: an empty
            // EST body is a client error, never a legitimate zero-byte payload.
            encoded.ShouldBeEmpty();
            Should.Throw<EstCodecException>(() => Base64Wire.DecodeTolerant(encoded));
            return;
        }

        Base64Wire.DecodeTolerant(encoded).ShouldBe(data);
    }

    [Theory]
    [InlineData(3, 0)]   // length % 3 == 0 -> no padding
    [InlineData(300, 0)]
    [InlineData(4, 2)]   // length % 3 == 1 -> "=="
    [InlineData(301, 2)]
    [InlineData(5, 1)]   // length % 3 == 2 -> "="
    [InlineData(302, 1)]
    public void Encode_ProducesTheExpectedPadding(int length, int expectedPadding)
    {
        byte[] data = CreatePayload(length);

        string encoded = Base64Wire.Encode(data);

        encoded.Length.ShouldBe(4 * ((length + 2) / 3));
        encoded.Count(c => c == '=').ShouldBe(expectedPadding);
        encoded.TrimEnd('=').ShouldNotContain("=");

        // And the padding survives the tolerant decode path unchanged.
        Base64Wire.DecodeTolerant(encoded).ShouldBe(data);
    }

    [Fact]
    public void Encode_IsUnwrapped()
    {
        string encoded = Base64Wire.Encode(CreatePayload(1024));

        encoded.ShouldNotContain("\n");
        encoded.ShouldNotContain("\r");
    }

    // ---------------------------------------------------------------- decode: rejection

    [Fact]
    public void DecodeTolerant_RejectsNull()
    {
        EstCodecException ex = Should.Throw<EstCodecException>(() => Base64Wire.DecodeTolerant(null));

        ex.Message.ShouldContain("empty");
    }

    [Fact]
    public void DecodeTolerant_RejectsEmptyString()
    {
        EstCodecException ex = Should.Throw<EstCodecException>(() => Base64Wire.DecodeTolerant(string.Empty));

        ex.Message.ShouldContain("empty");
    }

    [Theory]
    [InlineData(" ")]
    [InlineData("\n")]
    [InlineData("\r\n")]
    [InlineData("\t")]
    [InlineData("   \r\n\t  \r\n")]
    public void DecodeTolerant_RejectsWhitespaceOnlyString(string input)
    {
        Should.Throw<EstCodecException>(() => Base64Wire.DecodeTolerant(input));
    }

    [Theory]
    [InlineData("!!!!")]
    [InlineData("abc")]              // length not a multiple of 4
    [InlineData("AAAAA")]
    [InlineData("QUJD*")]
    [InlineData("A===")]
    [InlineData("====")]
    [InlineData("QQ==QQ==")]         // padding in the middle
    [InlineData("not base64 at all")]
    [InlineData("éééé")]
    public void DecodeTolerant_RejectsInvalidBase64WithACodecException(string input)
    {
        // The point of this test is the *type*: callers map EstCodecException to 400, and a raw
        // FormatException escaping the codec would surface as a 500 instead.
        EstCodecException ex = Should.Throw<EstCodecException>(() => Base64Wire.DecodeTolerant(input));

        ex.ShouldBeOfType<EstCodecException>();
        ex.Message.ShouldContain("base64");
    }

    [Fact]
    public void DecodeTolerant_PreservesTheUnderlyingFormatExceptionAsInner()
    {
        EstCodecException ex = Should.Throw<EstCodecException>(() => Base64Wire.DecodeTolerant("!!!!"));

        ex.InnerException.ShouldBeOfType<FormatException>();
    }

    [Fact]
    public void DecodeTolerant_RejectsInvalidBase64ThatIsOnlyInvalidOnceWhitespaceIsStripped()
    {
        // "AA A" compacts to "AAA", which is not a valid base64 quantum.
        Should.Throw<EstCodecException>(() => Base64Wire.DecodeTolerant("AA A"));
    }

    // ---------------------------------------------------------------- EncodeWrapped

    [Theory]
    [InlineData(64)]
    [InlineData(76)]
    [InlineData(4)]
    [InlineData(1000)]
    public void EncodeWrapped_UsesTheRequestedLineLength(int lineLength)
    {
        byte[] data = CreatePayload(4096);

        string wrapped = Base64Wire.EncodeWrapped(data, lineLength);
        string[] lines = wrapped.Split('\n');

        lines.Length.ShouldBeGreaterThan(1);
        foreach (string line in lines[..^1])
        {
            line.Length.ShouldBe(lineLength);
        }

        lines[^1].Length.ShouldBeInRange(1, lineLength);
        wrapped.ShouldNotContain("\r");
    }

    [Theory]
    [InlineData(64)]
    [InlineData(76)]
    public void EncodeWrapped_RoundTripsThroughDecodeTolerant(int lineLength)
    {
        byte[] data = CreatePayload(3001);

        Base64Wire.DecodeTolerant(Base64Wire.EncodeWrapped(data, lineLength)).ShouldBe(data);
    }

    [Fact]
    public void EncodeWrapped_DefaultsToSixtyFour()
    {
        string wrapped = Base64Wire.EncodeWrapped(CreatePayload(1024));

        wrapped.Split('\n')[0].Length.ShouldBe(64);
    }

    [Fact]
    public void EncodeWrapped_LeavesShortPayloadsOnOneLine()
    {
        string wrapped = Base64Wire.EncodeWrapped(CreatePayload(9), 64);

        wrapped.ShouldNotContain("\n");
        wrapped.ShouldBe(Base64Wire.Encode(CreatePayload(9)));
    }

    [Fact]
    public void EncodeWrapped_EmitsNoTrailingNewline()
    {
        string wrapped = Base64Wire.EncodeWrapped(CreatePayload(4096), 64);

        wrapped.ShouldNotEndWith("\n");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(-1)]
    public void EncodeWrapped_RejectsUnusableLineLengths(int lineLength)
    {
        Should.Throw<ArgumentOutOfRangeException>(
            () => Base64Wire.EncodeWrapped(CreatePayload(64), lineLength));
    }

    // ---------------------------------------------------------------- helpers

    /// <summary>Deterministic pseudo-random bytes, so failures reproduce.</summary>
    private static byte[] CreatePayload(int length)
    {
        byte[] data = new byte[length];
        for (int i = 0; i < length; i++)
        {
            data[i] = (byte)((i * 37) ^ 0xA5);
        }

        return data;
    }

    private static string Wrap(string text, int width, string newLine)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < text.Length; i += width)
        {
            if (i > 0)
            {
                sb.Append(newLine);
            }

            sb.Append(text.AsSpan(i, Math.Min(width, text.Length - i)));
        }

        return sb.ToString();
    }
}
