using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace Modest.Codec.Tests;

/// <summary>
/// A scratch directory under the system temp path that deletes itself.
/// </summary>
internal sealed class TempDirectory : IDisposable
{
    public TempDirectory()
    {
        FullPath = Path.Combine(
            Path.GetTempPath(),
            "modest-codec-tests-" + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture));

        Directory.CreateDirectory(FullPath);
    }

    public string FullPath { get; }

    public string File(string name) => Path.Combine(FullPath, name);

    public void Dispose()
    {
        try
        {
            Directory.Delete(FullPath, recursive: true);
        }
        catch (IOException)
        {
            // A leftover scratch directory is not worth failing a test over.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

internal sealed record OpenSslResult(int ExitCode, string StandardOutput, string StandardError)
{
    public bool Succeeded => ExitCode == 0;

    public string Describe() =>
        $"exit {ExitCode}{Environment.NewLine}stdout: {StandardOutput}{Environment.NewLine}stderr: {StandardError}";
}

/// <summary>
/// Runs the real <c>openssl</c> binary. This is the independent oracle for the codec: assertions
/// made only against Modest's own reader prove self-consistency, not interoperability.
/// </summary>
internal static class OpenSsl
{
    private static readonly Lazy<bool> Probe = new(DetectOpenSsl, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>True when an <c>openssl</c> binary is on PATH and answers <c>version</c>.</summary>
    public static bool IsAvailable => Probe.Value;

    public static OpenSslResult Run(string arguments, string workingDirectory)
    {
        var startInfo = new ProcessStartInfo("openssl")
        {
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        foreach (string argument in SplitArguments(arguments))
        {
            startInfo.ArgumentList.Add(argument);
        }

        using Process process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start openssl.");

        process.StandardInput.Close();

        // Drain both pipes concurrently; a chatty openssl filling one buffer would otherwise
        // deadlock the wait below.
        Task<string> stdout = process.StandardOutput.ReadToEndAsync();
        Task<string> stderr = process.StandardError.ReadToEndAsync();

        if (!process.WaitForExit(60_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"openssl {arguments} did not finish within 60s.");
        }

        return new OpenSslResult(process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult());
    }

    /// <summary>Runs openssl and fails the test with the captured output if it does not succeed.</summary>
    public static OpenSslResult RunOrFail(string arguments, string workingDirectory)
    {
        OpenSslResult result = Run(arguments, workingDirectory);

        result.Succeeded.ShouldBeTrue($"openssl {arguments} failed: {result.Describe()}");
        return result;
    }

    private static bool DetectOpenSsl()
    {
        try
        {
            return Run("version", Path.GetTempPath()).Succeeded;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (TimeoutException)
        {
            return false;
        }
    }

    /// <summary>
    /// Minimal shell-like splitter so tests can write command lines as one readable string while
    /// still passing arguments through ArgumentList (no shell involved, so no quoting hazards).
    /// </summary>
    private static List<string> SplitArguments(string arguments)
    {
        List<string> parts = [];
        var current = new StringBuilder();
        char quote = '\0';

        foreach (char c in arguments)
        {
            if (quote != '\0')
            {
                if (c == quote)
                {
                    quote = '\0';
                }
                else
                {
                    current.Append(c);
                }

                continue;
            }

            switch (c)
            {
                case '"':
                case '\'':
                    quote = c;
                    break;
                case ' ':
                    if (current.Length > 0)
                    {
                        parts.Add(current.ToString());
                        current.Clear();
                    }

                    break;
                default:
                    current.Append(c);
                    break;
            }
        }

        if (current.Length > 0)
        {
            parts.Add(current.ToString());
        }

        return parts;
    }
}
