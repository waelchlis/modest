using System.Collections.Concurrent;
using System.Globalization;
using Microsoft.Extensions.Logging;

namespace Modest.Server.Tests;

/// <summary>
/// An <see cref="ILoggerProvider"/> that keeps every line the running host logged, so a test can
/// assert on the audit trail and search the whole log surface for a secret that should never have
/// been written to it.
/// </summary>
public sealed class CapturingLoggerProvider : ILoggerProvider
{
    private readonly ConcurrentQueue<string> _entries = new();

    /// <summary>Every captured line: level, category, rendered message, structured values, exception.</summary>
    public IReadOnlyList<string> Entries => [.. _entries];

    /// <summary>All captured output as one blob, for substring searching.</summary>
    public string AllText => string.Join('\n', _entries);

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, _entries);

    public void Dispose()
    {
    }

    private sealed class CapturingLogger(string category, ConcurrentQueue<string> sink) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull
        {
            sink.Enqueue(string.Create(CultureInfo.InvariantCulture, $"SCOPE {category} {Describe(state)}"));
            return NullScope.Instance;
        }

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            ArgumentNullException.ThrowIfNull(formatter);

            // Both the rendered message and the raw structured values are captured: a secret could
            // leak through either, and a test that only searched the rendered text would miss the
            // case where a value is carried as a log property.
            string line = string.Create(
                CultureInfo.InvariantCulture,
                $"{logLevel} {category} [{eventId.Id}] {formatter(state, exception)} || {Describe(state)} || {exception}");

            sink.Enqueue(line);
        }

        private static string Describe<TState>(TState state) =>
            state is IEnumerable<KeyValuePair<string, object?>> pairs
                ? string.Join(
                    ", ",
                    pairs.Select(static p => string.Create(CultureInfo.InvariantCulture, $"{p.Key}={p.Value}")))
                : state?.ToString() ?? string.Empty;
    }

    private sealed class NullScope : IDisposable
    {
        public static readonly NullScope Instance = new();

        public void Dispose()
        {
        }
    }
}
