using Modest.Server.Configuration;

namespace Modest.Server.Tests;

/// <summary>
/// A running host, shared by every test class in one collection.
/// </summary>
/// <remarks>
/// Starting Kestrel and loading PKI material costs far more than any single request, and none of the
/// tests sharing a host mutate its configuration — the ones that need different configuration get
/// their own host instead.
/// </remarks>
public abstract class ModestServerFixture : IAsyncLifetime
{
    private ModestServerHarness? _harness;

    /// <summary>The running host.</summary>
    public ModestServerHarness Harness =>
        _harness ?? throw new InvalidOperationException("The fixture has not been initialised.");

    /// <summary>Configures the host this fixture runs.</summary>
    protected abstract void Configure(HarnessOptions options);

    public async Task InitializeAsync() =>
        _harness = await ModestServerHarness.StartAsync(Configure).ConfigureAwait(false);

    public async Task DisposeAsync()
    {
        if (_harness is not null)
        {
            await _harness.DisposeAsync().ConfigureAwait(false);
        }
    }
}

/// <summary>A host signing with a locally held CA key.</summary>
public sealed class InternalCaFixture : ModestServerFixture
{
    protected override void Configure(HarnessOptions options) =>
        options.Mode = IssuanceMode.InternalCa;
}

/// <summary>A host forwarding every CSR to the stub upstream issuance API.</summary>
public sealed class HttpDelegateFixture : ModestServerFixture
{
    protected override void Configure(HarnessOptions options) =>
        options.Mode = IssuanceMode.HttpDelegate;
}

[CollectionDefinition(Name)]
public sealed class InternalCaHost : ICollectionFixture<InternalCaFixture>
{
    public const string Name = "modest-internal-ca";
}

[CollectionDefinition(Name)]
public sealed class HttpDelegateHost : ICollectionFixture<HttpDelegateFixture>
{
    public const string Name = "modest-http-delegate";
}
