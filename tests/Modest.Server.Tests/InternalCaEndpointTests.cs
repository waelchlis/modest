namespace Modest.Server.Tests;

/// <summary>The full EST surface against a host that signs with its own CA key.</summary>
[Collection(InternalCaHost.Name)]
public sealed class InternalCaEndpointTests(InternalCaFixture fixture)
    : EstEndpointTestsBase(fixture.Harness);
