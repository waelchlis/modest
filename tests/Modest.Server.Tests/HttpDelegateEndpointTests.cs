namespace Modest.Server.Tests;

/// <summary>
/// The same EST surface again, against a host that holds no CA key and forwards every CSR to an
/// external issuance API.
/// </summary>
/// <remarks>
/// Not a duplicate of <see cref="InternalCaEndpointTests"/>: it is the assertion that the protocol
/// layer is genuinely independent of the issuer behind it. A status code that came out right only
/// because the internal CA happened to produce it would fail here.
/// </remarks>
[Collection(HttpDelegateHost.Name)]
public sealed class HttpDelegateEndpointTests(HttpDelegateFixture fixture)
    : EstEndpointTestsBase(fixture.Harness);
