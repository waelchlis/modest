using Modest.Core.Issuance;

namespace Modest.Issuance.HttpDelegate.Tests;

/// <summary>
/// /cacerts and /readyz behaviour, both of which are answered entirely from the statically
/// configured PEM chain file.
/// </summary>
/// <remarks>
/// The chain is static rather than harvested from issuance responses because /cacerts has to answer
/// a client that has never enrolled — the bootstrap case — when a harvested cache would be empty.
/// </remarks>
public sealed class CaChainTests
{
    [Fact]
    public async Task The_configured_chain_file_is_served_with_the_right_count_and_order()
    {
        using var harness = IssuerHarness.Create();

        CaChainResult chain = await harness.Issuer.GetCaChainAsync(CancellationToken.None);

        chain.Chain.Count.ShouldBe(2);
        chain.Chain[0].Thumbprint.ShouldBe(SharedPki.Ca.Intermediate!.Thumbprint);
        chain.Chain[1].Thumbprint.ShouldBe(SharedPki.Ca.Root.Thumbprint);
    }

    [Fact]
    public async Task The_chain_file_is_read_once_and_cached()
    {
        using var harness = IssuerHarness.Create();

        CaChainResult first = await harness.Issuer.GetCaChainAsync(CancellationToken.None);

        // Deleting the file after the first read proves the second answer did not touch the disk.
        File.Delete(Path.Combine(harness.TempPath, "chain.pem"));

        CaChainResult second = await harness.Issuer.GetCaChainAsync(CancellationToken.None);

        second.Chain.Count.ShouldBe(first.Chain.Count);
        second.Chain[0].Thumbprint.ShouldBe(first.Chain[0].Thumbprint);
    }

    [Fact]
    public async Task A_missing_chain_file_surfaces_as_a_configuration_failure()
    {
        using var harness = IssuerHarness.Create(writeChainFile: false);

        var exception = await Should.ThrowAsync<PkiConfigurationException>(
            async () => await harness.Issuer.GetCaChainAsync(CancellationToken.None));

        exception.Message.ShouldContain("absent-chain.pem");
    }

    [Fact]
    public async Task An_empty_chain_file_surfaces_as_a_configuration_failure()
    {
        using var harness = IssuerHarness.Create();
        File.WriteAllText(Path.Combine(harness.TempPath, "chain.pem"), "# no certificates here\n");

        await Should.ThrowAsync<PkiConfigurationException>(
            async () => await harness.Issuer.GetCaChainAsync(CancellationToken.None));
    }

    [Fact]
    public async Task IsReadyAsync_is_true_when_the_chain_loads()
    {
        using var harness = IssuerHarness.Create();

        (await harness.Issuer.IsReadyAsync(CancellationToken.None)).ShouldBeTrue();
    }

    [Fact]
    public async Task IsReadyAsync_is_false_when_the_chain_file_is_missing()
    {
        // Readiness has to answer from local state without probing the upstream: a transient blip at
        // someone else's CA must not cycle this pod.
        using var harness = IssuerHarness.Create(writeChainFile: false);

        (await harness.Issuer.IsReadyAsync(CancellationToken.None)).ShouldBeFalse();
    }

    [Fact]
    public async Task IsReadyAsync_does_not_call_the_upstream()
    {
        using var harness = IssuerHarness.Create();

        await harness.Issuer.IsReadyAsync(CancellationToken.None);

        harness.ReceivedRequests.ShouldBeEmpty();
    }
}
