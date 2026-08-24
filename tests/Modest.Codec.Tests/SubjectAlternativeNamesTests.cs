using System.Net;

namespace Modest.Codec.Tests;

/// <summary>
/// SetEquals backs the re-enrollment identity check: "does the new CSR ask for the same names the
/// existing certificate already asserts?". Getting the comparison wrong in the permissive direction
/// silently authorises a name change, so the type-tagging is a security property, not a nicety.
/// </summary>
public sealed class SubjectAlternativeNamesTests
{
    [Fact]
    public void SetEquals_IgnoresOrder()
    {
        SubjectAlternativeNames a = Sans(
            dns: ["a.example.com", "b.example.com", "c.example.com"],
            ips: ["192.0.2.1", "192.0.2.2"],
            emails: ["one@example.com", "two@example.com"]);

        SubjectAlternativeNames b = Sans(
            dns: ["c.example.com", "a.example.com", "b.example.com"],
            ips: ["192.0.2.2", "192.0.2.1"],
            emails: ["two@example.com", "one@example.com"]);

        a.SetEquals(b).ShouldBeTrue();
        b.SetEquals(a).ShouldBeTrue();
    }

    [Fact]
    public void SetEquals_IsFalseForDifferentSets()
    {
        SubjectAlternativeNames a = Sans(dns: ["a.example.com"]);
        SubjectAlternativeNames b = Sans(dns: ["b.example.com"]);

        a.SetEquals(b).ShouldBeFalse();
        b.SetEquals(a).ShouldBeFalse();
    }

    [Fact]
    public void SetEquals_IsFalseWhenOneSideHasAnExtraName()
    {
        SubjectAlternativeNames a = Sans(dns: ["a.example.com"]);
        SubjectAlternativeNames b = Sans(dns: ["a.example.com", "b.example.com"]);

        a.SetEquals(b).ShouldBeFalse();
        b.SetEquals(a).ShouldBeFalse();
    }

    [Fact]
    public void SetEquals_DoesNotConflateADnsNameWithAnIpAddress()
    {
        // The attack this blocks: a client holding a certificate for the IP 1.2.3.4 re-enrolling
        // for the *DNS name* "1.2.3.4" (or the reverse). Flattened to strings the two look
        // identical; as identities they are not remotely the same thing.
        SubjectAlternativeNames asDns = Sans(dns: ["1.2.3.4"]);
        SubjectAlternativeNames asIp = Sans(ips: ["1.2.3.4"]);

        asDns.SetEquals(asIp).ShouldBeFalse();
        asIp.SetEquals(asDns).ShouldBeFalse();
    }

    [Fact]
    public void SetEquals_DoesNotConflateADnsNameWithAnEmailAddress()
    {
        SubjectAlternativeNames asDns = Sans(dns: ["admin@example.com"]);
        SubjectAlternativeNames asEmail = Sans(emails: ["admin@example.com"]);

        asDns.SetEquals(asEmail).ShouldBeFalse();
        asEmail.SetEquals(asDns).ShouldBeFalse();
    }

    [Fact]
    public void SetEquals_DoesNotConflateAUpnWithAnEmailAddress()
    {
        var asUpn = new SubjectAlternativeNames([], [], [], ["user@example.com"], []);
        SubjectAlternativeNames asEmail = Sans(emails: ["user@example.com"]);

        asUpn.SetEquals(asEmail).ShouldBeFalse();
        asEmail.SetEquals(asUpn).ShouldBeFalse();
    }

    [Fact]
    public void SetEquals_TreatsDnsNamesCaseInsensitively()
    {
        SubjectAlternativeNames lower = Sans(dns: ["device01.example.com"]);
        SubjectAlternativeNames mixed = Sans(dns: ["Device01.Example.COM"]);

        lower.SetEquals(mixed).ShouldBeTrue();
        mixed.SetEquals(lower).ShouldBeTrue();
    }

    [Fact]
    public void SetEquals_TreatsEmailAddressesCaseInsensitively()
    {
        SubjectAlternativeNames lower = Sans(emails: ["dev@example.com"]);
        SubjectAlternativeNames mixed = Sans(emails: ["Dev@Example.COM"]);

        lower.SetEquals(mixed).ShouldBeTrue();
    }

    [Fact]
    public void SetEquals_TreatsUserPrincipalNamesCaseInsensitively()
    {
        var lower = new SubjectAlternativeNames([], [], [], ["user@corp.example"], []);
        var mixed = new SubjectAlternativeNames([], [], [], ["USER@CORP.EXAMPLE"], []);

        lower.SetEquals(mixed).ShouldBeTrue();
    }

    [Fact]
    public void SetEquals_TreatsUrisCaseSensitively()
    {
        // Deliberate asymmetry with DNS/email: a URI path is case-sensitive, so folding case here
        // would call two different resources the same identity.
        var lower = new SubjectAlternativeNames([], [], [], [], ["https://example.com/device/a"]);
        var upper = new SubjectAlternativeNames([], [], [], [], ["https://example.com/device/A"]);

        lower.SetEquals(upper).ShouldBeFalse();
        lower.SetEquals(new SubjectAlternativeNames([], [], [], [], ["https://example.com/device/a"]))
            .ShouldBeTrue();
    }

    [Fact]
    public void SetEquals_ComparesIpAddressesByValueNotInstance()
    {
        SubjectAlternativeNames a = Sans(ips: ["2001:db8::1", "192.0.2.1"]);
        SubjectAlternativeNames b = Sans(ips: ["192.0.2.1", "2001:db8::1"]);

        a.SetEquals(b).ShouldBeTrue();
        a.SetEquals(Sans(ips: ["192.0.2.1"])).ShouldBeFalse();
        a.SetEquals(Sans(ips: ["192.0.2.1", "2001:db8::2"])).ShouldBeFalse();
    }

    [Fact]
    public void SetEquals_IgnoresDuplicateEntries()
    {
        // Set semantics: a repeated name is still the same set of identities.
        SubjectAlternativeNames withDuplicate = Sans(dns: ["a.example.com", "a.example.com"]);
        SubjectAlternativeNames without = Sans(dns: ["a.example.com"]);

        withDuplicate.SetEquals(without).ShouldBeTrue();
        without.SetEquals(withDuplicate).ShouldBeTrue();
    }

    [Fact]
    public void SetEquals_HoldsForTwoEmptySets()
    {
        SubjectAlternativeNames.Empty.SetEquals(SubjectAlternativeNames.Empty).ShouldBeTrue();
        SubjectAlternativeNames.Empty.SetEquals(Sans()).ShouldBeTrue();
        Sans().SetEquals(SubjectAlternativeNames.Empty).ShouldBeTrue();
    }

    [Fact]
    public void SetEquals_IsFalseBetweenEmptyAndPopulated()
    {
        SubjectAlternativeNames.Empty.SetEquals(Sans(dns: ["a.example.com"])).ShouldBeFalse();
        Sans(dns: ["a.example.com"]).SetEquals(SubjectAlternativeNames.Empty).ShouldBeFalse();
    }

    [Fact]
    public void SetEquals_RejectsNull()
    {
        Should.Throw<ArgumentNullException>(() => SubjectAlternativeNames.Empty.SetEquals(null!));
    }

    [Fact]
    public void Empty_IsEmpty()
    {
        SubjectAlternativeNames.Empty.IsEmpty.ShouldBeTrue();
        SubjectAlternativeNames.Empty.DnsNames.ShouldBeEmpty();
        SubjectAlternativeNames.Empty.IPAddresses.ShouldBeEmpty();
        SubjectAlternativeNames.Empty.EmailAddresses.ShouldBeEmpty();
        SubjectAlternativeNames.Empty.UserPrincipalNames.ShouldBeEmpty();
        SubjectAlternativeNames.Empty.Uris.ShouldBeEmpty();
    }

    [Theory]
    [InlineData("dns")]
    [InlineData("ip")]
    [InlineData("email")]
    [InlineData("upn")]
    [InlineData("uri")]
    public void IsEmpty_IsFalseWhenAnyTypeIsPopulated(string kind)
    {
        SubjectAlternativeNames sans = kind switch
        {
            "dns" => Sans(dns: ["a.example.com"]),
            "ip" => Sans(ips: ["192.0.2.1"]),
            "email" => Sans(emails: ["a@example.com"]),
            "upn" => new SubjectAlternativeNames([], [], [], ["u@example.com"], []),
            _ => new SubjectAlternativeNames([], [], [], [], ["https://example.com/a"]),
        };

        sans.IsEmpty.ShouldBeFalse();
    }

    private static SubjectAlternativeNames Sans(
        string[]? dns = null,
        string[]? ips = null,
        string[]? emails = null) =>
        new(
            dns ?? [],
            (ips ?? []).Select(IPAddress.Parse).ToList(),
            emails ?? [],
            [],
            []);
}
