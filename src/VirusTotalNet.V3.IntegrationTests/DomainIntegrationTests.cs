using VirusTotalNet.V3.Core;

namespace VirusTotalNet.V3.IntegrationTests;

[Trait(TestKey.TraitCategory, "Integration")]
public class DomainIntegrationTests
{
    [SkippableFact]
    public async Task GetDomain_ReturnsAttributes()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        var domain = await vt.GetDomainAsync("example.com");
        Assert.NotNull(domain);
        Assert.Equal("domain", domain!.Type);
        Assert.Equal("example.com", domain.Id);
        Assert.NotNull(domain.Attributes);
        Assert.NotNull(domain.Attributes!.LastAnalysisStats);
    }

    [SkippableFact]
    public async Task GetDomainResolutions_ReturnsCollection()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        var resolutions = await vt.GetDomainResolutionsAsync("example.com");
        Assert.NotNull(resolutions);
        // Resolutions may be empty for well-known domains, but should parse without error
        Assert.NotNull(resolutions.Items);
    }

    [SkippableFact]
    public async Task GetDomainSubdomains_ReturnsCollection()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        var subdomains = await vt.GetDomainSubdomainsAsync("example.com");
        Assert.NotNull(subdomains);
        Assert.NotNull(subdomains.Items);
    }
}
