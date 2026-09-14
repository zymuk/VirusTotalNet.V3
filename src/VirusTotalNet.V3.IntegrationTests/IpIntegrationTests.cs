using VirusTotalNet.V3.Core;

namespace VirusTotalNet.V3.IntegrationTests;

[Trait(TestKey.TraitCategory, "Integration")]
public class IpIntegrationTests
{
    [SkippableFact]
    public async Task GetIp_ReturnsAttributes()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        var ip = await vt.GetIpAsync("8.8.8.8");
        Assert.NotNull(ip);
        Assert.Equal("ip_address", ip!.Type);
        Assert.Equal("8.8.8.8", ip.Id);
        Assert.NotNull(ip.Attributes);
        Assert.NotNull(ip.Attributes!.LastAnalysisStats);
        Assert.False(string.IsNullOrWhiteSpace(ip.Attributes.Country));
        Assert.False(string.IsNullOrWhiteSpace(ip.Attributes.AsOwner));
    }

    [SkippableFact]
    public async Task GetIpResolutions_ReturnsCollection()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        var resolutions = await vt.GetIpResolutionsAsync("8.8.8.8");
        Assert.NotNull(resolutions);
        Assert.NotNull(resolutions.Items);
    }
}
