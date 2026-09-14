using VirusTotalNet.V3.Core;

namespace VirusTotalNet.V3.IntegrationTests;

[Trait(TestKey.TraitCategory, "Integration")]
public class SearchIntegrationTests
{
    [SkippableFact]
    public async Task SearchDomain_ReturnsCollection()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        await TestKey.RunUnlicensedAwareAsync(async () =>
        {
            var results = await vt.SearchAsync("type:domain domain:example.com", descriptorsOnly: true, limit: 5);
            Assert.NotNull(results);
            Assert.NotNull(results.Items);
            Assert.True(results.Count >= 0);
        });
    }
}