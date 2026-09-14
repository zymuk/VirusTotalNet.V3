using VirusTotalNet.V3.Core;

namespace VirusTotalNet.V3.IntegrationTests;

[Trait(TestKey.TraitCategory, "Integration")]
public class UrlIntegrationTests
{
    [SkippableFact]
    public async Task ScanUrl_WaitForCompletion_GetUrlReport()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        // 1. Scan URL
        var analysis = await vt.ScanUrlAsync("https://example.com");
        Assert.NotNull(analysis);
        Assert.Equal("analysis", analysis!.Type);
        Assert.NotNull(analysis.Id);

        // 2. Wait for completion
        var completed = await vt.WaitForCompletionAsync(analysis.Id!, TimeSpan.FromSeconds(5));
        Assert.NotNull(completed);
        Assert.Equal("completed", completed!.Attributes?.Status);

        // 3. Get URL report
        var urlReport = await vt.GetUrlAsync("https://example.com");
        Assert.NotNull(urlReport);
        Assert.Equal("url", urlReport!.Type);
        Assert.NotNull(urlReport.Id);
        Assert.NotNull(urlReport.Attributes);
        Assert.NotNull(urlReport.Attributes!.LastAnalysisStats);
    }

    [SkippableFact]
    public void EncodeUrlId_RoundTrip()
    {
        TestKey.SkipIfUnavailable();

        var encoded = VirusTotal.EncodeUrlId("https://example.com/path?q=1&r=2");
        Assert.False(string.IsNullOrWhiteSpace(encoded));
        Assert.DoesNotContain("/", encoded);
        Assert.DoesNotContain("=", encoded);
        Assert.DoesNotContain("+", encoded);
    }
}
