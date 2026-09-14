using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;


namespace VirusTotalNet.V3.IntegrationTests;

[Trait(TestKey.TraitCategory, "Integration")]
public class RelationshipIntegrationTests
{
    private const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    [SkippableFact]
    public async Task GetContactedUrls_OnFile()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        var urls = await vt.GetRelatedAsync<UrlObject>("files", EicarSha256, "contacted_urls");
        Assert.NotNull(urls);
        Assert.NotNull(urls.Items);
    }

    [SkippableFact]
    public async Task GetComments_OnFile()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        var comments = await vt.GetRelatedAsync<CommentObject>("files", EicarSha256, "comments");
        Assert.NotNull(comments);
        Assert.NotNull(comments.Items);
    }

    [SkippableFact]
    public async Task GetVotes_OnFile()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        var votes = await vt.GetRelatedAsync<VoteObject>("files", EicarSha256, "votes");
        Assert.NotNull(votes);
        Assert.NotNull(votes.Items);
    }

    [SkippableFact]
    public async Task GetRelatedIds_DescriptorFirst()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        var ids = await vt.Relationships.GetRelatedIdsAsync("files", EicarSha256, "contacted_urls");
        Assert.NotNull(ids);
        Assert.NotNull(ids.Items);

        foreach (var id in ids.Items!)
        {
            Assert.False(string.IsNullOrWhiteSpace(id.Id));
        }
    }
}
