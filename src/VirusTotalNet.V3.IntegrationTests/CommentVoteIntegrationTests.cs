using System.Text;
using VirusTotalNet.V3.Core;

namespace VirusTotalNet.V3.IntegrationTests;

[Trait(TestKey.TraitCategory, "Integration")]
public class CommentVoteIntegrationTests
{
    private const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    [SkippableFact]
    public async Task AddVote_AndListVotes()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        // Add a harmless vote on a well-known file (idempotent: a repeated identical vote is rejected)
        try
        {
            var vote = await vt.AddVoteAsync("files", EicarSha256, "harmless");
            Assert.NotNull(vote);
            Assert.Equal("vote", vote!.Type);
            Assert.NotNull(vote.Attributes);
            Assert.Equal("harmless", vote.Attributes!.Verdict);
        }
        catch (VtHttpException ex) when (ex.Message.Contains("already voted", StringComparison.OrdinalIgnoreCase))
        {
        }

        // List votes
        var votes = await vt.GetVotesAsync("files", EicarSha256);
        Assert.NotNull(votes);
        Assert.True(votes.Items!.Count >= 1);
    }

    [SkippableFact]
    public async Task AddComment_AndListComments()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        var text = $"integration-test-{DateTime.UtcNow.Ticks}";

        // Add comment
        var comment = await vt.AddCommentAsync("files", EicarSha256, text);
        Assert.NotNull(comment);
        Assert.Equal("comment", comment!.Type);
        Assert.NotNull(comment.Attributes);
        Assert.Equal(text, comment.Attributes!.Text);

        // List comments
        var comments = await vt.GetCommentsAsync("files", EicarSha256);
        Assert.NotNull(comments);
        Assert.True(comments.Items!.Count >= 1);
    }

    [SkippableFact]
    public async Task ListLatestComments_ReturnsCollection()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        var comments = await vt.ListLatestCommentsAsync(limit: 5);
        Assert.NotNull(comments);
        Assert.NotNull(comments.Items);
    }
}
