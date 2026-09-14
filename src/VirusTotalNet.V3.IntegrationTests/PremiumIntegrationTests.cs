using System.Text;
using VirusTotalNet.V3.Core;

namespace VirusTotalNet.V3.IntegrationTests;

[Trait(TestKey.TraitCategory, "Integration")]
public class PremiumIntegrationTests
{
    private const string EicarContent = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    [SkippableFact]
    public async Task PrivateScanning_Upload_Get_Delete()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        await TestKey.RunUnlicensedAwareAsync(async () =>
        {
            // 1. Upload private file
            await using var stream = new MemoryStream(Encoding.UTF8.GetBytes(EicarContent), writable: false);
            var analysis = await vt.UploadPrivateFileAsync(stream);
            Assert.NotNull(analysis);
            Assert.Equal("analysis", analysis!.Type);
            Assert.NotNull(analysis.Id);

            // 2. Get private file
            try
            {
                var file = await vt.GetPrivateFileAsync(analysis.Id!);
                Assert.NotNull(file);
                Assert.Equal("private_file", file!.Type);
            }
            finally
            {
                // 3. Delete (cleanup)
                await vt.DeletePrivateFileAsync(analysis.Id!);
            }
        });
    }

    [SkippableFact]
    public async Task PrivateScanning_GetUploadUrl()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        await TestKey.RunUnlicensedAwareAsync(async () =>
        {
            var url = await vt.GetPrivateFileUploadUrlAsync();
            Assert.False(string.IsNullOrWhiteSpace(url));
            Assert.StartsWith("https://", url);
        });
    }

    [SkippableFact]
    public async Task Hunting_CreateListDelete_Ruleset()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        await TestKey.RunUnlicensedAwareAsync(async () =>
        {
            var name = $"test-ruleset-{DateTime.UtcNow:yyyyMMddHHmmss}";
            var rules = "rule test { condition: filesize < 100KB }";

            // Create
            var created = await vt.CreateRulesetAsync(name, rules, enabled: false);
            Assert.NotNull(created);
            Assert.NotNull(created.Id);
            Assert.Equal(name, created.Attributes?.Name);

            var id = created.Id!;

            try
            {
                // Get
                var fetched = await vt.GetRulesetAsync(id);
                Assert.NotNull(fetched);
                Assert.Equal(id, fetched!.Id);

                // List
                var list = await vt.ListRulesetsAsync();
                Assert.NotNull(list);
                Assert.True(list.Items!.Count >= 1);
            }
            finally
            {
                await vt.DeleteRulesetAsync(id);
            }
        });
    }

    [SkippableFact]
    public async Task Feeds_GetFileFeedStream()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        await TestKey.RunUnlicensedAwareAsync(async () =>
        {
            // Per-minute feeds use YYYYMMDDhhmm (UTC). Pick a slot roughly one hour back.
            var time = DateTime.UtcNow.AddHours(-1).ToString("yyyyMMddHHmm");

            await using var stream = await vt.GetFileFeedStreamAsync(time);
            Assert.NotNull(stream);

            var buffer = new byte[1024];
            var read = await stream.ReadAsync(buffer);
            Assert.True(read > 0, "Feeds stream should contain data bytes");
        });
    }

    [SkippableFact]
    public async Task Retrohunt_CreateListJobs()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        await TestKey.RunUnlicensedAwareAsync(async () =>
        {
            var rules = "rule test { condition: filesize < 100KB }";

            // Create job
            var job = await vt.CreateRetrohuntJobAsync(rules, corpus: "main");
            Assert.NotNull(job);
            Assert.NotNull(job.Id);

            var id = job.Id!;

            try
            {
                // Get
                var fetched = await vt.GetRetrohuntJobAsync(id);
                Assert.NotNull(fetched);
                Assert.Equal(id, fetched!.Id);

                // List
                var list = await vt.ListRetrohuntJobsAsync();
                Assert.NotNull(list);
                Assert.True(list.Items!.Count >= 1);
            }
            finally
            {
                try
                {
                    // Abort (cleanup) — tolerated failing if the job already ran to completion
                    await vt.AbortRetrohuntJobAsync(id);
                }
                catch (VtHttpException)
                {
                    // Job may have already finished; not a failure for the integration check
                }
            }
        });
    }
}