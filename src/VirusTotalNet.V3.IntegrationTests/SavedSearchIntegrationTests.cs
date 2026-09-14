using VirusTotalNet.V3.Core;

namespace VirusTotalNet.V3.IntegrationTests;

[Trait(TestKey.TraitCategory, "Integration")]
public class SavedSearchIntegrationTests
{
    [SkippableFact]
    public async Task SavedSearch_CRUD_Cycle()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        await TestKey.RunUnlicensedAwareAsync(async () =>
        {
            var name = $"integration-test-{DateTime.UtcNow:yyyyMMddHHmmss}";

            // Create
            var created = await vt.CreateSavedSearchAsync(name, "type:domain domain:example.com", description: "Integration test");
            Assert.NotNull(created);
            Assert.NotNull(created.Id);
            Assert.Equal(name, created.Attributes?.Name);

            var id = created.Id!;

            try
            {
                // Get
                var fetched = await vt.GetSavedSearchAsync(id);
                Assert.NotNull(fetched);
                Assert.Equal(id, fetched!.Id);
                Assert.Equal(name, fetched.Attributes?.Name);

                // List
                var list = await vt.ListSavedSearchesAsync();
                Assert.NotNull(list);
                Assert.True(list.Items!.Count >= 1);
            }
            finally
            {
                // Cleanup
                await vt.DeleteSavedSearchAsync(id);
            }
        });
    }
}