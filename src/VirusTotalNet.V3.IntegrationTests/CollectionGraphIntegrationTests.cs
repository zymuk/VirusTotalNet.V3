using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.IntegrationTests;

[Trait(TestKey.TraitCategory, "Integration")]
public class CollectionGraphIntegrationTests
{
    [SkippableFact]
    public async Task Collection_CRUD_Cycle()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        var name = $"test-collection-{DateTime.UtcNow:yyyyMMddHHmmss}";

        // Create
        var created = await vt.CreateCollectionAsync(name, description: "Integration test");
        Assert.NotNull(created);
        Assert.NotNull(created.Id);
        Assert.Equal(name, created.Attributes?.Name);

        var id = created.Id!;

        try
        {
            // Get
            var fetched = await vt.GetCollectionAsync(id);
            Assert.NotNull(fetched);
            Assert.Equal(id, fetched!.Id);

            // Update
            var updated = await vt.UpdateCollectionAsync(id, description: "Updated description");
            Assert.NotNull(updated);
            Assert.Equal("Updated description", updated!.Attributes?.Description);
        }
        finally
        {
            await vt.DeleteCollectionAsync(id);
        }
    }

    [SkippableFact]
    public async Task Graph_CRUD_Cycle()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        // Create graph with required content (graph_data requires a version key)
        var graphData = new GraphData { Description = "Integration test graph", Version = "1" };
        var nodes = new List<GraphNode>
        {
            new() { EntityId = "example.com", Type = "domain", Text = "example.com", Index = 0 }
        };

        var created = await vt.CreateGraphAsync(graphData: graphData, nodes: nodes);
        Assert.NotNull(created);
        Assert.NotNull(created.Id);

        var id = created.Id!;

        try
        {
            // Get
            var fetched = await vt.GetGraphAsync(id);
            Assert.NotNull(fetched);
            Assert.Equal(id, fetched!.Id);
            Assert.NotNull(fetched.Attributes);

            // Update
            var newGraphData = new GraphData { Description = "Updated graph", Version = "1" };
            var updated = await vt.UpdateGraphAsync(id, graphData: newGraphData);
            Assert.NotNull(updated);
        }
        finally
        {
            await vt.DeleteGraphAsync(id);
        }
    }
}