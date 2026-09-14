using System;
using System.Threading.Tasks;
using System.Net;
using System.Net.Http;
using VirusTotalNet.V3.Tests.TestInternals;
using VirusTotalNet.V3.Clients;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;
using Xunit;

namespace VirusTotalNet.V3.Tests;

public class GraphClientTests
{
    private static VirusTotalOptions Options(string key = "test-key")
        => new() { ApiKey = key };

    [Fact]
    public async Task CreateGraph_PostsGraphDataNodesLinksAndPrivate()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "graph", "id": "g123" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new GraphClient(vt);

        var graphData = new GraphData { Description = "My graph", Version = "5.0.0" };
        var nodes = new[] { new GraphNode { EntityId = "hash1", Type = "file", Index = 0, Text = "root" } };
        var links = new[] { new GraphLink { Source = "a", Target = "b", ConnectionType = "last_serving_ip_address" } };

        var graph = await client.CreateGraphAsync(graphData, nodes, links, isPrivate: true);

        Assert.Equal("g123", graph!.Id);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "graphs", request.RequestUri!.ToString());
        Assert.Contains("\"graph_data\":{\"description\":\"My graph\",\"version\":\"5.0.0\"}", handler.LastRequestBody);
        Assert.Contains("\"nodes\":[{\"entity_id\":\"hash1\"", handler.LastRequestBody);
        Assert.Contains("\"links\":[{\"source\":\"a\",", handler.LastRequestBody);
        Assert.Contains("\"private\":true", handler.LastRequestBody);
    }

    [Fact]
    public async Task CreateGraph_NoContent_Throws()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new GraphClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(() => client.CreateGraphAsync());
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task GetGraph_SendsGet_AndDeserializesAttributes()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{"data":{"type":"graph","id":"g123","attributes":{"graph_data":{"description":"My graph","version":"5.0.0"},"nodes":[{"entity_id":"hash1","type":"file","index":0,"text":"root"}],"links":[{"source":"a","target":"b","connection_type":"last_serving_ip_address"}],"private":false,"views_count":2,"comments_count":1,"creation_date":1599060646}}}"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new GraphClient(vt);

        var graph = await client.GetGraphAsync("g123");

        var attrs = graph!.Attributes!;
        Assert.Equal("My graph", attrs.GraphData!.Description);
        Assert.Equal("5.0.0", attrs.GraphData!.Version);
        Assert.Single(attrs.Nodes!);
        Assert.Equal("hash1", attrs.Nodes![0].EntityId);
        Assert.Equal("last_serving_ip_address", attrs.Links![0].ConnectionType);
        Assert.False(attrs.Private);
        Assert.Equal(2, attrs.ViewsCount);
        Assert.Equal(1, attrs.CommentsCount);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1599060646), attrs.CreatedAt);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "graphs/g123", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task UpdateGraph_PatchesAttributes()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "graph", "id": "g123" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new GraphClient(vt);

        await client.UpdateGraphAsync("g123", isPrivate: false, nodes: new[] { new GraphNode { EntityId = "x", Type = "domain" } });

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Patch, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "graphs/g123", request.RequestUri!.ToString());
        Assert.Contains("\"private\":false", handler.LastRequestBody);
        Assert.Contains("\"nodes\":[{\"entity_id\":\"x\",\"type\":\"domain\"}]", handler.LastRequestBody);
    }

    [Fact]
    public async Task UpdateGraph_NoFields_Throws()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new GraphClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(() => client.UpdateGraphAsync("g123"));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task DeleteGraph_SendsDelete()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new GraphClient(vt);

        await client.DeleteGraphAsync("g123");

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Delete, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "graphs/g123", request.RequestUri!.ToString());
    }
}