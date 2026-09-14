using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using VirusTotalNet.V3.Tests.TestInternals;
using VirusTotalNet.V3.Clients;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;
using Xunit;

namespace VirusTotalNet.V3.Tests;

public class CollectionClientTests
{
    private static VirusTotalOptions Options(string key = "test-key")
        => new() { ApiKey = key };

    [Fact]
    public async Task CreateCollection_PostsJson()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "collection", "id": "col-1", "attributes": { "name": "my-col" } } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new CollectionClient(vt);

        var col = await client.CreateCollectionAsync("my-col", description: "desc");

        Assert.Equal("col-1", col!.Id);
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "collections", request.RequestUri!.ToString());
        Assert.Contains("\"name\":\"my-col\"", handler.LastRequestBody);
        Assert.Contains("\"description\":\"desc\"", handler.LastRequestBody);
    }

    [Fact]
    public async Task CreateCollection_EmptyName_Throws()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new CollectionClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(() => client.CreateCollectionAsync(" "));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task UpdateCollection_PatchJson()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "collection", "id": "col-1", "attributes": { "name": "updated" } } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new CollectionClient(vt);

        var col = await client.UpdateCollectionAsync("col-1", name: "updated");

        Assert.Equal("col-1", col!.Id);
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Patch, request.Method);
        Assert.Contains("\"name\":\"updated\"", handler.LastRequestBody);
    }

    [Fact]
    public async Task UpdateCollection_NoFields_Throws()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new CollectionClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(() => client.UpdateCollectionAsync("col-1"));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task DeleteCollection_SendsDelete()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new CollectionClient(vt);

        await client.DeleteCollectionAsync("col-1");

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Delete, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "collections/col-1", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task AddElements_PostsToRelationshipPath()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new CollectionClient(vt);

        var elements = new List<VtObjectId> { new("file", "aaaa") };

        await client.AddElementsAsync("col-1", CollectionRelationshipName.Files, elements);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "collections/col-1/files", request.RequestUri!.ToString());
        Assert.Contains("\"type\":\"file\"", handler.LastRequestBody);
        Assert.Contains("\"id\":\"aaaa\"", handler.LastRequestBody);
    }

    [Fact]
    public async Task RemoveElements_DeletesFromRelationshipPath()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new CollectionClient(vt);

        var elements = new List<VtObjectId> { new("url", "bHR0cHM6Ly9l") };

        await client.RemoveElementsAsync("col-1", CollectionRelationshipName.Urls, elements);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Delete, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "collections/col-1/urls", request.RequestUri!.ToString());
        Assert.Contains("\"type\":\"url\"", handler.LastRequestBody);
        Assert.Contains("\"id\":\"bHR0cHM6Ly9l\"", handler.LastRequestBody);
    }

    [Fact]
    public async Task ListElements_ReturnsCollection_WithCursor()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": [ { "type": "file", "id": "f1" }, { "type": "file", "id": "f2" } ], "meta": { "count": 2 }, "links": { "next": "https://x?cursor=c-9" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new CollectionClient(vt);

        var page = await client.ListElementsAsync<VtObjectId>("col-1", CollectionRelationshipName.Domains, cursor: "c-8");

        Assert.Equal(2, page.Items.Count);
        Assert.Equal("f1", page.Items[0].Id);
        Assert.Equal("c-9", page.NextCursor);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "collections/col-1/domains?cursor=c-8", request.RequestUri!.ToString());
    }

    [Theory]
    [InlineData("")]
    [InlineData("members")]
    [InlineData("unknown")]
    public async Task AddElements_InvalidRelationship_Throws(string relationship)
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new CollectionClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(
            () => client.AddElementsAsync("col-1", relationship, new[] { new VtObjectId("file", "aaa") }));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task AddElements_EmptyElements_Throws()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new CollectionClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(
            () => client.AddElementsAsync("col-1", CollectionRelationshipName.Files, Array.Empty<VtObjectId>()));
        Assert.Empty(handler.Requests);
    }
}