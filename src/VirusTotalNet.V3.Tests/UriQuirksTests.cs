using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.V3.Clients;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;
using VirusTotalNet.V3.Tests.TestInternals;
using Xunit;

namespace VirusTotalNet.V3.Tests;

public class UriQuirksTests
{
    private static VtClient CreateClient(StubHttpMessageHandler handler)
    {
        var options = new VirusTotalOptions
        {
            ApiKey = "test-key",
            RequestsPerMinute = 100,
            RequestsPerDay = 1000
        };
        options.Validate();
        return new VtClient(options, new HttpClient(handler));
    }

    [Fact]
    public async Task GetAsync_UnsafeIdCharacters_EncodedInPath()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, "{ \"data\": null }"));
        using var client = CreateClient(handler);

        await client.GetAsync<TestFileObject>($"files/id space&\u00e9");

        var uri = handler.Requests[0].RequestUri!.AbsoluteUri;
        var expectedPath = "files/id%20space%26" + Uri.EscapeDataString("\u00e9");
        Assert.Contains(expectedPath, uri);
        Assert.DoesNotContain("space&", uri);
    }

    [Fact]
    public async Task GetAsync_PercentEscapesPreserved()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, "{ \"data\": null }"));
        using var client = CreateClient(handler);

        await client.GetAsync<TestFileObject>("files/a%2Fb%20c");

        var uri = handler.Requests[0].RequestUri!.AbsoluteUri;
        Assert.Contains("files/a%2Fb%20c", uri);
    }

    [Fact]
    public void EncodeUrlId_RoundTrips_UnpaddedBase64Url()
    {
        var url = "https://example.com/?q=a b&x=\u00e9#frag";
        var encoded = UrlClient.EncodeUrlId(url);
        Assert.DoesNotContain('=', encoded);
        Assert.DoesNotContain('+', encoded);
        Assert.DoesNotContain('/', encoded);
        var pad = encoded.Length % 4 == 0 ? "" : new string('=', 4 - encoded.Length % 4);
        var bytes = Convert.FromBase64String(encoded.Replace('-', '+').Replace('_', '/') + pad);
        Assert.Equal(url, Encoding.UTF8.GetString(bytes));
    }

    [Fact]
    public async Task SearchAsync_QueryOperators_Escaped()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                "{ \"data\": [], \"meta\": { \"count\": 0 }, \"links\": { \"next\": null } }"));
        using var vt = new VtClient(CreateOptions(handler), new HttpClient(handler));
        var client = new VirusTotalNet.V3.Clients.SearchClient(vt);

        var query = "type:file name:\"a+b\" engine:harmless";
        await client.SearchAsync(query);

        var uri = handler.Requests[0].RequestUri!.AbsoluteUri;
        Assert.Contains("query=" + Uri.EscapeDataString(query), uri);
        Assert.DoesNotContain("name:\"a+b\"", uri);
    }

    private static VirusTotalOptions CreateOptions(StubHttpMessageHandler handler)
    {
        var options = new VirusTotalOptions { ApiKey = "test-key" };
        options.Validate();
        return options;
    }
}