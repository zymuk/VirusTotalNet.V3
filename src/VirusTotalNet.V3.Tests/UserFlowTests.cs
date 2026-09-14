using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VirusTotalNet.V3.Tests.TestInternals;
using VirusTotalNet.V3;
using VirusTotalNet.V3.Core;

namespace VirusTotalNet.V3.Tests;

/// <summary>
/// User-flow tests that call only methods on the <see cref="VirusTotal"/> facade class the way a
/// user would, letting the requests flow through a scripted handler and checking the info returned.
/// </summary>
public class UserFlowTests
{
    private static VirusTotalOptions Options(string key = "test-key")
        => new() { ApiKey = key, RequestsPerMinute = 10, RequestsPerDay = 10000 };

    private static VirusTotal CreateVirusTotal(StubHttpMessageHandler handler)
    {
        var vtClient = new VtClient(Options(), new HttpClient(handler));
        return new VirusTotal(vtClient);
    }

    private static byte[] EicarBytes()
        => Encoding.ASCII.GetBytes(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

    private static string Sha256Of(byte[] bytes)
        => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static string PathOf(HttpRequestMessage request)
        => request.RequestUri!.ToString().Substring(VirusTotalOptions.DefaultBaseAddress.Length);

    private static string FileReportJson(string sha256)
        => @"{ ""data"": { ""type"": ""file"", ""id"": """ + sha256 +
           @""", ""attributes"": { ""sha256"": """ + sha256 +
           @""", ""last_analysis_stats"": { ""malicious"": 5, ""harmless"": 3, ""undetected"": 2 },
                 ""last_analysis_results"": { ""AcmeAV"": { ""category"": ""malicious"", ""engine_name"": ""AcmeAV"",
                 ""method"": ""blacklist"", ""result"": ""Trojan.Generic"" } } } } }";

    [Fact]
    public async Task GetFileReportAsync_UnknownFile_UploadsWaitsAndReturnsDetectionInfo()
    {
        var bytes = EicarBytes();
        var sha256 = Sha256Of(bytes);

        var fileGets = 0;
        var handler = new StubHttpMessageHandler(request =>
        {
            var path = PathOf(request);

            // First lookup misses (unknown file), later lookups serve the report.
            if (request.Method == HttpMethod.Get && path == "files/" + sha256)
            {
                fileGets++;
                return fileGets == 1
                    ? StubHttpMessageHandler.Json(HttpStatusCode.NotFound, """{"error":{"code":"NotFoundError"}}""")
                    : StubHttpMessageHandler.Json(HttpStatusCode.OK, FileReportJson(sha256));
            }

            if (request.Method == HttpMethod.Post && path == "files")
                return StubHttpMessageHandler.Json(HttpStatusCode.OK,
                    """{"data":{"type":"analysis","id":"analysis-upl-1","attributes":{"status":"queued"}}}""");

            if (request.Method == HttpMethod.Get && path == "analyses/analysis-upl-1")
                return StubHttpMessageHandler.Json(HttpStatusCode.OK,
                    """{"data":{"type":"analysis","id":"analysis-upl-1","attributes":{"status":"completed","stats":{"malicious":5}}}}""");

            return StubHttpMessageHandler.Json(HttpStatusCode.NotFound, """{"error":{"code":"NotFoundError"}}""");
        });

        using var vt = CreateVirusTotal(handler);

        // One facade call: upload a sample, wait for it, get the info back.
        var report = await vt.GetFileReportAsync(bytes);

        Assert.Equal(sha256, report.Id);
        Assert.Equal(sha256, report.Attributes!.Sha256);
        Assert.Equal(5, report.Attributes.LastAnalysisStats!.Malicious);
        Assert.Equal(3, report.Attributes.LastAnalysisStats.Harmless);

        var engine = report.Attributes.LastAnalysisResults!["AcmeAV"];
        Assert.Equal("Trojan.Generic", engine.Result);
        Assert.Equal("malicious", engine.Category);
        Assert.Equal("AcmeAV", engine.EngineName);

        var calls = handler.Requests.Select(PathOf).ToArray();
        Assert.Equal(new[]
        {
            "files/" + sha256,
            "files",
            "analyses/analysis-upl-1",
            "files/" + sha256,
        }, calls);
    }

    [Fact]
    public async Task GetFileReportAsync_KnownFile_ReturnsReportWithoutUploading()
    {
        var bytes = EicarBytes();
        var sha256 = Sha256Of(bytes);

        var handler = new StubHttpMessageHandler(request =>
            StubHttpMessageHandler.Json(HttpStatusCode.OK, FileReportJson(PathOf(request).Substring("files/".Length))));

        using var vt = CreateVirusTotal(handler);

        var report = await vt.GetFileReportAsync(bytes);

        Assert.Equal(sha256, report.Id);
        Assert.Equal(5, report.Attributes!.LastAnalysisStats!.Malicious);
        Assert.Equal("Trojan.Generic", report.Attributes.LastAnalysisResults!["AcmeAV"].Result);

        var calls = handler.Requests.Select(PathOf).ToArray();
        Assert.Equal(new[] { "files/" + sha256 }, calls);
    }

    [Fact]
    public async Task GetFileReportAsync_ByHash_ReturnsDetectionInfo()
    {
        const string hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

        var handler = new StubHttpMessageHandler(request =>
            StubHttpMessageHandler.Json(HttpStatusCode.OK, FileReportJson(hash)));

        using var vt = CreateVirusTotal(handler);

        var report = await vt.GetFileReportAsync(hash);

        Assert.Equal(hash, report.Id);
        Assert.Equal(hash, report.Attributes!.Sha256);
        Assert.Equal(5, report.Attributes.LastAnalysisStats!.Malicious);
        Assert.Equal(3, report.Attributes.LastAnalysisStats.Harmless);

        var engine = report.Attributes.LastAnalysisResults!["AcmeAV"];
        Assert.Equal("Trojan.Generic", engine.Result);
        Assert.Equal("malicious", engine.Category);
        Assert.Equal("AcmeAV", engine.EngineName);

        var calls = handler.Requests.Select(PathOf).ToArray();
        Assert.Equal(new[] { "files/" + hash }, calls);
    }

    [Fact]
    public async Task ScanUrl_WaitForCompletion_ThenGetUrl_ReturnsUrlDetectionInfo()
    {
        const string url = "https://example.com/a";

        var handler = new StubHttpMessageHandler(request =>
        {
            var path = PathOf(request);

            if (request.Method == HttpMethod.Post && path == "urls")
                return StubHttpMessageHandler.Json(HttpStatusCode.OK,
                    """{"data":{"type":"analysis","id":"analysis-url-1","attributes":{"status":"queued"}}}""");

            if (request.Method == HttpMethod.Get && path == "analyses/analysis-url-1")
                return StubHttpMessageHandler.Json(HttpStatusCode.OK,
                    """{"data":{"type":"analysis","id":"analysis-url-1","attributes":{"status":"completed"}}}""");

            if (request.Method == HttpMethod.Get && path.StartsWith("urls/", StringComparison.Ordinal))
                return StubHttpMessageHandler.Json(HttpStatusCode.OK,
                    """{"data":{"type":"url","id":"aHR0cHM6Ly9leGFtcGxlLmNvbS9h","attributes":{"url":"https://example.com/a","last_analysis_stats":{"malicious":1}}}}""");

            return StubHttpMessageHandler.Json(HttpStatusCode.NotFound, """{"error":{"code":"NotFoundError"}}""");
        });

        using var vt = CreateVirusTotal(handler);

        var analysis = await vt.ScanUrlAsync(url);
        var completed = await vt.WaitForCompletionAsync(analysis.Id, TimeSpan.FromMilliseconds(1));
        var urlObject = await vt.GetUrlAsync(url);

        Assert.Equal("analysis-url-1", analysis.Id);
        Assert.Equal("completed", completed.Attributes!.Status);
        Assert.Equal(url, urlObject.Attributes!.Url);
        Assert.Equal(1, urlObject.Attributes.LastAnalysisStats!.Malicious);

        var calls = handler.Requests.Select(PathOf).ToArray();
        Assert.Equal(new[]
        {
            "urls",
            "analyses/analysis-url-1",
            "urls/aHR0cHM6Ly9leGFtcGxlLmNvbS9h",
        }, calls);
    }

    [Fact]
    public async Task CreateSavedSearch_List_Get_Delete_ThenList_TracksLifecycle()
    {
        var deleted = false;
        var handler = new StubHttpMessageHandler(request =>
        {
            var path = PathOf(request);

            if (request.Method == HttpMethod.Post && path == "saved_searches")
                return StubHttpMessageHandler.Json(HttpStatusCode.OK,
                    """{"data":{"type":"saved_search","id":"search-42","attributes":{"name":"APT domains","search_query":"type:domain tag:apt","description":"Daily review","private":true,"tags":["apt","research"]}}}""");

            if (request.Method == HttpMethod.Get && path == "saved_searches")
                return deleted
                    ? StubHttpMessageHandler.Json(HttpStatusCode.OK,
                        """{"data":[{"type":"saved_search","id":"search-7","attributes":{"name":"IoCs","search_query":"type:file"}}]}""")
                    : StubHttpMessageHandler.Json(HttpStatusCode.OK,
                        """{"data":[{"type":"saved_search","id":"search-42","attributes":{"name":"APT domains","search_query":"type:domain tag:apt"}},{"type":"saved_search","id":"search-7","attributes":{"name":"IoCs","search_query":"type:file"}}]}""");

            if (request.Method == HttpMethod.Get && path == "saved_searches/search-42")
                return StubHttpMessageHandler.Json(HttpStatusCode.OK,
                    """{"data":{"type":"saved_search","id":"search-42","attributes":{"name":"APT domains","search_query":"type:domain tag:apt"}}}""");

            if (request.Method == HttpMethod.Delete && path == "saved_searches/search-42")
            {
                deleted = true;
                return StubHttpMessageHandler.Json(HttpStatusCode.OK, """{"data":null}""");
            }

            return StubHttpMessageHandler.Json(HttpStatusCode.NotFound, """{"error":{"code":"NotFoundError"}}""");
        });

        using var vt = CreateVirusTotal(handler);

        var created = await vt.CreateSavedSearchAsync(
            "APT domains",
            "type:domain tag:apt",
            description: "Daily review",
            isPrivate: true,
            tags: new[] { "apt", "research" });

        Assert.Equal("search-42", created.Id);
        Assert.Equal("APT domains", created.Attributes!.Name);
        Assert.Equal("type:domain tag:apt", created.Attributes.Query);
        Assert.Equal("Daily review", created.Attributes.Description);
        Assert.True(created.Attributes.Private);
        Assert.Equal(new[] { "apt", "research" }, created.Attributes.Tags!);

        var before = await vt.ListSavedSearchesAsync();
        Assert.Contains(before.Items, s => s.Id == "search-42");

        var fetched = await vt.GetSavedSearchAsync("search-42");
        Assert.Equal("type:domain tag:apt", fetched.Attributes!.Query);

        await vt.DeleteSavedSearchAsync("search-42");
        var after = await vt.ListSavedSearchesAsync();
        Assert.DoesNotContain(after.Items, s => s.Id == "search-42");

        var calls = handler.Requests.Select(r => r.Method + " " + PathOf(r)).ToArray();
        Assert.Equal(new[]
        {
            "POST saved_searches",
            "GET saved_searches",
            "GET saved_searches/search-42",
            "DELETE saved_searches/search-42",
            "GET saved_searches",
        }, calls);
    }

    [Fact]
    public async Task ScanFileAsync_ByPath_LikeGenboxV2_UploadsAndReturnsAnalysis()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".com");
        await File.WriteAllBytesAsync(path, EicarBytes());

        try
        {
            var handler = new StubHttpMessageHandler(request =>
            {
                var pathOf = PathOf(request);

                if (request.Method == HttpMethod.Post && pathOf == "files")
                    return StubHttpMessageHandler.Json(HttpStatusCode.OK,
                        """{"data":{"type":"analysis","id":"analysis-v2scan-1","attributes":{"status":"queued"}}}""");

                return StubHttpMessageHandler.Json(HttpStatusCode.NotFound, """{"error":{"code":"NotFoundError"}}""");
            });

            using var vt = CreateVirusTotal(handler);

            // The exact call a VirusTotal v2 user is used to: a path instead of a stream.
            var scan = await vt.ScanFileAsync(path);

            Assert.Equal("analysis-v2scan-1", scan.Id);
            Assert.Equal("queued", scan.Attributes!.Status);

            var calls = handler.Requests.Select(PathOf).ToArray();
            Assert.Equal(new[] { "files" }, calls);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task GetUrlReportAsync_WithScanIfNoReport_ScansWhenUrlIsNew_LikeGenboxV2()
    {
        const string url = "https://example.com/b";
        const string urlId = "aHR0cHM6Ly9leGFtcGxlLmNvbS9i";

        var urlGets = 0;
        var handler = new StubHttpMessageHandler(request =>
        {
            var path = PathOf(request);

            // First lookup misses so the report is generated by scanning, exactly like v2's flag.
            if (request.Method == HttpMethod.Get && path == "urls/" + urlId)
            {
                urlGets++;
                return urlGets == 1
                    ? StubHttpMessageHandler.Json(HttpStatusCode.NotFound, """{"error":{"code":"NotFoundError"}}""")
                    : StubHttpMessageHandler.Json(HttpStatusCode.OK,
                        """{"data":{"type":"url","id":"aHR0cHM6Ly9leGFtcGxlLmNvbS9i","attributes":{"url":"https://example.com/b","last_analysis_stats":{"malicious":1}}}}""");
            }

            if (request.Method == HttpMethod.Post && path == "urls")
                return StubHttpMessageHandler.Json(HttpStatusCode.OK,
                    """{"data":{"type":"analysis","id":"analysis-url-scanif-1","attributes":{"status":"queued"}}}""");

            if (request.Method == HttpMethod.Get && path == "analyses/analysis-url-scanif-1")
                return StubHttpMessageHandler.Json(HttpStatusCode.OK,
                    """{"data":{"type":"analysis","id":"analysis-url-scanif-1","attributes":{"status":"completed"}}}""");

            return StubHttpMessageHandler.Json(HttpStatusCode.NotFound, """{"error":{"code":"NotFoundError"}}""");
        });

        using var vt = CreateVirusTotal(handler);

        // One facade call with the v2 signature: auto-scan when the URL is unknown.
        var report = await vt.GetUrlReportAsync(url, scanIfNoReport: true);

        Assert.Equal(url, report.Attributes!.Url);
        Assert.Equal(1, report.Attributes.LastAnalysisStats!.Malicious);

        var calls = handler.Requests.Select(PathOf).ToArray();
        Assert.Equal(new[]
        {
            "urls/" + urlId,
            "urls",
            "analyses/analysis-url-scanif-1",
            "urls/" + urlId,
        }, calls);
    }
}