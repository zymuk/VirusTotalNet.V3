using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VirusTotalNet.V3.Tests.TestInternals;
using VirusTotalNet.V3;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Tests;

public class VirusTotalTests
{
    private static VirusTotalOptions Options(string key = "test-key")
        => new() { ApiKey = key };

    private static VirusTotal CreateVirusTotal(StubHttpMessageHandler handler)
    {
        var vtClient = new VtClient(Options(), new HttpClient(handler));
        return new VirusTotal(vtClient);
    }

    private static byte[] EicarBytes()
        => Encoding.ASCII.GetBytes(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

    private static string Sha256Of(byte[] bytes)
        => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static string FileJson(string sha256)
        => $$"""{ "data": { "type": "file", "id": "{{sha256}}", "attributes": { "sha256": "{{sha256}}", "last_analysis_stats": { "malicious": 65, "harmless": 0 } } } }""";

    [Fact]
    public async Task GetFileReport_ByHash_GetsFileReport()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, FileJson("hash123")));

        using var vt = CreateVirusTotal(handler);

        var file = await vt.GetFileReportAsync("hash123");

        Assert.Equal("file", file!.Type);
        Assert.Equal(65, file.Attributes!.LastAnalysisStats!.Malicious);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "files/hash123", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task GetFileReport_ByBytes_UsesComputedSha256()
    {
        var bytes = EicarBytes();
        var sha256 = Sha256Of(bytes);
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, FileJson(sha256)));

        using var vt = CreateVirusTotal(handler);

        var file = await vt.GetFileReportAsync(bytes);

        Assert.Equal(sha256, file!.Id);
        Assert.Equal(65, file.Attributes!.LastAnalysisStats!.Malicious);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "files/" + sha256, request.RequestUri!.ToString());
    }

    [Fact]
    public async Task GetFileReport_ByBytes_NotFound_ScansWaitsAndRefetches()
    {
        var bytes = EicarBytes();
        var sha256 = Sha256Of(bytes);

        var fileGets = 0;
        var handler = new StubHttpMessageHandler(request =>
        {
            var url = request.RequestUri!.ToString();
            var fileUrl = VirusTotalOptions.DefaultBaseAddress + "files/" + sha256;

            if (request.Method == HttpMethod.Get && url == fileUrl)
            {
                fileGets++;
                return fileGets == 1
                    ? StubHttpMessageHandler.Json(HttpStatusCode.NotFound,
                        """{ "error": { "code": "NotFoundError", "message": "Not found" } }""")
                    : StubHttpMessageHandler.Json(HttpStatusCode.OK, FileJson(sha256));
            }

            if (request.Method == HttpMethod.Post && url.EndsWith("/files"))
                return StubHttpMessageHandler.Json(HttpStatusCode.OK,
                    """{ "data": { "type": "analysis", "id": "analysis-abc" } }""");

            if (request.Method == HttpMethod.Get && url.EndsWith("/analyses/analysis-abc"))
                return StubHttpMessageHandler.Json(HttpStatusCode.OK,
                    """{ "data": { "type": "analysis", "id": "analysis-abc", "attributes": { "status": "completed" } } }""");

            return StubHttpMessageHandler.Json(HttpStatusCode.NotFound,
                """{ "error": { "code": "NotFoundError", "message": "Not found" } }""");
        });

        using var vt = CreateVirusTotal(handler);

        var file = await vt.GetFileReportAsync(bytes);

        Assert.Equal(sha256, file!.Id);
        Assert.Equal(4, handler.Requests.Count);
    }

    [Fact]
    public async Task GetFileReport_NullArgs_Throw()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));

        using var vt = CreateVirusTotal(handler);

        await Assert.ThrowsAsync<ArgumentNullException>(() => vt.GetFileReportAsync((byte[])null!));
        await Assert.ThrowsAsync<ArgumentException>(() => vt.GetFileReportAsync((string)null!));
    }

    [Fact]
    public void Facade_Exposes_All_Module_Clients()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));

        using var vt = CreateVirusTotal(handler);

        Assert.NotNull(vt.FileClient);
        Assert.NotNull(vt.AnalysisClient);
        Assert.NotNull(vt.UrlClient);
        Assert.NotNull(vt.DomainClient);
        Assert.NotNull(vt.IpClient);
        Assert.NotNull(vt.Behaviour);
        Assert.NotNull(vt.Feedback);
        Assert.NotNull(vt.Search);
        Assert.NotNull(vt.Relationships);
        Assert.NotNull(vt.SavedSearchClient);
        Assert.NotNull(vt.CollectionClient);
        Assert.NotNull(vt.GraphClient);
        Assert.NotNull(vt.ThreatActor);
        Assert.NotNull(vt.Feeds);
        Assert.NotNull(vt.PrivateScanning);
        Assert.NotNull(vt.Hunting);
        Assert.NotNull(vt.Retrohunt);
        Assert.NotNull(vt.Users);
    }
}