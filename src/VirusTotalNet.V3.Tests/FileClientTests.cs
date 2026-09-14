using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using VirusTotalNet.V3.Tests.TestInternals;
using VirusTotalNet.V3.Clients;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Tests;

public class FileClientTests
{
    private static VirusTotalOptions Options(string key = "test-key")
        => new() { ApiKey = key };

    [Fact]
    public async Task ScanFile_SendsMultipartPost_ToFilesEndpoint()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "analysis", "id": "analysis-1", "links": { "self": "https://x/analyses/analysis-1" } } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes("sample-bytes"));
        var analysis = await client.ScanFileAsync(stream, "eicar.txt");

        Assert.NotNull(analysis);
        Assert.Equal("analysis", analysis!.Type);
        Assert.Equal("analysis-1", analysis.Id);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "files", request.RequestUri!.ToString());

        Assert.True(request.Headers.TryGetValues("x-apikey", out var authValues));
        Assert.Equal("test-key", Assert.Single(authValues!));

        Assert.NotNull(request.Content);
        var contentType = request.Content!.Headers.ContentType!;
        Assert.Equal("multipart/form-data", contentType.MediaType);
    }

    [Fact]
    public async Task ScanFile_SendsFilePart_WithFieldNameAndFilename()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "analysis", "id": "a2" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes("EICAR"));
        await client.ScanFileAsync(stream, "malware.exe");

Assert.Contains("name=file", handler.LastRequestBody);
        Assert.Contains("filename=malware.exe", handler.LastRequestBody);
        Assert.Contains("EICAR", handler.LastRequestBody);
    }

    [Fact]
    public async Task ScanFile_SendsPasswordField_WhenProvided()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "analysis", "id": "a3" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes("PK..."));

        await client.ScanFileAsync(stream, "protected.zip", password: "s3cret");

        Assert.Contains("name=password", handler.LastRequestBody);
        Assert.Contains("s3cret", handler.LastRequestBody);
    }

    [Fact]
    public async Task ScanFile_OmitsPasswordField_WhenNotProvided()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "analysis", "id": "a4" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes("PK..."));
        await client.ScanFileAsync(stream, "plain.zip");

        Assert.DoesNotContain("name=password", handler.LastRequestBody);
    }

    [Fact]
    public async Task ScanFile_DeserializesAnalysisAttributes()
    {
        const string json = """
            {
              "data": {
                "type": "analysis",
                "id": "analysis-42",
                "attributes": {
                  "status": "completed",
                  "date": 1704067200,
                  "stats": { "malicious": 12, "harmless": 58, "undetected": 7, "suspicious": 0, "type-unsupported": 2, "timeout": 1 }
                }
              }
            }
            """;

        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, json));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes("bytes"));
        var analysis = await client.ScanFileAsync(stream, "x.bin");

        Assert.Equal("analysis", analysis.Type);
        Assert.Equal("analysis-42", analysis.Id);

        var attrs = analysis.Attributes;
        Assert.NotNull(attrs);
        Assert.Equal("completed", attrs!.Status);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1704067200), attrs.Date);
        Assert.Equal(12, attrs.Stats!.Malicious);
        Assert.Equal(58, attrs.Stats.Harmless);
        Assert.Equal(2, attrs.Stats.TypeUnsupported);
    }

    [Fact]
    public async Task ScanFile_OversizedStream_Throws()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        var oversized = new MemoryStream(new byte[FileClient.MaxScanSize + 1]);

        await using (oversized)
        {
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => client.ScanFileAsync(oversized, "big.bin"));
        }

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task ScanFile_NullStream_Throws()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => client.ScanFileAsync(null!, "x.bin"));
    }

    [Fact]
    public async Task GetFile_SendsGet_ToFilesEndpoint()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "file", "id": "hash123" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        var file = await client.GetFileAsync("hash123");

        Assert.NotNull(file);
        Assert.Equal("file", file!.Type);
        Assert.Equal("hash123", file.Id);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "files/hash123", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task GetFile_DeserializesAttributes()
    {
        const string json = """
            {
              "data": {
                "type": "file",
                "id": "aa1c00e982e0e0e4fdf1c70ddf2b2f7f4d0c9e7e702f00e3f9a76f8c6d5a4b3c2",
                "attributes": {
                  "sha256": "aa1c00e982e0e0e4fdf1c70ddf2b2f7f4d0c9e7e702f00e3f9a76f8c6d5a4b3c2",
                  "size": "12345",
                  "last_analysis_stats": { "malicious": "5", "suspicious": "1", "harmless": "60", "undetected": "30", "type-unsupported": "4", "timeout": "0" }
                }
              }
            }
            """;

        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, json));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        var file = await client.GetFileAsync("aa1c00e982e0e0e4fdf1c70ddf2b2f7f4d0c9e7e702f00e3f9a76f8c6d5a4b3c2");

        var attrs = file.Attributes;
        Assert.NotNull(attrs);
        Assert.Equal("aa1c00e982e0e0e4fdf1c70ddf2b2f7f4d0c9e7e702f00e3f9a76f8c6d5a4b3c2", attrs!.Sha256);
        Assert.Equal(12345, attrs.Size);
        Assert.Equal(5, attrs.LastAnalysisStats!.Malicious);
        Assert.Equal(60, attrs.LastAnalysisStats.Harmless);
        Assert.Equal(4, attrs.LastAnalysisStats.TypeUnsupported);
    }

    [Fact]
    public async Task GetFile_EmptyId_Throws()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(
            () => client.GetFileAsync(" "));

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task AnalyseFile_SendsPost_ToRescanEndpoint()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "analysis", "id": "analysis-rescan-1" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        var analysis = await client.AnalyseFileAsync("hash123");

        Assert.Equal("analysis", analysis!.Type);
        Assert.Equal("analysis-rescan-1", analysis.Id);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "files/hash123/analyse", request.RequestUri!.ToString());
        Assert.Equal("{}", handler.LastRequestBody);
    }

    [Fact]
    public async Task AnalyseFile_EmptyId_Throws()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(
            () => client.AnalyseFileAsync(""));

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Download_SendsGet_AndReturnsStream()
    {
        var bytes = Encoding.UTF8.GetBytes("file-bytes");
        var handler = new StubHttpMessageHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(bytes)
            });

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        using var stream = await client.DownloadAsync("hash123");
        using var reader = new StreamReader(stream);
        Assert.Equal("file-bytes", await reader.ReadToEndAsync());

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "files/hash123/download", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task Download_NotFound_Throws()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.NotFound,
                """{ "error": { "code": "NotFoundError", "message": "Not found" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await Assert.ThrowsAsync<NotFoundException>(
            () => client.DownloadAsync("unknown"));
    }

    [Fact]
    public async Task GetDownloadUrl_ReturnsSignedUrl()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": "https://files.example.com/dl/signed?token=abc" }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        var url = await client.GetDownloadUrlAsync("hash123");

        Assert.Equal("https://files.example.com/dl/signed?token=abc", url);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "files/hash123/download_url", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task DownloadMethods_EmptyId_Throw()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(() => client.DownloadAsync(" "));
        await Assert.ThrowsAsync<ArgumentException>(() => client.GetDownloadUrlAsync(""));

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task ScanLargeFile_FetchesUploadUrl_ThenPostsMultipartToIt()
    {
        var handler = new StubHttpMessageHandler(request =>
        {
            if (request.Method == HttpMethod.Get)
                return StubHttpMessageHandler.Json(HttpStatusCode.OK,
                    """{ "data": "https://upload.example.com/uploads/u1" }""");

            return StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "analysis", "id": "analysis-big" } }""");
        });

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes("big-file-bytes"));
        var analysis = await client.ScanLargeFileAsync(stream, "big.rar");

        Assert.Equal("analysis", analysis!.Type);
        Assert.Equal("analysis-big", analysis.Id);

        Assert.Equal(2, handler.Requests.Count);

        Assert.Equal(HttpMethod.Get, handler.Requests[0].Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "files/upload_url", handler.Requests[0].RequestUri!.ToString());

        Assert.Equal(HttpMethod.Post, handler.Requests[1].Method);
        Assert.Equal("https://upload.example.com/uploads/u1", handler.Requests[1].RequestUri!.ToString());
        Assert.Equal("multipart/form-data", handler.Requests[1].Content!.Headers.ContentType!.MediaType);
        Assert.Contains("name=file", handler.LastRequestBody);
        Assert.Contains("filename=big.rar", handler.LastRequestBody);
    }

    [Fact]
    public async Task ScanLargeFile_NoUploadUrl_Throws()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes("bytes"));
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.ScanLargeFileAsync(stream, "big.rar"));
    }

    [Fact]
    public async Task ScanLargeFile_NullStream_Throws()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => client.ScanLargeFileAsync(null!, "big.rar"));
    }
}