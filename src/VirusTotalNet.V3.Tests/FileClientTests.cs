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
using VirusTotalNet.V3.Models.Attributes;

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
    public async Task ScanFile_DeserializesTypedResultsAndFiles()
    {
        const string json = """
            {
              "data": {
                "type": "analysis",
                "id": "analysis-43",
                "attributes": {
                  "status": "completed",
                  "date": 1704067200,
                  "stats": { "malicious": 5, "harmless": 1, "undetected": 0, "suspicious": 0, "type-unsupported": 0, "timeout": 0 },
                  "results": {
                    "ALYac": {
                      "category": "malicious",
                      "engine_name": "ALYac",
                      "engine_version": "1.1.1.5",
                      "engine_update": "20200609",
                      "method": "blacklist",
                      "result": "Dialer.Webdialer.F"
                    },
                    "ClamAV": {
                      "category": "malicious",
                      "engine_name": "ClamAV",
                      "method": "blacklist",
                      "result": "Win.Trojan.Dialer-83"
                    }
                  },
                  "files": {
                    "abc123": { "md5": "d41d8cd9", "sha1": "da39a3ee", "sha256": "abc123", "names": ["setup.exe", "installer.exe"] }
                  }
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

        var attrs = analysis.Attributes;
        Assert.NotNull(attrs);

        var results = attrs!.Results;
        Assert.NotNull(results);
        Assert.Equal(2, results!.Count);
        Assert.Equal("malicious", results["ALYac"].Category);
        Assert.Equal("Dialer.Webdialer.F", results["ALYac"].Result);
        Assert.Equal("ClamAV", results["ClamAV"].EngineName);

        var files = attrs.Files;
        Assert.NotNull(files);
        Assert.Single(files!);
        var file = files!["abc123"];
        Assert.Equal("d41d8cd9", file.Md5);
        Assert.Equal("abc123", file.Sha256);
        Assert.Equal(new[] { "setup.exe", "installer.exe" }, file.Names);
    }

    [Fact]
    public async Task ScanFile_AlreadyKnownFile_ReturnsCompletedAnalysisWithStats()
    {
        const string json = """
            {
              "data": {
                "type": "analysis",
                "id": "analysis-known",
                "attributes": {
                  "status": "completed",
                  "date": 1704067200,
                  "stats": { "malicious": 6, "harmless": 40, "undetected": 0, "suspicious": 0, "type-unsupported": 0, "timeout": 0 }
                }
              }
            }
            """;

        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, json));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes("already-known-bytes"));
        var analysis = await client.ScanFileAsync(stream, "known.exe");

        Assert.NotNull(analysis.Attributes);
        Assert.Equal(AnalysisStatus.Completed, analysis.Attributes!.Status);
        Assert.NotNull(analysis.Attributes.Stats);
        Assert.Equal(6, analysis.Attributes.Stats!.Malicious);
    }

    [Fact]
    public async Task ScanFile_QueuedAnalysis_HasNoStatsUntilCompleted()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "analysis", "id": "analysis-5", "attributes": { "status": "queued" } } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes("new-unique-bytes"));
        var analysis = await client.ScanFileAsync(stream, "new.bin");

        Assert.Equal(AnalysisStatus.Queued, analysis.Attributes!.Status);
        Assert.Null(analysis.Attributes.Stats);
        Assert.Null(analysis.Attributes.Results);
    }

    [Fact]
    public async Task ScanFile_InProgressAnalysis_KeepsPendingStatus()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "analysis", "id": "analysis-6", "attributes": { "status": "in-progress" } } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes("pending-bytes"));
        var analysis = await client.ScanFileAsync(stream, "pending.bin");

        Assert.Equal(AnalysisStatus.InProgress, analysis.Attributes!.Status);
        Assert.Null(analysis.Attributes.Stats);
    }

    [Fact]
    public async Task ScanFile_CopiesRemainingBytes_FromCurrentStreamPosition()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "analysis", "id": "analysis-pos" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes("prefix-middle-suffix"));
        stream.Position = 7;

        var analysis = await client.ScanFileAsync(stream, "pos.bin");

        Assert.Equal("analysis-pos", analysis!.Id);
        Assert.Contains("middle-suffix", handler.LastRequestBody);
        Assert.DoesNotContain("prefix-", handler.LastRequestBody);
    }

    [Fact]
    public async Task ScanFile_Retry_RebuildsMultipartContentPerAttempt()
    {
        var attempts = 0;
        var handler = new StubHttpMessageHandler(request =>
        {
            attempts++;
            return attempts == 1
                ? StubHttpMessageHandler.Json(HttpStatusCode.InternalServerError,
                    """{ "error": { "code": "InternalServerError", "message": "boom" } }""")
                : StubHttpMessageHandler.Json(HttpStatusCode.OK,
                    """{ "data": { "type": "analysis", "id": "analysis-retry" } }""");
        });

        var options = Options();
        options.UseRetry = true;
        options.MaxRetries = 2;

        using var vt = new VtClient(options, new HttpClient(handler));
        var client = new FileClient(vt);

        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes("retry-me"));
        var analysis = await client.ScanFileAsync(stream, "retry.bin");

        Assert.Equal("analysis-retry", analysis!.Id);
        Assert.Equal(2, attempts);

        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal(HttpMethod.Post, handler.Requests[0].Method);
        Assert.Equal(HttpMethod.Post, handler.Requests[1].Method);
        Assert.Contains("retry-me", handler.LastRequestBody!);
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
    public async Task ScanFile_AtMaximumSize_IsAllowed()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "analysis", "id": "analysis-max" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        var max = new MemoryStream(new byte[FileClient.MaxScanSize]);

        await using (max)
        {
            var analysis = await client.ScanFileAsync(max, "max.bin");
            Assert.Equal("analysis-max", analysis!.Id);
        }

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
    }

    [Fact]
    public async Task ScanFile_NonSeekableStream_SkipsSizeCheckAndUploads()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "analysis", "id": "analysis-ns" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await using var stream = new NonSeekableMemoryStream(Encoding.UTF8.GetBytes("payload"));
        var analysis = await client.ScanFileAsync(stream, "ns.bin");

        Assert.Equal("analysis-ns", analysis!.Id);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
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
    public async Task GetFile_NotFound_MapsToNotFoundException()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.NotFound,
                """{ "error": { "code": "NotFoundError", "message": "Resource not found" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        var ex = await Assert.ThrowsAsync<NotFoundException>(
            () => client.GetFileAsync("deadbeef"));

        Assert.Equal("NotFoundError", ex.ErrorCode);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "files/deadbeef", request.RequestUri!.ToString());
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
    public async Task AnalyseFile_ConcurrentRescanRefused_MapsToHttpException()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.UnprocessableEntity,
                """{ "error": { "message": "Already being submitted for scanning" } }"""));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        var ex = await Assert.ThrowsAsync<VtHttpException>(() => client.AnalyseFileAsync("hash123"));

        Assert.Contains("Already being submitted for scanning", ex.Message);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, ex.StatusCode);
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

    [Fact]
    public async Task ScanLargeFile_AcceptsStreamBeyondDirectUploadLimit()
    {
        var handler = new StubHttpMessageHandler(request =>
        {
            if (request.Method == HttpMethod.Get)
                return StubHttpMessageHandler.Json(HttpStatusCode.OK,
                    """{ "data": "https://upload.example.com/uploads/big" }""");

            return StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "analysis", "id": "analysis-large" } }""");
        });

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new FileClient(vt);

        await using var stream = new MemoryStream(new byte[FileClient.MaxScanSize + 1]);
        var analysis = await client.ScanLargeFileAsync(stream, "over-limit.bin");

        Assert.Equal("analysis-large", analysis!.Id);

        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal(HttpMethod.Get, handler.Requests[0].Method);
        Assert.Equal(HttpMethod.Post, handler.Requests[1].Method);
        Assert.Equal("https://upload.example.com/uploads/big", handler.Requests[1].RequestUri!.ToString());
        Assert.Contains("filename=over-limit.bin", handler.LastRequestBody!);
    }

    private sealed class NonSeekableMemoryStream : MemoryStream
    {
        public NonSeekableMemoryStream(byte[] buffer) : base(buffer, writable: false)
        {
        }

        public override bool CanSeek => false;
    }
}