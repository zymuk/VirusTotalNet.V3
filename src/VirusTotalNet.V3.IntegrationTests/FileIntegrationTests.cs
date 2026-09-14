using System.Security.Cryptography;
using System.Text;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;
using VirusTotalNet.V3.Models.Attributes;

namespace VirusTotalNet.V3.IntegrationTests;

[Trait(TestKey.TraitCategory, "Integration")]
[Collection("FileIntegration")]
public class FileIntegrationTests
{
    private const string EicarContent = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    private const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    [SkippableFact]
    public async Task UploadFile_WaitForCompletion_GetReport_Download()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        var payload = NewUniquePayload();
        await using var stream = new MemoryStream(payload, writable: false);

        // 1. Upload for scanning
        var analysis = await vt.ScanFileAsync(stream, "lifecycle.bin");
        Assert.NotNull(analysis);
        Assert.Equal("analysis", analysis!.Type);
        Assert.NotNull(analysis.Id);

        var analysisId = analysis.Id!;
        Assert.False(string.IsNullOrWhiteSpace(analysisId));

        // 2. Wait for completion
        var completed = await vt.WaitForCompletionAsync(analysisId, TimeSpan.FromSeconds(5));
        Assert.NotNull(completed);
        Assert.Equal("completed", completed!.Attributes?.Status);
        Assert.NotNull(completed.Attributes?.Stats);

        // 3. Get file report by the SHA-256 hash of the uploaded content
        var sha256 = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
        var fileReport = await vt.GetFileReportAsync(sha256);
        Assert.NotNull(fileReport);
        Assert.Equal("file", fileReport!.Type);
        Assert.NotNull(fileReport.Attributes);
        Assert.True(fileReport.Attributes!.LastAnalysisStats is not null,
            "A completed analysis must produce detection statistics in the file report");

        // 4. Download the scanned file (tolerated: some tiers restrict downloads with HTTP 403)
        try
        {
            await using var downloaded = await vt.DownloadFileAsync(fileReport.Id!);
            Assert.NotNull(downloaded);
            Assert.True(downloaded!.Length > 0);
        }
        catch (VtHttpException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            Skip.If(true, "File download endpoint not licensed for this key (HTTP 403): " + ex.Message);
        }
    }

    [SkippableFact]
    public async Task GetFileReport_ByHash_ReturnsExpectedFields()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        var file = await vt.GetFileReportAsync(EicarSha256);
        Assert.NotNull(file);
        Assert.Equal("file", file!.Type);
        Assert.NotNull(file.Id);
        Assert.NotNull(file.Attributes);
        Assert.NotNull(file.Attributes!.Sha256);
        Assert.Equal(EicarSha256, file.Attributes.Sha256, ignoreCase: true);
        Assert.NotNull(file.Attributes.LastAnalysisStats);
        Assert.True(file.Attributes.LastAnalysisStats!.Malicious >= 1, "EICAR should be detected by at least 1 engine");
    }

    [SkippableFact]
    public async Task GetFile_NotYetUploaded_ThrowsNotFound()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        var neverUploadedHash = RandomSha256();
        var ex = await Assert.ThrowsAsync<NotFoundException>(
            () => vt.GetFileReportAsync(neverUploadedHash));

        Assert.Equal("NotFoundError", ex.ErrorCode);
    }

    [SkippableFact]
    public async Task GetAnalysis_RightAfterScan_StatusIsValid()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        var payload = NewUniquePayload();
        await using var stream = new MemoryStream(payload, writable: false);
        var analysis = await vt.ScanFileAsync(stream, "state.bin");

        Assert.NotNull(analysis);
        Assert.NotNull(analysis!.Id);
        Assert.Equal("analysis", analysis.Type);

        var fetched = await vt.GetAnalysisAsync(analysis.Id!);
        Assert.NotNull(fetched);

        var status = fetched!.Attributes?.Status;
        Assert.True(
            status is AnalysisStatus.Queued
                or AnalysisStatus.InProgress
                or AnalysisStatus.Completed,
            $"Unexpected analysis status right after scan: '{status}'");
    }

    [SkippableFact]
    public async Task CheckFileAlreadyScanned_UsingTryGet()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        var scanned = await vt.Client.TryGetAsync<FileObject>("/files/" + EicarSha256);
        Assert.True(scanned.IsSuccess, "EICAR was uploaded earlier in this session; it should already exist");
        Assert.NotNull(scanned.Value);
        Assert.True(scanned.Value!.Attributes!.LastAnalysisStats is not null);

        var notScanned = await vt.Client.TryGetAsync<FileObject>("/files/" + RandomSha256());
        Assert.False(notScanned.IsSuccess);
        Assert.NotNull(notScanned.Error);
        Assert.Equal("NotFoundError", notScanned.Error.Code);
    }

    [SkippableFact]
    public async Task ScanFile_ThenWaitForCompletion_ThenCheckAlreadyScannedByHash()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        var payload = NewUniquePayload();
        await using var stream = new MemoryStream(payload, writable: false);
        var analysis = await vt.ScanFileAsync(stream, "scanned-check.bin");
        Assert.NotNull(analysis?.Id);

        var completed = await vt.WaitForCompletionAsync(analysis!.Id!, TimeSpan.FromSeconds(5));
        Assert.Equal(AnalysisStatus.Completed, completed!.Attributes?.Status);

        var sha256 = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
        var result = await vt.Client.TryGetAsync<FileObject>("/files/" + sha256);
        Assert.True(result.IsSuccess, "After the analysis completes the file must be retrievable by its hash");
        Assert.NotNull(result.Value);
        Assert.True(result.Value!.Attributes!.LastAnalysisStats is not null);
    }

    [SkippableFact]
    public async Task ScanFile_SizeWithinDirectUploadLimit_Uploads()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        var payload = new byte[4 * 1024 * 1024];
        RandomNumberGenerator.Fill(payload);

        await using var stream = new MemoryStream(payload, writable: false);
        var analysis = await vt.ScanFileAsync(stream, "bulk-4mb.bin");

        Assert.NotNull(analysis);
        Assert.Equal("analysis", analysis!.Type);
        Assert.False(string.IsNullOrWhiteSpace(analysis.Id));
    }

    private static string RandomSha256()
        => Convert.ToHexString(SHA256.HashData(RandomNumberGenerator.GetBytes(64))).ToLowerInvariant();

    private static byte[] NewUniquePayload(int size = 1024)
    {
        var payload = new byte[size];
        RandomNumberGenerator.Fill(payload);
        return payload;
    }

    [SkippableFact]
    public async Task GetDownloadUrl_ReturnsNonEmpty()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        try
        {
            var url = await vt.GetFileDownloadUrlAsync(EicarSha256);
            Assert.False(string.IsNullOrWhiteSpace(url));
            Assert.StartsWith("https://", url);
        }
        catch (VtHttpException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            Skip.If(true, "download_url endpoint not licensed for this key (HTTP 403): " + ex.Message);
        }
    }
}