# Migrating from VirusTotalNet v2 to v3

This guide helps you migrate from **VirusTotalNet (v2/Genbox)** to **VirusTotalNet.V3**.

## Key Changes at a Glance

| Aspect | v2 (Genbox) | v3 (This Library) |
|--------|-------------|-------------------|
| **Response format** | Flat `response_code` + fields | Envelope `{data, meta, links, error}` |
| **Error handling** | `ResponseCode` + `ResponseCodeException` | HTTP status + `error.code` → typed exceptions |
| **Auth** | Query param `apikey` | Header `x-apikey` |
| **Base URL** | `https://www.virustotal.com/vtapi/v2/` | `https://www.virustotal.com/api/v3/` |
| **Rate limit** | 4 req/min (free) | 4 req/min & 500 req/day (configurable) |
| **Field naming** | PascalCase | snake_case (auto-converted) |

## Method Mapping Table

| v2 Method | v3 Equivalent |
|-----------|---------------|
| `GetFileReportAsync(hash)` | `FileClient.GetFileAsync(hash)` |
| `ScanFileAsync(bytes/Stream/path)` | `FileClient.ScanFileAsync(bytes/Stream/path)` |
| `ScanFileAsync(path)` (overload) | `FileClient.ScanFileAsync(path)` |
| `GetFileReportAsync(FileInfo/Stream)` | `FileClient.GetFileAsync(hash)` → then `GetFileAsync` |
| `RescanFileAsync(hash)` | `FileClient.AnalyseFileAsync(hash)` |
| `GetUrlReportAsync(url)` | `UrlClient.GetUrlAsync(url)` |
| `ScanUrlAsync(url)` | `UrlClient.ScanUrlAsync(url)` |
| `RescanUrlAsync(url)` | `UrlClient.AnalyseUrlAsync(url)` |
| `GetDomainReportAsync(domain)` | `DomainClient.GetDomainAsync(domain)` |
| `GetIPReportAsync(ip)` | `IpClient.GetIpAsync(ip)` |
| `GetCommentsAsync(resource)` | `FeedbackClient.GetCommentsAsync(resource)` |
| `PostCommentAsync(resource, comment)` | `FeedbackClient.AddCommentAsync(resource, comment)` |
| `GetVotesAsync(resource)` | `FeedbackClient.GetVotesAsync(resource)` |
| `PostVoteAsync(resource, verdict)` | `FeedbackClient.AddVoteAsync(resource, verdict)` |

## Exception Migration

| v2 Exception | v3 Exception | Notes |
|-------------|--------------|-------|
| `ResponseCodeException` | `VirusTotalException` (base) | Check `StatusCode` and `ErrorCode` |
| — | `NotFoundException` | 404 NotFoundError |
| — | `AuthenticationException` | 401 AuthenticationRequiredError / InvalidApiKeyError |
| — | `QuotaExceededException` | 403 QuotaExceededError / 429 RateLimitExceededError |
| — | `RateLimitException` | 429 with `RetryAfter` |
| — | `ServerException` | 500/502/503 InternalError / ServiceUnavailableError |
| — | `InvalidRequestException` | 400 BadRequestError / InvalidArgumentError |
| — | `VtHttpException` | Fallback for unknown error codes |

## Code Samples

### Before (v2)
```csharp
var vt = new VirusTotal(apiKey);
var report = await vt.GetFileReportAsync("eicar_hash");
if (report.ResponseCode == 1) {
    Console.WriteLine($"Detected: {report.Positives}/{report.Total}");
}
```

### After (v3)
```csharp
var options = new VirusTotalOptions { ApiKey = "your-key" };
using var client = new VirusTotal(options);
var file = await client.FileClient.GetFileAsync("eicar_hash");
if (file.Data?.Attributes?.LastAnalysisStats != null) {
    var stats = file.Data.Attributes.LastAnalysisStats;
    Console.WriteLine($"Detected: {stats.Malicious}/{stats.Harmless + stats.Malicious + stats.Suspicious + stats.Undetected}");
}
```

### File Scan (v3)
```csharp
using var client = new VirusTotal(new VirusTotalOptions { ApiKey = "key" });

// Small file (< 32 MB)
var analysis = await client.FileClient.ScanFileAsync(fileBytes);
analysis = await client.AnalysisClient.WaitForCompletionAsync(analysis.Data.Id);
var report = await client.FileClient.GetFileAsync(analysis.Meta.FileInfo.Sha256);

// Large file (> 32 MB)
var uploadUrl = await client.FileClient.GetFileUploadUrlAsync();
await client.FileClient.UploadFileToUrlAsync(uploadUrl, largeFileStream);
analysis = await client.AnalysisClient.WaitForCompletionAsync(analysis.Data.Id);
```

### Error Handling (v3)
```csharp
try {
    var file = await client.FileClient.GetFileAsync("hash");
} catch (NotFoundException) {
    // File not in VT database
} catch (RateLimitException ex) {
    // Respect ex.RetryAfter
    await Task.Delay(ex.RetryAfter.Value);
} catch (AuthenticationException) {
    // Invalid or missing API key
} catch (VirusTotalException ex) {
    // Other errors: ex.StatusCode, ex.ErrorCode, ex.Message
}
```

### Result-Style (No-Throw)
```csharp
var options = new VirusTotalOptions { ApiKey = "key", ThrowOnError = false };
using var client = new VtClient(options);

var result = await client.TryGetAsync<FileObject>("files/hash");
if (result.IsSuccess) {
    var file = result.Value;
} else {
    // result.Error contains ErrorCode, Message, StatusCode
}
```

## Field Naming (snake_case)

| v2 Field | v3 Field |
|----------|----------|
| `response_code` | (envelope `data` presence) |
| `positives` | `last_analysis_stats.malicious` |
| `total` | `last_analysis_stats.harmless + malicious + suspicious + undetected` |
| `scan_date` | `last_analysis_date` (unix timestamp) |
| `sha256` | `sha256` (in `data.id` and `attributes.sha256`) |
| `scans` | `last_analysis_results` (engine_name → `LastAnalysisResult`) |
| `verbose_msg` | `error.message` (in envelope) |

## Rate Limiting

```csharp
var options = new VirusTotalOptions
{
    ApiKey = "key",
    RequestsPerMinute = 4,      // default
    RequestsPerDay = 500,       // default
    UseRetry = true,            // default
    MaxRetries = 3,             // default
    InitialRetryDelay = TimeSpan.FromMilliseconds(500)
};
```

## DI Integration (Optional)

```csharp
services.AddVirusTotal(config => {
    config.ApiKey = configuration["VirusTotal:ApiKey"];
    config.RequestsPerMinute = 4;
});

// In controller/service:
public class MyService {
    private readonly IVtClient _client;
    public MyService(IVtClient client) => _client = client;
}
```

## Key Resources

- [VirusTotal API v3 Docs](https://virustotal.readme.io)
- [API Reference](https://virustotal.readme.io/reference)
- [OpenAPI Spec](https://virustotal.readme.io/reference/openapi.json)

## Need Help?

- Check the [examples project](examples/) for full workflows
- Open an issue on [GitHub](https://github.com/zymuk/VirusTotalNet.V3)
- Review the [PRD.md](docs/PRD.md) for design decisions