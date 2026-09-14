# VirusTotal.NET - A full implementation of the VirusTotal 3.0 API

[![NuGet](https://img.shields.io/nuget/v/VirusTotalNet.V3.svg?style=flat-square&label=nuget)](https://www.nuget.org/packages/VirusTotalNet.V3/)

### Features

* Fully asynchronous; zero external dependencies (`net8.0` trimmable/AOT-compatible + `netstandard2.0`)
* `VirusTotal` facade keeps the calls of the old v2 library — `GetFileReportAsync`, `ScanFileAsync(path)`, `RescanFileAsync`, `GetIPReportAsync`, `GetDomainReportAsync`, `GetUrlReportAsync(url, scanIfNoReport)` — so most v2 code compiles unchanged (results are the v3 models)
* Scan, rescan and reports for files, URLs, IP addresses and domains; comments & votes on any object
* Intelligence search, saved searches, collections, graphs, threat actors, behaviour reports and relationship traversal
* Premium: feeds, private scanning, hunting rulesets, retrohunt, users & groups
* Built-in file size limits, configurable rate limits (4 req/min & 500 req/day), retry with backoff, and `ThrowOnError=false` Result-style error handling

### Examples

Every example below is shipped and runnable in the `VirusTotalNet.V3.Examples` console project (`VT_API_KEY` required).

The classic EICAR "seen before?" check, one line like the v2 library. Set `VT_API_KEY` and run the console project:

```csharp
using System.Text;
using VirusTotalNet.V3;
using VirusTotalNet.V3.Models;

var vt = new VirusTotal("YOUR_API_KEY");

byte[] eicar = Encoding.ASCII.GetBytes(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

FileObject file = await vt.GetFileReportAsync(eicar);
Console.WriteLine("Malicious: " + file.Attributes.LastAnalysisStats.Malicious);
```

`GetFileReportAsync` looks the file up by its computed SHA-256; if VirusTotal does not know it yet, the facade submits a scan, waits for completion, and returns the fresh report.

Upload a file, wait for the analysis to finish, then fetch the result — the same flow, straight from the facade (the underlying module clients stay reachable through `FileClient`/`AnalysisClient`):

```csharp
using System.Security.Cryptography;
using VirusTotalNet.V3;
using VirusTotalNet.V3.Models;

var vt = new VirusTotal("YOUR_API_KEY");

string path = @"C:\path\to\file.exe";          // point at a real file

// 1. Scan the file straight from its path (overloads also take FileInfo or byte[] + filename).
AnalysisObject analysis = await vt.ScanFileAsync(path);

// 2. Wait until the analysis finishes (polls through the shared rate limiter).
AnalysisObject completed = await vt.WaitForCompletionAsync(analysis.Id);
Console.WriteLine("Status: " + completed.Attributes.Status);

// 3. Fetch the final report by SHA-256 and read the detection stats.
string sha256 = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(path))).ToLowerInvariant();
FileObject report = await vt.GetFileReportAsync(sha256);   // or vt.FileClient.GetFileAsync(sha256) for a pure lookup
Console.WriteLine("Malicious: " + report.Attributes.LastAnalysisStats.Malicious);
```

`ScanFileAsync` returns the created analysis; `WaitForCompletionAsync` polls until the status is terminal; `GetFileReportAsync(sha256)` then returns the fresh report including the per-engine statistics.

Walk the links between objects: look a file up, then query it directly by type or traverse its relationships from the object at hand:

```csharp
using VirusTotalNet.V3;
using VirusTotalNet.V3.Models;
using VirusTotalNet.V3.Relationships;

var vt = new VirusTotal("YOUR_API_KEY");
FileObject file = await vt.GetFileReportAsync("sha256_of_the_file");

// Query a domain directly by type, all on the facade.
DomainObject domain = await vt.GetDomainAsync("example.com");
VtCollection<DomainObject> subs = await vt.GetDomainSubdomainsAsync("example.com");
VtCollection<ResolutionObject> resolutions = await vt.GetDomainResolutionsAsync("example.com");

// Walk relationships from the file object without knowing API paths.
VtCollection<VtObjectId> commentIds = await vt.Relationships.GetRelatedIdsAsync("files", file.Id, "comments"); // ids only
VtCollection<UrlObject> contacted = await file.ContactedUrlsAsync(vt.Relationships);                          // typed + memoized
await foreach (UrlObject url in vt.Relationships.TraverseAsync<UrlObject>("files", file.Id, "contacted_urls")) // all pages
{
    Console.WriteLine(url.Id);
}
```

These lookup methods are hoisted onto the facade (`GetDomainAsync`, `GetIpAsync`, `GetUrlAsync`, ...), and the module clients (`UrlClient`, `DomainClient`, `IpClient`, `FeedbackClient`, `Relationships`) remain reachable through facade properties — so both "query by type you already know" and "navigate from an object in hand" work without constructing clients yourself. Traversals share one rate limiter plus memoized first pages so they stay budget-friendly.

Run an intelligence search and handle errors without try/catch — `ThrowOnError` stays on by default, or switch to Result-style:

```csharp
using VirusTotalNet.V3;
using VirusTotalNet.V3.Models;

var vt = new VirusTotal("YOUR_API_KEY");

// /intelligence/search, cursor-paged like every collection.
VtCollection<VtSearchObject> hits = await vt.SearchAsync("type:domain tags:phishing", descriptorsOnly: true);
foreach (VtSearchObject hit in hits.Items)
    Console.WriteLine($"{hit.Type} / {hit.Id}");

// Result-style: TryGetAsync/TryPostAsync never throw for API errors.
VtResult<FileObject> lookup = await vt.Client.TryGetAsync<FileObject>("/files/unknown-hash");
if (lookup.IsSuccess)
    Console.WriteLine("File found: " + lookup.Value!.Id);
else
    Console.WriteLine($"HTTP {(int)lookup.Error!.StatusCode!}: {lookup.Error.Code} — {lookup.Error.Message}");
```

`SearchAsync` mirrors the other collection clients (`VtCollection<T>` with `Count`/`NextCursor`); `TryGetAsync`/`TryPostAsync` return a `VtResult<T>` discriminated union and still apply the shared rate limiter and retry policy.

Optional package `VirusTotalNet.V3.DependencyInjection` wires everything into your DI container:

```csharp
using Microsoft.Extensions.DependencyInjection;
using VirusTotalNet.V3.Clients;
using VirusTotalNet.V3.DependencyInjection;
using VirusTotalNet.V3.Models;

var services = new ServiceCollection();

// From a delegate...
services.AddVirusTotal(options => options.ApiKey = "YOUR_API_KEY");
// ...or from an IConfiguration section named "VirusTotal".
// services.AddVirusTotal(configuration);

using var provider = services.BuildServiceProvider();

// All clients share one IVtClient (rate limiter, retry, api key).
var fileClient = provider.GetRequiredService<IFileClient>();
FileObject report = await fileClient.GetFileAsync("sha256_of_the_file");
```

Batch report generator — the `VirusTotalNet.V3.ReportGenerator` console tool scans one or more files, uploads the ones VirusTotal has never seen (choosing the pre-signed large-file flow automatically when over 32 MB), waits for the analyses, and writes a self-contained HTML-reporting XML using the original emotive XSL style (opens in any browser). Pass `-apiKey=<key>` or set the `VT_API_KEY` environment variable, then supply the path to scan:

```shell
# using the -apiKey flag
dotnet run --project src/VirusTotalNet.V3.ReportGenerator -- -apiKey=YOUR_KEY -path=D:\MyFolder -report=D:\Report.xml

# using VT_API_KEY env var
set VT_API_KEY=...
dotnet run --project src/VirusTotalNet.V3.ReportGenerator -- -path=D:\MyFolder -report=D:\Report.xml
```

Other flags: `-showTabAnalyzing` opens the VirusTotal GUI in a browser after each lookup, `-logPathUpload=<logfile>` writes scan IDs to a log file.

Features and examples in this README only appear once they are implemented and tested.