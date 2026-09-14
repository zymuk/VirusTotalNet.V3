# VirusTotal.NET - A full implementation of the VirusTotal 3.0 API

[![NuGet](https://img.shields.io/nuget/v/VirusTotalNet.V3.svg?style=flat-square&label=nuget)](https://www.nuget.org/packages/VirusTotalNet.V3/)

### Features

* Zero external dependencies; targets `net8.0` (trimmable, AOT-compatible) and `netstandard2.0`, packaged as `VirusTotalNet.V3`
* Single envelope `VtResponse<T>` with lossless `JsonExtensionData` and tolerant JSON converters (string-typed numbers, Unix timestamps, crammed dates) for every endpoint
* `VtClient` — `x-apikey` auth, base URL, AOT-safe overloads, shared rate limiter (4 req/min & 500 req/day), retry with exponential backoff + jitter; maps `error.code` to a typed exception hierarchy (`ThrowOnError` toggle); `GetRawAsync<T>` for the handful of endpoints with bare (non-envelope) JSON payloads
* Files — scan (≤ 32 MB), upload > 32 MB via pre-signed URL, report by md5/sha1/sha256, rescan, download; optional ZIP `password` for encrypted archives; typed per-engine results (`LastAnalysisResults`) plus aggregated `LastAnalysisStats`
* Analyses — get analysis, `WaitForCompletionAsync` with configurable polling
* URLs / Domains / IPs — scan, get, rescan; resolutions, subdomains
* Comments & votes on any object type (list + create), plus comment management — `GET /comments` (filter/limit/cursor), `GET/DELETE /comments/{id}`, and voting on a comment (`POST /comments/{id}/vote` as `Positive`/`Negative`/`Abuse` counts)
* Saved searches — create (name + `search_query`, optional description/private/tags), list, get, delete under `/saved_searches`
* Collections — create/get/update/delete collections and manage element relationships `/collections/{id}/{files|urls|domains|ip_addresses}` (add/remove/list)
* Graphs — create/update/get/delete `/graphs` with the documented `graph_data`/`nodes`/`links`/`private` schema (create requires at least one payload)
* Threat actors — retrieve `/threat_actors/{id}` profiles
* Relationships — typed accessors + generic fallback, descriptor-first ids, memoized `IAsyncEnumerable` traversal
* Behaviours — per-file sandbox behaviour reports (`IBehaviourClient`/`BehaviourClient`): retrieve a `file_behaviour`, download EVTX/PCAP/memdump/HTML artifacts
* Search — `/intelligence/search` via `ISearchClient`/`SearchClient` (cursor pagination, `descriptors_only` mode, `order`, `limit` up to 300)
* Feeds (premium) — `IFeedsClient`/`FeedsClient` streams bzip2-compressed NDJSON batches of files, URLs, domains, IPs and file behaviours (`/feeds/{type}/{time}` per-minute; `/feeds/{type}/hourly/{time}` hourly for all five types); raw `Stream` returned so you can decompress any way you like
* Private scanning (premium) — `IPrivateScanningClient`/`PrivateScanningClient`: upload samples under `/private/files` (multipart with sandbox/network/TLS options), upload URL, list/get/delete, analyse, retrieve private analyses and behaviour reports without sharing samples publicly
* Livehunt hunting rulesets — `IHuntingClient`/`HuntingClient`: create/list/get/update/delete YARA rulesets under `/intelligence/hunting_rulesets` (fail-fast on rule name, rules and match object type), list/get hunting notifications, and read the Intelligence IoC Stream (`/ioc_stream`, filter/limit/order/cursor-paged with notification context)
* Retrohunt — `IRetrohuntClient`/`RetrohuntClient`: create/list/get/abort `/intelligence/retrohunt_jobs` (rules, notification email, `main`/`goodware` corpus, time range) and list the matching files
* Users & groups — `IUsersClient`/`UsersClient`: get/update/delete users and groups, manage group membership (add/remove via `/groups/{id}/relationships/users`, assign group roles `USER_ROLE_GROUP_ADMIN`/`USER_ROLE_PRIVATE_SCANNING` as set/add/remove), and read per-user API usage breakdowns
* Error handling — `ThrowOnError=false` returns the error envelope; Result-style `VtResult<T>` through `IVtClient.Try*`, so checks never need a try/catch
* `VirusTotal` facade — v2-style one-liners: `GetFileReportAsync(hash)` / `GetFileReportAsync(bytes)`, auto-scans and waits when the file is unknown; exposes all 18 module clients (`FileClient`, `AnalysisClient`, `Relationships`, `UrlClient`, `DomainClient`, `IpClient`, `Behaviour`, `Feedback`, `Search`, `SavedSearchClient`, `CollectionClient`, `GraphClient`, `ThreatActor`, `Feeds`, `PrivateScanning`, `Hunting`, `Retrohunt`, `Users`)
* DI — optional `VirusTotalNet.V3.DependencyInjection` package: `AddVirusTotal` (options delegate or `IConfiguration` section) registers the client, all module clients and the facade behind one shared `IVtClient`

### Examples

Every example below is shipped and runnable in the `VirusTotalNet.V3.Examples` console project (`VT_API_KEY` required).

The classic EICAR "seen before?" check, one line like the v2 library. Set `VT_API_KEY` and run the console project:

```csharp
using System.Text;
using VirusTotalNet.V3;

var vt = new VirusTotal("YOUR_API_KEY");

byte[] eicar = Encoding.ASCII.GetBytes(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

FileObject file = await vt.GetFileReportAsync(eicar);
Console.WriteLine("Malicious: " + file.Attributes.LastAnalysisStats.Malicious);
```

`GetFileReportAsync` looks the file up by its computed SHA-256; if VirusTotal does not know it yet, the facade submits a scan, waits for completion, and returns the fresh report.

Upload a file, wait for the analysis to finish, then fetch the result — the same flow, this time against the underlying module clients:

```csharp
using System.Text;
using VirusTotalNet.V3;

var vt = new VirusTotal("YOUR_API_KEY");

string path = @"C:\path\to\file.exe";          // point at a real file
byte[] payload = await File.ReadAllBytesAsync(path);

// 1. Upload the file and get its analysis id.
using var upload = new MemoryStream(payload);
AnalysisObject analysis = await vt.FileClient.ScanFileAsync(upload, fileName: Path.GetFileName(path));

// 2. Wait until the analysis finishes (polls through the shared rate limiter).
AnalysisObject completed = await vt.AnalysisClient.WaitForCompletionAsync(analysis.Id);
Console.WriteLine("Status: " + completed.Attributes.Status);

// 3. Fetch the final report by SHA-256 and read the detection stats.
string sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(payload)).ToLowerInvariant();
FileObject report = await vt.FileClient.GetFileAsync(sha256);
Console.WriteLine("Malicious: " + report.Attributes.LastAnalysisStats.Malicious);
```

`ScanFileAsync` returns the created analysis; `WaitForCompletionAsync` polls until the status is terminal; `GetFileAsync` then returns the fresh report including the per-engine statistics.

Walk the links between objects: look a file up, then query it directly by type (M3 clients) or traverse its relationships from the object at hand (M4):

```csharp
using VirusTotalNet.V3;
using VirusTotalNet.V3.Clients;
using VirusTotalNet.V3.Relationships;

var vt = new VirusTotal("YOUR_API_KEY");
FileObject file = await vt.FileClient.GetFileAsync("sha256_of_the_file");

// M3 — query a domain directly by type.
var domains = new DomainClient(vt.Client);
DomainObject domain = await domains.GetDomainAsync("example.com");
VtCollection<DomainObject> subs = await domains.GetSubdomainsAsync("example.com");
VtCollection<ResolutionObject> resolutions = await domains.GetResolutionsAsync("example.com");

// M4 — walk relationships from the file object without knowing API paths.
VtCollection<VtObjectId> commentIds = await vt.Relationships.GetRelatedIdsAsync("files", file.Id, "comments"); // ids only
VtCollection<UrlObject> contacted = await file.ContactedUrlsAsync(vt.Relationships);                          // typed + memoized
await foreach (UrlObject url in vt.Relationships.TraverseAsync<UrlObject>("files", file.Id, "contacted_urls")) // all pages
{
    Console.WriteLine(url.Id);
}
```

M3 clients (`UrlClient`, `DomainClient`, `IpClient`, `FeedbackClient`) target a specific object type you already know. M4 navigation works off an object in hand — no need to remember endpoint paths — and shares one rate limiter plus memoized first pages so traversals stay budget-friendly.

Run an intelligence search and handle errors without try/catch — `ThrowOnError` stays on by default, or switch to Result-style:

```csharp
using VirusTotalNet.V3;
using VirusTotalNet.V3.Clients;

var vt = new VirusTotal("YOUR_API_KEY");

// M5 — /intelligence/search, cursor-paged like every collection.
var search = new SearchClient(vt.Client);
VtCollection<VtSearchObject> hits = await search.SearchAsync("type:domain tags:phishing", descriptorsOnly: true);
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

M6 — optional package `VirusTotalNet.V3.DependencyInjection` wires everything into your DI container:

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