using System.Text;
using VirusTotalNet.V3;
using VirusTotalNet.V3.Models;

var apiKey = Environment.GetEnvironmentVariable("VT_API_KEY");
if (string.IsNullOrWhiteSpace(apiKey))
{
    Console.WriteLine("Set the VT_API_KEY environment variable to run this example.");
    return;
}

// EICAR is the standard antivirus test file; VirusTotal always has it in its database.
byte[] eicar = Encoding.ASCII.GetBytes(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

using var vt = new VirusTotal(apiKey);

// "Have I seen this before?" — one line, in the spirit of the v2 library.
var file = await vt.GetFileReportAsync(eicar);

Console.WriteLine($"SHA-256 : {file.Id}");
Console.WriteLine($"Malicious: {file.Attributes?.LastAnalysisStats?.Malicious}");

Console.WriteLine();
Console.WriteLine("=== Upload a file -> wait -> fetch result ===");

if (args.Length == 0)
{
    Console.WriteLine("Pass a file path as the first argument, e.g.: dotnet run -- sample.exe");
    return;
}

string path = args[0];
byte[] payload = await File.ReadAllBytesAsync(path);

// 1. Scan the file straight from its path and get the analysis id.
var analysis = await vt.ScanFileAsync(path);

// 2. Wait until the analysis finishes (polls through the shared rate limiter).
var completed = await vt.WaitForCompletionAsync(analysis.Id);
Console.WriteLine($"Analysis {completed.Id}: status = {completed.Attributes?.Status}");

// 3. Fetch the final report by SHA-256 and show the detection stats.
string sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(payload)).ToLowerInvariant();
var report = await vt.GetFileReportAsync(sha256);
Console.WriteLine($"SHA-256   : {report.Id}");
Console.WriteLine($"Malicious : {report.Attributes?.LastAnalysisStats?.Malicious}");

Console.WriteLine();
Console.WriteLine("=== URLs / Domains / IPs ===");

var domain = await vt.GetDomainAsync("example.com");
Console.WriteLine($"Domain: {domain.Id} (registrar: {domain.Attributes?.Registrar}, malicious: {domain.Attributes?.LastAnalysisStats?.Malicious})");

var subs = await vt.GetDomainSubdomainsAsync("example.com");
Console.WriteLine($"Subdomains: {subs.Count} on this page — first few:");
foreach (var sub in subs.Items.Take(5))
    Console.WriteLine("  " + sub.Id);

var resolutions = await vt.GetDomainResolutionsAsync("example.com");
Console.WriteLine($"Resolutions: {resolutions.Count} on this page — first few:");
foreach (var res in resolutions.Items.Take(5))
    Console.WriteLine("  -> " + res.Attributes?.IpAddress);

Console.WriteLine();
Console.WriteLine("=== Relationships from an object in hand ===");

Console.WriteLine($"Walking relationships of {file.Id} (the EICAR sample):");

// Descriptor-first: (type, id) only, light on quota.
var commentIds = await vt.GetRelatedIdsAsync("files", file.Id, "comments");
Console.WriteLine($"comments: {commentIds.Count} ids on this page");

// Typed accessor (first page is memoized per session).
var contacted = await vt.GetRelatedAsync<UrlObject>("files", file.Id, "contacted_urls");
Console.WriteLine($"contacted_urls: {contacted.Count} on this page — first few:");
foreach (var url in contacted.Items.Take(5))
    Console.WriteLine("  " + url.Id);

// Generic fallback + paged traversal (bounded to keep the demo quota-friendly).
var total = 0;
await foreach (var url in vt.TraverseRelatedAsync<UrlObject>("files", file.Id, "contacted_urls"))
{
    total++;
    if (total >= 5)
        break;
}
Console.WriteLine($"traversed contacted_urls: {total} items (bounded)");

Console.WriteLine();
Console.WriteLine("=== Intelligence search + result-style (no-throw) ===");

var results = await vt.SearchAsync("type:domain tags:phishing", descriptorsOnly: true);
Console.WriteLine($"Search: {results.Count} matches on this page — first few:");
foreach (var hit in results.Items.Take(5))
    Console.WriteLine($"  {hit.Type} / {hit.Id}");

// Result-style: never throws for API errors, errors come back as VtResult.
var lookup = await vt.TryGetAsync<FileObject>("/files/definitely-not-a-real-hash");
if (lookup.IsSuccess)
    Console.WriteLine("File found: " + lookup.Value!.Id);
else
    Console.WriteLine($"Lookup failed (HTTP {(int)lookup.Error!.StatusCode!}): {lookup.Error.Code} — {lookup.Error.Message}");