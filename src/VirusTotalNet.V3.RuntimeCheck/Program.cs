using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Reflection;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using VirusTotalNet.V3;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;
using VirusTotalNet.V3.Models.Attributes;

namespace RuntimeCheck;

/// <summary>
/// Condition #4 verification — runtime check: a net8.0 console app that references the
/// <b>netstandard2.0</b> build of VirusTotalNet.V3 and exercises the JSON converters,
/// envelope models and the full client pipeline against realistic VirusTotal payloads.
/// Exits non-zero on the first failure so it can gate builds.
/// </summary>
internal static class Program
{
    private const string Sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    private const string SampleFileReport = """
        {
          "data": {
            "type": "file",
            "id": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "attributes": {
              "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
              "md5": "44d88612fea8a8f36de82e1278abb02f",
              "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
              "size": 68,
              "type": "txt",
              "last_analysis_date": 1726060800,
              "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 62,
                "harmless": 0,
                "timeout": 0,
                "type-unsupported": 0
              },
              "last_analysis_results": {
                "Acronis": {
                  "engine_name": "Acronis",
                  "engine_version": "1.2.0.17",
                  "engine_update": "20240910",
                  "method": "blacklist",
                  "category": "harmless",
                  "result": "clean"
                }
              },
              "magic": "ASCII text",
              "meaningful_name": "eicar.com"
            },
            "links": {
              "self": "https://www.virustotal.com/api/v3/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
            }
          },
          "meta": {
            "file_info": {
              "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
              "threat_label": null,
              "popular_threat_category": null,
              "size": 68
            }
          },
          "links": {
            "self": "https://www.virustotal.com/api/v3/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
          }
        }
        """;

    private static async Task<int> Main()
    {
        var assembly = typeof(VirusTotal).Assembly;
        var tfm = assembly.GetCustomAttribute<TargetFrameworkAttribute>()?.FrameworkName;
        Console.WriteLine($"Loaded assembly : {assembly.FullName}");
        Console.WriteLine($"Assembly location: {assembly.Location}");
        Console.WriteLine($"Target framework: {tfm}");

        if (tfm is null || !tfm.Contains(".NETStandard", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine($"FATAL: expected the netstandard2.0 build, loaded TFM {tfm}.");
            return 1;
        }

        try
        {
            CheckEnvelopeAndConverters();

            using var client = new VtClient(
                new VirusTotalOptions
                {
                    ApiKey = "runtime-check",
                    RequestsPerMinute = 1000,
                    RequestsPerDay = 1000000,
                },
                new HttpClient(new StubHandler()));

            await CheckClientPipelineAsync(client);
            await CheckResultStyleAsync(client);
            await CheckErrorMappingAsync(client);

            Console.WriteLine("RuntimeCheck (netstandard2.0 build) OK — converters + envelope + client pipeline verified.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"FATAL: {ex}");
            return 1;
        }
    }

    private static void CheckEnvelopeAndConverters()
    {
        var envelope = JsonSerializer.Deserialize<VtResponse<FileObject>>(
            SampleFileReport,
            VirusTotalJson.Options);
        var resolvedAttrs = envelope?.Data?.Attributes;
        Require(resolvedAttrs is not null, "Envelope/attributes did not deserialize.");
        var attrs = resolvedAttrs;

        Require(attrs.Sha256 == Sha256, $"Unexpected sha256: {attrs.Sha256}");
        Require(attrs.Size == 68, $"Unexpected size: {attrs.Size}");
        Require(attrs.LastAnalysisStats?.Malicious == 0, "Malicious count mismatch.");
        Require(attrs.LastAnalysisStats?.Undetected == 62, "Undetected count mismatch.");

        var acronis = attrs.LastAnalysisResults is { } results && results.TryGetValue("Acronis", out var acronisValue)
            ? acronisValue
            : null;
        Require(acronis is not null, "Acronis engine result missing.");
        Require(acronis!.Category == "harmless", $"Unexpected Acronis category: {acronis.Category}");
        Require(acronis.EngineUpdate == "20240910", $"YYYYmmdd engine_update not converted: {acronis.EngineUpdate}");
        Require(acronis.Result == "clean", $"Unexpected Acronis result: {acronis.Result}");

        Require(attrs.Raw.ContainsKey("last_analysis_date"), "last_analysis_date not preserved in Raw.");
        var meta = envelope?.Meta;
        Require(meta is not null && meta.Raw.ContainsKey("file_info"), "meta.file_info not preserved in Raw.");
    }

    private static async Task CheckClientPipelineAsync(VtClient client)
    {
        var file = await client.GetAsync<FileObject>("/files/" + Sha256);
        Require(file?.Data?.Attributes?.Sha256 == Sha256, "GetAsync<FileObject> pipeline mismatch.");
    }

    private static async Task CheckResultStyleAsync(VtClient client)
    {
        var result = await client.TryGetAsync<FileObject>("/files/" + Sha256);
        Require(result.IsSuccess, "TryGetAsync should succeed for a known object.");
        Require(result.Value!.Attributes?.Sha256 == Sha256, "TryGetAsync value mismatch.");
    }

    private static async Task CheckErrorMappingAsync(VtClient client)
    {
        bool mapped = false;
        try
        {
            await client.GetAsync<FileObject>("/files/0000000000000000000000000000000000000000000000000000000000000000");
        }
        catch (NotFoundException)
        {
            mapped = true;
        }

        Require(mapped, "Expected NotFoundException for a 404 envelope.");
    }

    private static void Require([DoesNotReturnIf(false)] bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private static readonly string NotFoundEnvelope = """
            { "error": { "code": "NotFoundError", "message": "File not found" } }
            """;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            var body = path.EndsWith("/0000000000000000000000000000000000000000000000000000000000000000", StringComparison.Ordinal)
                ? NotFoundEnvelope
                : SampleFileReport;

            return Task.FromResult(
                new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(body, Encoding.UTF8, "application/json"),
                });
        }
    }
}