using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Models.Attributes;

/// <summary>Well-known analysis status values (see <see cref="AnalysisAttributes.Status"/>).</summary>
public static class AnalysisStatus
{
    /// <summary>The analysis job is waiting to be picked up.</summary>
    public const string Queued = "queued";

    /// <summary>The analysis job is currently running.</summary>
    public const string InProgress = "in-progress";

    /// <summary>The analysis job has finished and results are available.</summary>
    public const string Completed = "completed";
}

/// <summary>
/// Attributes of an <c>analysis</c> object (see <see cref="AnalysisObject"/>): the status of the
/// job, aggregated verdict stats, and per-engine results. Fields not yet mapped are preserved
/// losslessly in <see cref="VtObject{TA}.Raw"/>.
/// </summary>
public sealed class AnalysisAttributes
{
    /// <summary>Current status of the analysis: <c>queued</c>, <c>in-progress</c>, or <c>completed</c>.</summary>
    public string? Status { get; set; }

    /// <summary>Time the analysis was created (Unix timestamp, seconds).</summary>
    public DateTimeOffset? Date { get; set; }

    /// <summary>Aggregated verdict statistics for this analysis.</summary>
    public LastAnalysisStats? Stats { get; set; }

    /// <summary>
    /// Per-engine detection results, keyed by engine name. Same shape as
    /// <see cref="VtFileAttributes.LastAnalysisResults"/> (<c>attributes.results</c>).
    /// </summary>
    public Dictionary<string, LastAnalysisResult>? Results { get; set; }

    /// <summary>
    /// Files involved in this analysis, keyed by SHA-256 (<c>attributes.files</c>). Present on
    /// file analyses, e.g. the entries of a scanned archive.
    /// </summary>
    public Dictionary<string, AnalysisFile>? Files { get; set; }

    /// <summary>Any attribute fields not mapped by properties above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}

/// <summary>
/// A file referenced by an analysis object (<c>attributes.files</c> value), e.g. an entry of a
/// scanned archive: the file hashes plus every name it is known by.
/// </summary>
public sealed class AnalysisFile
{
    /// <summary>MD5 digest of the file.</summary>
    public string? Md5 { get; set; }

    /// <summary>SHA-1 digest of the file.</summary>
    public string? Sha1 { get; set; }

    /// <summary>SHA-256 digest of the file.</summary>
    public string? Sha256 { get; set; }

    /// <summary>All known file names.</summary>
    public List<string>? Names { get; set; }
}