using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.V3.Models.Attributes;

/// <summary>Attributes of a saved search (<c>saved_search</c> object).</summary>
public sealed class SavedSearchAttributes
{
    /// <summary>Name of the saved search.</summary>
    public string? Name { get; set; }

    /// <summary>Search query string (<c>search_query</c> on the wire).</summary>
    [JsonPropertyName("search_query")]
    public string? Query { get; set; }

    /// <summary>Description of the saved search.</summary>
    public string? Description { get; set; }

    /// <summary>Whether the saved search is private.</summary>
    public bool? Private { get; set; }

    /// <summary>Tags associated with the saved search.</summary>
    public List<string>? Tags { get; set; }

    /// <summary>Origin of the saved search, e.g. <c>Crowdsourced</c> or <c>Partner</c>.</summary>
    public string? Origin { get; set; }

    /// <summary>Timestamp the search was created (Unix seconds).</summary>
    [JsonPropertyName("creation_date")]
    public DateTimeOffset? CreatedAt { get; set; }

    /// <summary>Timestamp the search was last modified (Unix seconds).</summary>
    [JsonPropertyName("last_modification_date")]
    public DateTimeOffset? UpdatedAt { get; set; }

    /// <summary>Timestamp the search was last executed (Unix seconds).</summary>
    [JsonPropertyName("last_execution_date")]
    public DateTimeOffset? LastExecutedAt { get; set; }

    /// <summary>User who created the search (if available).</summary>
    public string? CreatedBy { get; set; }

    /// <summary>Any attribute fields not mapped above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}