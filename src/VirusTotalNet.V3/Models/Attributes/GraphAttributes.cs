using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.V3.Models.Attributes;

/// <summary>Attributes of a <c>graph</c> object.</summary>
public sealed class GraphAttributes
{
    /// <summary>The graph data payload (contains the graph name/description and format version).</summary>
    public GraphData? GraphData { get; set; }

    /// <summary>Nodes of the graph.</summary>
    public List<GraphNode>? Nodes { get; set; }

    /// <summary>Links between nodes.</summary>
    public List<GraphLink>? Links { get; set; }

    /// <summary>Whether the graph is private.</summary>
    public bool? Private { get; set; }

    /// <summary>The graph viewport / scale.</summary>
    public GraphPosition? Position { get; set; }

    /// <summary>Number of comments.</summary>
    public long? CommentsCount { get; set; }

    /// <summary>Number of times the graph has been viewed.</summary>
    public long? ViewsCount { get; set; }

    /// <summary>Creation timestamp (Unix seconds).</summary>
    [JsonPropertyName("creation_date")]
    public DateTimeOffset? CreatedAt { get; set; }

    /// <summary>Last modification timestamp (Unix seconds).</summary>
    [JsonPropertyName("last_modified_date")]
    public DateTimeOffset? UpdatedAt { get; set; }

    /// <summary>Any attribute fields not mapped above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}