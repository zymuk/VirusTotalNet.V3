using System.Collections.Generic;
using System.Text.Json;

namespace VirusTotalNet.V3.Models;

/// <summary>The high-level graph payload (<c>graph_data</c> attribute).</summary>
public sealed class GraphData
{
    /// <summary>The graph name (the API stores the name inside <c>graph_data.description</c>).</summary>
    public string? Description { get; set; }

    /// <summary>The graph format version.</summary>
    public string? Version { get; set; }
}

/// <summary>A node in a graph (<c>nodes</c> attribute).</summary>
public sealed class GraphNode
{
    /// <summary>Id of the entity the node represents, e.g. a file hash or a domain name.</summary>
    public string? EntityId { get; set; }

    /// <summary>Node type, e.g. <c>file</c>, <c>url</c>, <c>domain</c>, <c>ip_address</c> or <c>relationship</c>.</summary>
    public string? Type { get; set; }

    /// <summary>Node label.</summary>
    public string? Text { get; set; }

    /// <summary>Index of the node in the node list.</summary>
    public int? Index { get; set; }

    /// <summary>Relative horizontal location of the node.</summary>
    public float? X { get; set; }

    /// <summary>Relative vertical location of the node.</summary>
    public float? Y { get; set; }

    /// <summary>Pinned horizontal position (optional).</summary>
    public float? Fx { get; set; }

    /// <summary>Pinned vertical position (optional).</summary>
    public float? Fy { get; set; }

    /// <summary>Entity specific attributes (optional).</summary>
    public Dictionary<string, JsonElement>? EntityAttributes { get; set; }
}

/// <summary>A link between two graph nodes (<c>links</c> attribute).</summary>
public sealed class GraphLink
{
    /// <summary>Entity id of the link source.</summary>
    public string? Source { get; set; }

    /// <summary>Entity id of the link target.</summary>
    public string? Target { get; set; }

    /// <summary>Type of the connection between source and target.</summary>
    public string? ConnectionType { get; set; }
}

/// <summary>The graph viewport (<c>position</c> attribute).</summary>
public sealed class GraphPosition
{
    /// <summary>Horizontal position.</summary>
    public float? X { get; set; }

    /// <summary>Vertical position.</summary>
    public float? Y { get; set; }

    /// <summary>Zoom scale.</summary>
    public string? Scale { get; set; }
}