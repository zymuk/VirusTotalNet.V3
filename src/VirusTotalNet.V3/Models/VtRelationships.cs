using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.V3.Models;

/// <summary>
/// The <c>relationships</c> object of an API object. Each relationship is deserialized losslessly
/// into <see cref="Raw"/>; typed, strongly-typed accessors are layered on top elsewhere
/// (see the <c>VirusTotalNet.V3.Relationships</c> namespace).
/// </summary>
public sealed class VtRelationships
{
    /// <summary>Relationship name → payload, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}