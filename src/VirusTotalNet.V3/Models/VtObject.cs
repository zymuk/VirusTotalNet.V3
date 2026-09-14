using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.V3.Models;

/// <summary>
/// Base class of every API object (file, URL, domain, IP address, ...). Subclass it with the
/// concrete attributes POCO, e.g. <c>public sealed class FileObject : VtObject&lt;FileAttributes&gt; { }</c>.
/// </summary>
/// <typeparam name="TA">POCO mapping the <c>attributes</c> object of the entity.</typeparam>
public abstract class VtObject<TA> where TA : class
{
    /// <summary>Type of the object, e.g. <c>file</c>, <c>url</c>.</summary>
    public string Type { get; set; } = string.Empty;

    /// <summary>Identifier of the object, e.g. the SHA-256 for files.</summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>Typed attributes; <c>null</c> when the API did not include them (e.g. relationship entries).</summary>
    public TA? Attributes { get; set; }

    /// <summary>Related objects; the raw map is preserved losslessly.</summary>
    public VtRelationships? Relationships { get; set; }

    /// <summary>Links of the object, typically a <c>self</c> URL.</summary>
    public VtLinks? Links { get; set; }

    /// <summary>Any object fields not mapped by properties above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}