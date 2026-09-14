using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.V3.Models;

/// <summary>
/// An object returned by the Intelligence IoC Stream (<c>GET /ioc_stream</c>). The objects
/// are polymorphic (files, URLs, domains, IP addresses); the object kind is <see cref="Type"/>
/// and <see cref="Id"/> holds its identifier. <see cref="ContextAttributes"/> carries the
/// notification context attached by the stream. When <c>descriptors_only=false</c> the full
/// attributes are kept losslessly in <see cref="Raw"/>.
/// </summary>
public sealed class VtIocStreamObject
{
    /// <summary>Type of the object, e.g. <c>file</c>, <c>url</c>, <c>domain</c>, <c>ip_address</c>.</summary>
    public string Type { get; set; } = string.Empty;

    /// <summary>Identifier of the object, e.g. the SHA-256 for files.</summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>Notification context attached by the IoC Stream.</summary>
    public IocStreamContextAttributes? ContextAttributes { get; set; }

    /// <summary>Any object fields not mapped above (full <c>attributes</c>, relationships, ...), preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}

/// <summary>Context attributes attached by the IoC Stream to every returned object.</summary>
public sealed class IocStreamContextAttributes
{
    /// <summary>Identifier of the notification; usable on the <c>ioc_stream_notifications</c> endpoints.</summary>
    public string? NotificationId { get; set; }

    /// <summary>Creation date of the notification (UTC timestamp).</summary>
    public long? NotificationDate { get; set; }

    /// <summary>Origin of the notification, e.g. <c>hunting</c> or <c>subscriptions</c>.</summary>
    public string? Origin { get; set; }

    /// <summary>Notification tags (usable with the <c>notification_tag:</c> filter).</summary>
    public List<string>? Tags { get; set; }

    /// <summary>Sources that triggered the notification (e.g. the hunting ruleset).</summary>
    public List<IocStreamSource>? Sources { get; set; }

    /// <summary>Extra contextual information for notifications of <c>hunting</c> origin.</summary>
    public HuntingContextInfo? HuntingInfo { get; set; }
}

/// <summary>A source object that triggered an IoC Stream notification.</summary>
public sealed class IocStreamSource
{
    /// <summary>Type of the source, e.g. <c>hunting_ruleset</c>.</summary>
    public string? Type { get; set; }

    /// <summary>Identifier of the source object.</summary>
    public string? Id { get; set; }

    /// <summary>Human-readable label of the source.</summary>
    public string? Label { get; set; }
}

/// <summary>Additional context for IoC Stream notifications coming from livehunting.</summary>
public sealed class HuntingContextInfo
{
    /// <summary>Name of the matched rule.</summary>
    public string? RuleName { get; set; }

    /// <summary>Tags of the matched rule.</summary>
    public List<string>? RuleTags { get; set; }

    /// <summary>Matched contents inside the file as a hexdump.</summary>
    public string? Snippet { get; set; }

    /// <summary>Country where the matched file was uploaded from.</summary>
    public string? SourceCountry { get; set; }

    /// <summary>Unique identifier for the source in ciphered form.</summary>
    public string? SourceKey { get; set; }
}