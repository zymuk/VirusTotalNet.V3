using System.Collections.Generic;

namespace VirusTotalNet.V3.Models;

/// <summary>
/// API usage of a user/group broken down by endpoint and day
/// (payload of <c>/users/{id}/api_usage</c> and <c>/groups/{id}/api_usage</c>).
/// Daily maps are keyed by date (<c>YYYY-MM-DD</c>) then endpoint pattern; totals are
/// keyed by endpoint pattern directly.
/// </summary>
public sealed class ApiUsage
{
    /// <summary>Requests consuming quota, keyed by day then endpoint.</summary>
    public Dictionary<string, Dictionary<string, long>>? Daily { get; set; }

    /// <summary>Requests not consuming quota, keyed by day then endpoint.</summary>
    public Dictionary<string, Dictionary<string, long>>? DailyEndpointsNotConsumingQuota { get; set; }

    /// <summary>Total quota-consuming requests, keyed by endpoint.</summary>
    public Dictionary<string, long>? Total { get; set; }

    /// <summary>Total non-quota-consuming requests, keyed by endpoint.</summary>
    public Dictionary<string, long>? TotalEndpointsNotConsumingQuota { get; set; }
}