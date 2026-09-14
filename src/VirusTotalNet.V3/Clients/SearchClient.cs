using System;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Clients;

/// <summary>
/// Full-text search over all object types (<c>/intelligence/search</c>).
/// </summary>
public interface ISearchClient
{
    /// <summary>
    /// Runs an intelligence search query and returns one page of results.
    /// </summary>
    /// <param name="query">The search query, e.g. <c>type:url</c> or <c>name:powershell.exe</c>.</param>
    /// <param name="cursor">Optional pagination cursor for the next page.</param>
    /// <param name="descriptorsOnly">When <c>true</c>, the API returns only <c>(type, id)</c> descriptors to save quota.</param>
    /// <param name="order">Optional sort order, e.g. <c>date+</c> or <c>-last_modification_date</c>.</param>
    /// <param name="limit">Maximum number of results to return (1-300; the API default is 10).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A page of search hits with its next cursor.</returns>
    Task<VtCollection<VtSearchObject>> SearchAsync(string query, string? cursor = null, bool descriptorsOnly = false, string? order = null, int? limit = null, CancellationToken cancellationToken = default);
}

/// <summary>
/// <see cref="ISearchClient"/> implementation built on top of <see cref="VtClient"/>.
/// </summary>
public sealed class SearchClient : ISearchClient
{
    private readonly IVtClient _client;

    /// <summary>Creates a search client backed by the given <see cref="IVtClient"/>.</summary>
    public SearchClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<VtCollection<VtSearchObject>> SearchAsync(string query, string? cursor = null, bool descriptorsOnly = false, string? order = null, int? limit = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(query))
            throw new ArgumentException("A search query is required.", nameof(query));
        if (limit is < 1 or > 300)
            throw new ArgumentOutOfRangeException(nameof(limit), "The limit must be between 1 and 300.");

        var path = $"/intelligence/search?query={Uri.EscapeDataString(query.Trim())}";
        if (descriptorsOnly)
            path += "&descriptors_only=true";
        if (order is not null && order.Trim().Length > 0)
            path += $"&order={Uri.EscapeDataString(order.Trim())}";
        if (limit is not null)
            path += $"&limit={limit}";
        if (cursor is not null)
            path += $"&cursor={Uri.EscapeDataString(cursor)}";

        var response = await _client.GetAsync<List<VtSearchObject>>(path, cancellationToken).ConfigureAwait(false);
        return VtCollection<VtSearchObject>.FromEnvelope(response.EnsureSuccess());
    }
}