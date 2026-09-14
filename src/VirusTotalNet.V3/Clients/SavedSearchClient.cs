using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Clients;

/// <summary>Operations on saved searches (<c>/saved_searches</c>).</summary>
public interface ISavedSearchClient
{
    /// <summary>
    /// Creates a saved search (<c>POST /saved_searches</c>).
    /// The query is stored under the API's <c>search_query</c> attribute.
    /// </summary>
    Task<SavedSearchObject> CreateSavedSearchAsync(string name, string query, string? description = null, bool? isPrivate = null, IReadOnlyList<string>? tags = null, CancellationToken cancellationToken = default);

    /// <summary>Retrieves a saved search (<c>GET /saved_searches/{id}</c>).</summary>
    Task<SavedSearchObject> GetSavedSearchAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>List saved searches (<c>GET /saved_searches</c>) with cursor pagination.</summary>
    Task<VtCollection<SavedSearchObject>> ListSavedSearchesAsync(string? cursor = null, CancellationToken cancellationToken = default);

    /// <summary>Deletes a saved search (<c>DELETE /saved_searches/{id}</c>).</summary>
    Task DeleteSavedSearchAsync(string id, CancellationToken cancellationToken = default);
}

/// <summary><see cref="ISavedSearchClient"/> implementation built on top of <see cref="VtClient"/>.</summary>
public sealed class SavedSearchClient : ISavedSearchClient
{
    private readonly IVtClient _client;

    /// <summary>Creates a saved-search client backed by the given <see cref="IVtClient"/>.</summary>
    public SavedSearchClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<SavedSearchObject> CreateSavedSearchAsync(string name, string query, string? description = null, bool? isPrivate = null, IReadOnlyList<string>? tags = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("A saved search name is required.", nameof(name));
        if (string.IsNullOrWhiteSpace(query))
            throw new ArgumentException("A saved search query is required.", nameof(query));

        var attributes = new Dictionary<string, object>
        {
            ["name"] = name,
            ["search_query"] = query
        };
        if (description is not null) attributes["description"] = description;
        if (isPrivate is not null) attributes["private"] = isPrivate;
        if (tags is not null) attributes["tags"] = tags;

        var response = await _client.PostAsync<SavedSearchObject>("/saved_searches", new
        {
            data = new
            {
                type = "saved_search",
                attributes
            }
        }, cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no saved search.");
    }

    /// <inheritdoc />
    public async Task<SavedSearchObject> GetSavedSearchAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A saved search id is required.", nameof(id));

        var response = await _client.GetAsync<SavedSearchObject>($"/saved_searches/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no saved search.");
    }

    /// <inheritdoc />
    public async Task<VtCollection<SavedSearchObject>> ListSavedSearchesAsync(string? cursor = null, CancellationToken cancellationToken = default)
    {
        var path = "/saved_searches";
        if (cursor is not null)
            path += $"?cursor={Uri.EscapeDataString(cursor)}";

        var response = await _client.GetAsync<List<SavedSearchObject>>(path, cancellationToken).ConfigureAwait(false);
        return VtCollection<SavedSearchObject>.FromEnvelope(response.EnsureSuccess());
    }

    /// <inheritdoc />
    public async Task DeleteSavedSearchAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A saved search id is required.", nameof(id));

        var response = await _client.DeleteAsync<SavedSearchObject>($"/saved_searches/{id}", cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
    }
}
