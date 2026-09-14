using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Clients;

/// <summary>
/// Well-known collection relationship names used by the element endpoints
/// <c>/{collectionId}/{relationship}</c>.
/// </summary>
public static class CollectionRelationshipName
{
    /// <summary><c>files</c></summary>
    public const string Files = "files";

    /// <summary><c>urls</c></summary>
    public const string Urls = "urls";

    /// <summary><c>domains</c></summary>
    public const string Domains = "domains";

    /// <summary><c>ip_addresses</c></summary>
    public const string IpAddresses = "ip_addresses";

    private static readonly HashSet<string> Known = new(StringComparer.Ordinal)
    {
        Files, Urls, Domains, IpAddresses
    };

    /// <summary>Returns <c>true</c> when <paramref name="relationship"/> is a documented collection element relationship.</summary>
    public static bool IsKnown(string relationship)
        => Known.Contains(relationship);
}

/// <summary>Operations on collections (<c>/collections</c>).</summary>
public interface ICollectionClient
{
    /// <summary>Creates a collection (<c>POST /collections</c>).</summary>
    Task<CollectionObject> CreateCollectionAsync(string name, string? description = null, CancellationToken cancellationToken = default);

    /// <summary>Retrieves a collection (<c>GET /collections/{id}</c>).</summary>
    Task<CollectionObject> GetCollectionAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>Updates a collection (<c>PATCH /collections/{id}</c>).</summary>
    Task<CollectionObject> UpdateCollectionAsync(string id, string? name = null, string? description = null, CancellationToken cancellationToken = default);

    /// <summary>Deletes a collection (<c>DELETE /collections/{id}</c>).</summary>
    Task DeleteCollectionAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Adds elements of one object type to a collection (<c>POST /collections/{id}/{relationship}</c>).
    /// See <see cref="CollectionRelationshipName"/>.
    /// </summary>
    /// <param name="collectionId">Collection id.</param>
    /// <param name="relationship">Element relationship name, e.g. <see cref="CollectionRelationshipName.Files"/>.</param>
    /// <param name="elements">Object descriptors to add.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task AddElementsAsync(string collectionId, string relationship, IEnumerable<VtObjectId> elements, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes elements of one object type from a collection (<c>DELETE /collections/{id}/{relationship}</c>).
    /// See <see cref="CollectionRelationshipName"/>.
    /// </summary>
    /// <param name="collectionId">Collection id.</param>
    /// <param name="relationship">Element relationship name, e.g. <see cref="CollectionRelationshipName.Urls"/>.</param>
    /// <param name="elements">Object descriptors to remove.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task RemoveElementsAsync(string collectionId, string relationship, IEnumerable<VtObjectId> elements, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists the related objects of one relationship of a collection
    /// (<c>GET /collections/{id}/{relationship}</c>) with cursor pagination.
    /// See <see cref="CollectionRelationshipName"/>.
    /// </summary>
    /// <typeparam name="T">Object type of the related resources (e.g. <see cref="FileObject"/>).</typeparam>
    /// <param name="collectionId">Collection id.</param>
    /// <param name="relationship">Element relationship name, e.g. <see cref="CollectionRelationshipName.IpAddresses"/>.</param>
    /// <param name="cursor">Optional pagination cursor for the next page.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<VtCollection<T>> ListElementsAsync<T>(string collectionId, string relationship, string? cursor = null, CancellationToken cancellationToken = default)
        where T : class;
}

/// <summary><see cref="ICollectionClient"/> implementation built on top of <see cref="VtClient"/>.</summary>
public sealed class CollectionClient : ICollectionClient
{
    private readonly IVtClient _client;

    /// <summary>Creates a collection client backed by the given <see cref="IVtClient"/>.</summary>
    public CollectionClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<CollectionObject> CreateCollectionAsync(string name, string? description = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("A collection name is required.", nameof(name));

        var response = await _client.PostAsync<CollectionObject>("/collections", new
        {
            data = new
            {
                type = "collection",
                attributes = new { name, description }
            }
        }, cancellationToken).ConfigureAwait(false);

        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no collection.");
    }

    /// <inheritdoc />
    public async Task<CollectionObject> GetCollectionAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A collection id is required.", nameof(id));

        var response = await _client.GetAsync<CollectionObject>($"/collections/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no collection.");
    }

    /// <inheritdoc />
    public async Task<CollectionObject> UpdateCollectionAsync(string id, string? name = null, string? description = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A collection id is required.", nameof(id));

        var attributes = new Dictionary<string, object>();
        if (name is not null) attributes["name"] = name;
        if (description is not null) attributes["description"] = description;

        if (attributes.Count == 0)
            throw new ArgumentException("At least one field (name or description) must be provided for update.", nameof(name));

        var response = await _client.PatchAsync<CollectionObject>($"/collections/{id}", new
        {
            data = new
            {
                type = "collection",
                id,
                attributes
            }
        }, cancellationToken).ConfigureAwait(false);

        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no collection.");
    }

    /// <inheritdoc />
    public async Task DeleteCollectionAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A collection id is required.", nameof(id));

        var response = await _client.DeleteAsync<CollectionObject>($"/collections/{id}", cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
    }

    /// <inheritdoc />
    public async Task AddElementsAsync(string collectionId, string relationship, IEnumerable<VtObjectId> elements, CancellationToken cancellationToken = default)
    {
        ValidateCollectionAndRelationship(collectionId, relationship);

        var elementList = elements?.ToList() ?? throw new ArgumentNullException(nameof(elements));
        if (elementList.Count == 0)
            throw new ArgumentException("At least one element must be provided.", nameof(elements));

        var response = await _client.PostAsync<CollectionObject>($"/collections/{collectionId}/{relationship}", new
        {
            data = elementList
        }, cancellationToken).ConfigureAwait(false);

        response.EnsureSuccess();
    }

    /// <inheritdoc />
    public async Task RemoveElementsAsync(string collectionId, string relationship, IEnumerable<VtObjectId> elements, CancellationToken cancellationToken = default)
    {
        ValidateCollectionAndRelationship(collectionId, relationship);

        var elementList = elements?.ToList() ?? throw new ArgumentNullException(nameof(elements));
        if (elementList.Count == 0)
            throw new ArgumentException("At least one element must be provided.", nameof(elements));

        var response = await _client.DeleteAsync<CollectionObject>($"/collections/{collectionId}/{relationship}", new
        {
            data = elementList
        }, cancellationToken).ConfigureAwait(false);

        response.EnsureSuccess();
    }

    /// <inheritdoc />
    public async Task<VtCollection<T>> ListElementsAsync<T>(string collectionId, string relationship, string? cursor = null, CancellationToken cancellationToken = default)
        where T : class
    {
        ValidateCollectionAndRelationship(collectionId, relationship);

        var path = $"/collections/{collectionId}/{relationship}";
        if (cursor is not null)
            path += $"?cursor={Uri.EscapeDataString(cursor)}";

        var response = await _client.GetAsync<List<T>>(path, cancellationToken).ConfigureAwait(false);
        return VtCollection<T>.FromEnvelope(response.EnsureSuccess());
    }

    private static void ValidateCollectionAndRelationship(string collectionId, string relationship)
    {
        if (string.IsNullOrWhiteSpace(collectionId))
            throw new ArgumentException("A collection id is required.", nameof(collectionId));
        if (string.IsNullOrWhiteSpace(relationship))
            throw new ArgumentException("A collection relationship is required.", nameof(relationship));
        if (!CollectionRelationshipName.IsKnown(relationship))
            throw new ArgumentException($"Unknown collection relationship \"{relationship}\".", nameof(relationship));
    }
}