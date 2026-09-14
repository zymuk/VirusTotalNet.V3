using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Clients;

/// <summary>Operations on graphs (<c>/graphs</c>).</summary>
public interface IGraphClient
{
    /// <summary>
    /// Creates a graph (<c>POST /graphs</c>). At least one of <paramref name="graphData"/>,
    /// <paramref name="nodes"/> or <paramref name="links"/> must be provided.
    /// </summary>
    /// <param name="graphData">Optional graph data payload (name/description and version).</param>
    /// <param name="nodes">Optional list of graph nodes.</param>
    /// <param name="links">Optional list of links between nodes.</param>
    /// <param name="isPrivate">When <c>true</c>, the graph counts against the private graph quota.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<GraphObject> CreateGraphAsync(GraphData? graphData = null, IReadOnlyList<GraphNode>? nodes = null, IReadOnlyList<GraphLink>? links = null, bool? isPrivate = null, CancellationToken cancellationToken = default);

    /// <summary>Retrieves a graph (<c>GET /graphs/{id}</c>).</summary>
    Task<GraphObject> GetGraphAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates a graph (<c>PATCH /graphs/{id}</c>). At least one parameter must be provided.
    /// </summary>
    /// <param name="id">Graph id (65-character hex string).</param>
    /// <param name="graphData">Updated graph data payload (name/description and version).</param>
    /// <param name="nodes">Updated node list (replaces the whole list when provided).</param>
    /// <param name="links">Updated link list (replaces the whole list when provided).</param>
    /// <param name="isPrivate">Updated private status.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<GraphObject> UpdateGraphAsync(string id, GraphData? graphData = null, IReadOnlyList<GraphNode>? nodes = null, IReadOnlyList<GraphLink>? links = null, bool? isPrivate = null, CancellationToken cancellationToken = default);

    /// <summary>Deletes a graph (<c>DELETE /graphs/{id}</c>).</summary>
    Task DeleteGraphAsync(string id, CancellationToken cancellationToken = default);
}

/// <summary><see cref="IGraphClient"/> implementation built on top of <see cref="VtClient"/>.</summary>
public sealed class GraphClient : IGraphClient
{
    private readonly IVtClient _client;

    /// <summary>Creates a graph client backed by the given <see cref="IVtClient"/>.</summary>
    public GraphClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<GraphObject> CreateGraphAsync(GraphData? graphData = null, IReadOnlyList<GraphNode>? nodes = null, IReadOnlyList<GraphLink>? links = null, bool? isPrivate = null, CancellationToken cancellationToken = default)
    {
        if (graphData is null && nodes is null && links is null)
            throw new ArgumentException("A graph must contain at least graph data, nodes or links.", nameof(graphData));

        var attributes = BuildAttributes(graphData, nodes, links, isPrivate);
        var response = await _client.PostAsync<GraphObject>("/graphs", new { data = new { type = "graph", attributes } }, cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no graph.");
    }

    /// <inheritdoc />
    public async Task<GraphObject> GetGraphAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A graph id is required.", nameof(id));

        var response = await _client.GetAsync<GraphObject>($"/graphs/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no graph.");
    }

    /// <inheritdoc />
    public async Task<GraphObject> UpdateGraphAsync(string id, GraphData? graphData = null, IReadOnlyList<GraphNode>? nodes = null, IReadOnlyList<GraphLink>? links = null, bool? isPrivate = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A graph id is required.", nameof(id));
        if (graphData is null && nodes is null && links is null && isPrivate is null)
            throw new ArgumentException("At least one graph field must be provided for update.", nameof(graphData));

        var attributes = BuildAttributes(graphData, nodes, links, isPrivate);
        var response = await _client.PatchAsync<GraphObject>($"/graphs/{id}", new { data = new { type = "graph", id, attributes } }, cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no graph.");
    }

    /// <inheritdoc />
    public async Task DeleteGraphAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A graph id is required.", nameof(id));

        var response = await _client.DeleteAsync<GraphObject>($"/graphs/{id}", cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
    }

    private static Dictionary<string, object> BuildAttributes(GraphData? graphData, IReadOnlyList<GraphNode>? nodes, IReadOnlyList<GraphLink>? links, bool? isPrivate)
    {
        var attributes = new Dictionary<string, object>();
        if (graphData is not null) attributes["graph_data"] = graphData;
        if (nodes is not null) attributes["nodes"] = nodes;
        if (links is not null) attributes["links"] = links;
        if (isPrivate is not null) attributes["private"] = isPrivate;
        return attributes;
    }
}