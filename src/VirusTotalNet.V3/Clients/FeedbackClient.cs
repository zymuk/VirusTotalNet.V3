using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Clients;

/// <summary>
/// Comments and votes on any object type (files, URLs, domains, IP addresses).
/// </summary>
public interface IFeedbackClient
{
    /// <summary>
    /// Lists the comments of an object (<c>GET /{objectType}/{id}/comments</c>).
    /// </summary>
    /// <param name="objectType">Object type path segment, see <see cref="VtObjectType"/>.</param>
    /// <param name="id">Object id (for URLs, the base64url-encoded id).</param>
    /// <param name="cursor">Optional pagination cursor for the next page.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<VtCollection<CommentObject>> GetCommentsAsync(string objectType, string id, string? cursor = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Adds a comment to an object (<c>POST /{objectType}/{id}/comments</c>).
    /// </summary>
    /// <param name="objectType">Object type path segment, see <see cref="VtObjectType"/>.</param>
    /// <param name="id">Object id.</param>
    /// <param name="text">The comment text (markdown).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created comment object.</returns>
    Task<CommentObject> AddCommentAsync(string objectType, string id, string text, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists the votes of an object (<c>GET /{objectType}/{id}/votes</c>).
    /// </summary>
    /// <param name="objectType">Object type path segment, see <see cref="VtObjectType"/>.</param>
    /// <param name="id">Object id.</param>
    /// <param name="cursor">Optional pagination cursor for the next page.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<VtCollection<VoteObject>> GetVotesAsync(string objectType, string id, string? cursor = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Casts a vote on an object (<c>POST /{objectType}/{id}/votes</c>).
    /// </summary>
    /// <param name="objectType">Object type path segment, see <see cref="VtObjectType"/>.</param>
    /// <param name="id">Object id.</param>
    /// <param name="verdict">The verdict, e.g. <c>malicious</c> or <c>harmless</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created vote object.</returns>
    Task<VoteObject> AddVoteAsync(string objectType, string id, string verdict, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists the most recent comments across the community (<c>GET /comments</c>).
    /// </summary>
    /// <param name="filter">Optional filter expression, e.g. <c>attributes.date:2020-04-01T00:00:00Z</c>.</param>
    /// <param name="limit">Optional maximum number of comments to return.</param>
    /// <param name="cursor">Optional pagination cursor for the next page.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<VtCollection<CommentObject>> ListLatestCommentsAsync(string? filter = null, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a single comment object (<c>GET /comments/{id}</c>).
    /// </summary>
    /// <param name="commentId">Comment id (see the <c>d|f|g|i|u</c> id prefixes from the API docs).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<CommentObject> GetCommentAsync(string commentId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a comment (<c>DELETE /comments/{id}</c>). Only the author can delete it.
    /// </summary>
    /// <param name="commentId">Comment id.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task DeleteCommentAsync(string commentId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Casts a vote on a comment (<c>POST /comments/{id}/vote</c>).
    /// </summary>
    /// <param name="commentId">Comment id.</param>
    /// <param name="vote">The vote category (positive, negative or abuse).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task VoteCommentAsync(string commentId, CommentVoteKind vote, CancellationToken cancellationToken = default);
}

/// <summary>
/// <see cref="IFeedbackClient"/> implementation built on top of <see cref="VtClient"/>.
/// </summary>
public sealed class FeedbackClient : IFeedbackClient
{
    private readonly IVtClient _client;

    /// <summary>Creates a feedback (comments/votes) client backed by the given <see cref="IVtClient"/>.</summary>
    public FeedbackClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<VtCollection<CommentObject>> GetCommentsAsync(string objectType, string id, string? cursor = null, CancellationToken cancellationToken = default)
    {
        var path = ValidatePath(objectType, id);
        var response = await _client.GetAsync<List<CommentObject>>(Paginate(path + "/comments", cursor), cancellationToken).ConfigureAwait(false);
        return VtCollection<CommentObject>.FromEnvelope(response.EnsureSuccess());
    }

    /// <inheritdoc />
    public async Task<CommentObject> AddCommentAsync(string objectType, string id, string text, CancellationToken cancellationToken = default)
    {
        var path = ValidatePath(objectType, id);
        if (string.IsNullOrWhiteSpace(text))
            throw new ArgumentException("Comment text is required.", nameof(text));

        var body = new { data = new { type = "comment", attributes = new { text } } };
        var response = await _client.PostAsync<CommentObject>(path + "/comments", body, cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? new CommentObject();
    }

    /// <inheritdoc />
    public async Task<VtCollection<VoteObject>> GetVotesAsync(string objectType, string id, string? cursor = null, CancellationToken cancellationToken = default)
    {
        var path = ValidatePath(objectType, id);
        var response = await _client.GetAsync<List<VoteObject>>(Paginate(path + "/votes", cursor), cancellationToken).ConfigureAwait(false);
        return VtCollection<VoteObject>.FromEnvelope(response.EnsureSuccess());
    }

    /// <inheritdoc />
    public async Task<VoteObject> AddVoteAsync(string objectType, string id, string verdict, CancellationToken cancellationToken = default)
    {
        var path = ValidatePath(objectType, id);
        if (!IsValidVerdict(verdict))
            throw new ArgumentException("The verdict must be either \"harmless\" or \"malicious\".", nameof(verdict));

        var body = new { data = new { type = "vote", attributes = new { verdict } } };
        var response = await _client.PostAsync<VoteObject>(path + "/votes", body, cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? new VoteObject();
    }

    /// <inheritdoc />
    public async Task<VtCollection<CommentObject>> ListLatestCommentsAsync(string? filter = null, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default)
    {
        if (limit is < 1)
            throw new ArgumentOutOfRangeException(nameof(limit), "The limit must be at least 1.");

        var parameters = new List<string>();
        if (filter is not null && filter.Trim().Length > 0)
            parameters.Add($"filter={Uri.EscapeDataString(filter.Trim())}");
        if (limit is not null)
            parameters.Add($"limit={limit}");
        if (cursor is not null && cursor.Trim().Length > 0)
            parameters.Add($"cursor={Uri.EscapeDataString(cursor)}");

        var path = parameters.Count == 0 ? "/comments" : "/comments?" + string.Join("&", parameters);

        var response = await _client.GetAsync<List<CommentObject>>(path, cancellationToken).ConfigureAwait(false);
        return VtCollection<CommentObject>.FromEnvelope(response.EnsureSuccess());
    }

    /// <inheritdoc />
    public async Task<CommentObject> GetCommentAsync(string commentId, CancellationToken cancellationToken = default)
    {
        var id = ValidateCommentId(commentId);

        var response = await _client.GetAsync<CommentObject>($"/comments/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? new CommentObject();
    }

    /// <inheritdoc />
    public async Task DeleteCommentAsync(string commentId, CancellationToken cancellationToken = default)
    {
        var id = ValidateCommentId(commentId);

        var response = await _client.DeleteAsync<CommentObject>($"/comments/{id}", cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
    }

    /// <inheritdoc />
    public async Task VoteCommentAsync(string commentId, CommentVoteKind vote, CancellationToken cancellationToken = default)
    {
        var id = ValidateCommentId(commentId);

        var body = new
        {
            data = new
            {
                abuse = vote == CommentVoteKind.Abuse ? 1 : 0,
                negative = vote == CommentVoteKind.Negative ? 1 : 0,
                positive = vote == CommentVoteKind.Positive ? 1 : 0
            }
        };

        var response = await _client.PostAsync<CommentObject>($"/comments/{id}/vote", body, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
    }

    private static string ValidateCommentId(string commentId)
    {
        if (string.IsNullOrWhiteSpace(commentId))
            throw new ArgumentException("A comment id is required.", nameof(commentId));
        return commentId.Trim();
    }

    private static string ValidatePath(string objectType, string id)
    {
        if (string.IsNullOrWhiteSpace(objectType))
            throw new ArgumentException("An object type is required.", nameof(objectType));
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("An object id is required.", nameof(id));

        return $"/{objectType.Trim()}/{id.Trim()}";
    }

    private static string Paginate(string path, string? cursor)
        => string.IsNullOrEmpty(cursor) ? path : $"{path}?cursor={Uri.EscapeDataString(cursor)}";

    private static bool IsValidVerdict(string? verdict)
        => verdict is "harmless" or "malicious";
}