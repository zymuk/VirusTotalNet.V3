using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Clients;

/// <summary>Valid group role values used by the group membership management endpoints.</summary>
public static class GroupRoles
{
    /// <summary>Group administrator role (<c>USER_ROLE_GROUP_ADMIN</c>).</summary>
    public const string GroupAdmin = "USER_ROLE_GROUP_ADMIN";

    /// <summary>Grants access to Private Scanning within the group (<c>USER_ROLE_PRIVATE_SCANNING</c>).</summary>
    public const string PrivateScanning = "USER_ROLE_PRIVATE_SCANNING";
}

/// <summary>
/// Operations on users and groups (<c>/users</c> and <c>/groups</c>): retrieve, update and
/// delete accounts, and manage group membership.
/// </summary>
public interface IUsersClient
{
    /// <summary>Retrieves a user by its id (<c>GET /users/{id}</c>).</summary>
    Task<UserObject> GetUserAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>Updates a user (<c>PATCH /users/{id}</c>); only provided fields are changed.</summary>
    Task<UserObject> UpdateUserAsync(string id, string? displayName = null, string? email = null, string? name = null, CancellationToken cancellationToken = default);

    /// <summary>Deletes a user (<c>DELETE /users/{id}</c>).</summary>
    Task DeleteUserAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>Retrieves a group by its id (<c>GET /groups/{id}</c>).</summary>
    Task<GroupObject> GetGroupAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>Updates a group (<c>PATCH /groups/{id}</c>).</summary>
    Task<GroupObject> UpdateGroupAsync(string id, string? name = null, CancellationToken cancellationToken = default);

    /// <summary>Deletes a group (<c>DELETE /groups/{id}</c>).</summary>
    Task DeleteGroupAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>Lists the members of a group (<c>GET /groups/{id}/users</c>) with cursor pagination.</summary>
    Task<VtCollection<UserObject>> ListGroupUsersAsync(string id, string? cursor = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Adds a user to a group (<c>POST /groups/{id}/relationships/users</c>).
    /// </summary>
    /// <param name="groupId">Group id.</param>
    /// <param name="userEmail">Email of the user to add; a username is rejected by the API.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task AddUserToGroupAsync(string groupId, string userEmail, CancellationToken cancellationToken = default);

    /// <summary>
    /// Replaces the roles of a user in a group (<c>PATCH /groups/{id}/relationships/users</c>).
    /// Roles must be one of the <see cref="GroupRoles"/> values.
    /// </summary>
    Task SetGroupUserRolesAsync(string groupId, string userId, IEnumerable<string> roles, CancellationToken cancellationToken = default);

    /// <summary>
    /// Appends new roles to a user in a group (<c>PATCH /groups/{id}/relationships/users</c>);
    /// existing roles are kept. Roles must be one of the <see cref="GroupRoles"/> values.
    /// </summary>
    Task AddGroupUserRolesAsync(string groupId, string userId, IEnumerable<string> roles, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes the given roles from a user in a group (<c>PATCH /groups/{id}/relationships/users</c>).
    /// Roles must be one of the <see cref="GroupRoles"/> values.
    /// </summary>
    Task RemoveGroupUserRolesAsync(string groupId, string userId, IEnumerable<string> roles, CancellationToken cancellationToken = default);

    /// <summary>Removes a user from a group (<c>DELETE /groups/{id}/relationships/users/{userId}</c>).</summary>
    Task RemoveUserFromGroupAsync(string groupId, string userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the API usage of a user broken down by endpoint (<c>GET /users/{id}/api_usage</c>).
    /// </summary>
    /// <param name="id">User id or API key.</param>
    /// <param name="startDate">First day to report, format <c>YYYYMMDD</c>.</param>
    /// <param name="endDate">Last day to report, format <c>YYYYMMDD</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<ApiUsage> GetUserApiUsageAsync(string id, string? startDate = null, string? endDate = null, CancellationToken cancellationToken = default);
}

/// <summary><see cref="IUsersClient"/> implementation built on top of <see cref="VtClient"/>.</summary>
public sealed class UsersClient : IUsersClient
{
    private readonly IVtClient _client;

    /// <summary>Creates a users client backed by the given <see cref="IVtClient"/>.</summary>
    public UsersClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<UserObject> GetUserAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A user id is required.", nameof(id));

        var response = await _client.GetAsync<UserObject>($"/users/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no user.");
    }

    /// <inheritdoc />
    public async Task<UserObject> UpdateUserAsync(string id, string? displayName = null, string? email = null, string? name = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A user id is required.", nameof(id));

        var attributes = new Dictionary<string, object>();
        if (displayName is not null) attributes["display_name"] = displayName;
        if (email is not null) attributes["email"] = email;
        if (name is not null) attributes["name"] = name;

        if (attributes.Count == 0)
            throw new ArgumentException("At least one field must be provided for update.", nameof(displayName));

        var response = await _client.PatchAsync<UserObject>($"/users/{id}", new
        {
            data = new
            {
                type = "user",
                id,
                attributes
            }
        }, cancellationToken).ConfigureAwait(false);

        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no user.");
    }

    /// <inheritdoc />
    public async Task DeleteUserAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A user id is required.", nameof(id));

        var response = await _client.DeleteAsync<UserObject>($"/users/{id}", cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
    }

    /// <inheritdoc />
    public async Task<GroupObject> GetGroupAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A group id is required.", nameof(id));

        var response = await _client.GetAsync<GroupObject>($"/groups/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no group.");
    }

    /// <inheritdoc />
    public async Task<GroupObject> UpdateGroupAsync(string id, string? name = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A group id is required.", nameof(id));
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("A group name is required.", nameof(name));

        var response = await _client.PatchAsync<GroupObject>($"/groups/{id}", new
        {
            data = new
            {
                type = "group",
                id,
                attributes = new { name }
            }
        }, cancellationToken).ConfigureAwait(false);

        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no group.");
    }

    /// <inheritdoc />
    public async Task DeleteGroupAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A group id is required.", nameof(id));

        var response = await _client.DeleteAsync<GroupObject>($"/groups/{id}", cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
    }

    /// <inheritdoc />
    public async Task<VtCollection<UserObject>> ListGroupUsersAsync(string id, string? cursor = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A group id is required.", nameof(id));

        var path = $"/groups/{id}/users";
        if (cursor is not null)
            path += $"?cursor={Uri.EscapeDataString(cursor)}";

        var response = await _client.GetAsync<List<UserObject>>(path, cancellationToken).ConfigureAwait(false);
        return VtCollection<UserObject>.FromEnvelope(response.EnsureSuccess());
    }

    /// <inheritdoc />
    public Task AddUserToGroupAsync(string groupId, string userEmail, CancellationToken cancellationToken = default)
        => AddUsersToGroupAsync(groupId, new[] { userEmail }, cancellationToken);

    private async Task AddUsersToGroupAsync(string groupId, IReadOnlyCollection<string> userEmails, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(groupId))
            throw new ArgumentException("A group id is required.", nameof(groupId));
        if (userEmails is null || userEmails.Count == 0 || userEmails.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException("At least one user email is required.", nameof(userEmails));

        var members = userEmails.Select(email => new { type = "user", id = email }).ToArray();
        var response = await _client.PostAsync<JsonElement>($"/groups/{groupId}/relationships/users", new { data = members }, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
    }

    /// <inheritdoc />
    public Task SetGroupUserRolesAsync(string groupId, string userId, IEnumerable<string> roles, CancellationToken cancellationToken = default)
        => PatchGroupUserRolesAsync(groupId, userId, "roles", roles, cancellationToken);

    /// <inheritdoc />
    public Task AddGroupUserRolesAsync(string groupId, string userId, IEnumerable<string> roles, CancellationToken cancellationToken = default)
        => PatchGroupUserRolesAsync(groupId, userId, "add_roles", roles, cancellationToken);

    /// <inheritdoc />
    public Task RemoveGroupUserRolesAsync(string groupId, string userId, IEnumerable<string> roles, CancellationToken cancellationToken = default)
        => PatchGroupUserRolesAsync(groupId, userId, "remove_roles", roles, cancellationToken);

    private async Task PatchGroupUserRolesAsync(string groupId, string userId, string operation, IEnumerable<string> roles, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(groupId))
            throw new ArgumentException("A group id is required.", nameof(groupId));
        if (string.IsNullOrWhiteSpace(userId))
            throw new ArgumentException("A user id is required.", nameof(userId));
        if (roles is null)
            throw new ArgumentNullException(nameof(roles));

        var roleList = roles.ToList();
        if (roleList.Count == 0)
            throw new ArgumentException("At least one role is required.", nameof(roles));
        foreach (var role in roleList)
        {
            if (role is not (GroupRoles.GroupAdmin or GroupRoles.PrivateScanning))
                throw new ArgumentException($"The role \"{role}\" is not valid. Allowed roles: {GroupRoles.GroupAdmin}, {GroupRoles.PrivateScanning}.", nameof(roles));
        }

        var body = new
        {
            data = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["type"] = "user",
                    ["id"] = userId,
                    ["context_attributes"] = new Dictionary<string, object?> { [operation] = roleList }
                }
            }
        };

        var response = await _client.PatchAsync<JsonElement>($"/groups/{groupId}/relationships/users", body, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
    }

    /// <inheritdoc />
    public async Task RemoveUserFromGroupAsync(string groupId, string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(groupId))
            throw new ArgumentException("A group id is required.", nameof(groupId));
        if (string.IsNullOrWhiteSpace(userId))
            throw new ArgumentException("A user id is required.", nameof(userId));

        var response = await _client.DeleteAsync<JsonElement>($"/groups/{groupId}/relationships/users/{userId}", cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
    }

    /// <inheritdoc />
    public async Task<ApiUsage> GetUserApiUsageAsync(string id, string? startDate = null, string? endDate = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A user id is required.", nameof(id));

        var path = $"/users/{id}/api_usage";
        var separator = "?";
        if (startDate is not null)
        {
            path += separator + "start_date=" + Uri.EscapeDataString(startDate);
            separator = "&";
        }
        if (endDate is not null)
        {
            path += separator + "end_date=" + Uri.EscapeDataString(endDate);
            separator = "&";
        }

        return await _client.GetRawAsync<ApiUsage>(path, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("The API returned no usage data.");
    }
}