using System;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Clients;

/// <summary>
/// Retrohunt operations (<c>/intelligence/retrohunt_jobs</c>): run YARA rules against
/// historical intelligence data and inspect the matching files.
/// </summary>
public interface IRetrohuntClient
{
    /// <summary>
    /// Creates a retrohunt job (<c>POST /intelligence/retrohunt_jobs</c>).
    /// </summary>
    /// <param name="rules">YARA rules that define what to look for in the historical corpus.</param>
    /// <param name="notificationEmail">Email address notified when the job finishes.</param>
    /// <param name="corpus">Data set to search; normally <c>main</c>.</param>
    /// <param name="timeRangeStart">Start of the time window to search (Unix timestamp, seconds).</param>
    /// <param name="timeRangeEnd">End of the time window to search (Unix timestamp, seconds).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created retrohunt job; poll its id to track progress.</returns>
    Task<RetrohuntJobObject> CreateJobAsync(string rules, string? notificationEmail = null, string? corpus = "main", int? timeRangeStart = null, int? timeRangeEnd = null, CancellationToken cancellationToken = default);

    /// <summary>Lists retrohunt jobs (<c>GET /intelligence/retrohunt_jobs</c>) with cursor pagination.</summary>
    Task<VtCollection<RetrohuntJobObject>> ListJobsAsync(string? cursor = null, CancellationToken cancellationToken = default);

    /// <summary>Retrieves a retrohunt job by its id (<c>GET /intelligence/retrohunt_jobs/{id}</c>).</summary>
    Task<RetrohuntJobObject> GetJobAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>Aborts a running retrohunt job (<c>DELETE /intelligence/retrohunt_jobs/{id}</c>).</summary>
    Task AbortJobAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>Lists the files matching a retrohunt job (<c>GET /intelligence/retrohunt_jobs/{id}/matching_files</c>).</summary>
    Task<VtCollection<FileObject>> GetMatchingFilesAsync(string id, string? cursor = null, CancellationToken cancellationToken = default);
}

/// <summary><see cref="IRetrohuntClient"/> implementation built on top of <see cref="VtClient"/>.</summary>
public sealed class RetrohuntClient : IRetrohuntClient
{
    private const string JobsPath = "/intelligence/retrohunt_jobs";

    private readonly IVtClient _client;

    /// <summary>Creates a retrohunt client backed by the given <see cref="IVtClient"/>.</summary>
    public RetrohuntClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<RetrohuntJobObject> CreateJobAsync(string rules, string? notificationEmail = null, string? corpus = "main", int? timeRangeStart = null, int? timeRangeEnd = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(rules))
            throw new ArgumentException("YARA rules are required.", nameof(rules));
        if (corpus is not null && corpus is not ("main" or "goodware"))
            throw new ArgumentException("The corpus must be either \"main\" or \"goodware\".", nameof(corpus));

        var response = await _client.PostAsync<RetrohuntJobObject>(JobsPath, new
        {
            data = new
            {
                type = "retrohunt_job",
                attributes = new
                {
                    rules = rules,
                    notificationEmail = notificationEmail,
                    corpus = corpus,
                    timeRange = timeRangeStart is not null || timeRangeEnd is not null
                        ? new { start = timeRangeStart, end = timeRangeEnd }
                        : null
                }
            }
        }, cancellationToken).ConfigureAwait(false);

        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no retrohunt job.");
    }

    /// <inheritdoc />
    public async Task<VtCollection<RetrohuntJobObject>> ListJobsAsync(string? cursor = null, CancellationToken cancellationToken = default)
    {
        var path = JobsPath;
        if (cursor is not null)
            path += $"?cursor={Uri.EscapeDataString(cursor)}";

        var response = await _client.GetAsync<List<RetrohuntJobObject>>(path, cancellationToken).ConfigureAwait(false);
        return VtCollection<RetrohuntJobObject>.FromEnvelope(response.EnsureSuccess());
    }

    /// <inheritdoc />
    public async Task<RetrohuntJobObject> GetJobAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A retrohunt job id is required.", nameof(id));

        var response = await _client.GetAsync<RetrohuntJobObject>($"{JobsPath}/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no retrohunt job.");
    }

    /// <inheritdoc />
    public async Task AbortJobAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A retrohunt job id is required.", nameof(id));

        var response = await _client.DeleteAsync<RetrohuntJobObject>($"{JobsPath}/{id}", cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
    }

    /// <inheritdoc />
    public async Task<VtCollection<FileObject>> GetMatchingFilesAsync(string id, string? cursor = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A retrohunt job id is required.", nameof(id));

        var path = $"{JobsPath}/{id}/matching_files";
        if (cursor is not null)
            path += $"?cursor={Uri.EscapeDataString(cursor)}";

        var response = await _client.GetAsync<List<FileObject>>(path, cancellationToken).ConfigureAwait(false);
        return VtCollection<FileObject>.FromEnvelope(response.EnsureSuccess());
    }
}