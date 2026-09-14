using System;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Clients;

/// <summary>
/// Private scanning endpoints (<c>/private/files</c>). Only available to users and groups
/// with a Private Scanning license. Private samples are never shared with the community.
/// </summary>
public interface IPrivateScanningClient
{
    /// <summary>
    /// Uploads a file to the private scanning environment (<c>POST /private/files</c>) and starts an analysis.
    /// </summary>
    /// <param name="file">The file content to scan; the stream is not disposed by this method.</param>
    /// <param name="disableSandbox">When <c>true</c>, custom dynamic analysis is disabled and only static analysis is run.</param>
    /// <param name="enableInternet">When <c>true</c>, the sample is allowed network access during dynamic analysis.</param>
    /// <param name="interceptTls">When <c>true</c>, TLS traffic produced by the sample is intercepted and analysed.</param>
    /// <param name="commandLine">Command line arguments to pass to the sample during dynamic analysis.</param>
    /// <param name="password">Password to use when the sample is a password-protected archive.</param>
    /// <param name="retentionPeriodDays">Number of days the sample is retained before being deleted.</param>
    /// <param name="storageRegion">Storage region for the sample, e.g. <c>EU</c> or <c>US</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created analysis object; poll its id to retrieve the completed report.</returns>
    Task<AnalysisObject> UploadPrivateFileAsync(Stream file, bool? disableSandbox = null, bool? enableInternet = null, bool? interceptTls = null, string? commandLine = null, string? password = null, int? retentionPeriodDays = null, string? storageRegion = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a pre-signed URL that can be used to upload a private file (<c>GET /private/files/upload_url</c>).
    /// </summary>
    Task<string> GetPrivateFileUploadUrlAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists private files uploaded by the current user (<c>GET /private/files</c>) with cursor pagination.
    /// </summary>
    Task<VtCollection<PrivateFileObject>> ListPrivateFilesAsync(string? cursor = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a private file by its id (<c>GET /private/files/{id}</c>).
    /// </summary>
    Task<PrivateFileObject> GetPrivateFileAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a private file (<c>DELETE /private/files/{id}</c>).
    /// </summary>
    Task DeletePrivateFileAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Starts a new analysis of an already uploaded private file (<c>POST /private/files/{id}/analyse</c>).
    /// </summary>
    Task<AnalysisObject> AnalysePrivateFileAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a private analysis by its id (<c>GET /private/analyses/{id}</c>).
    /// </summary>
    Task<AnalysisObject> GetPrivateAnalysisAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the behaviour reports of a private file (<c>GET /private/files/{id}/behaviours</c>).
    /// </summary>
    Task<VtCollection<BehaviourObject>> GetPrivateFileBehavioursAsync(string id, CancellationToken cancellationToken = default);
}

/// <summary><see cref="IPrivateScanningClient"/> implementation built on top of <see cref="VtClient"/>.</summary>
public sealed class PrivateScanningClient : IPrivateScanningClient
{
    private readonly IVtClient _client;

    /// <summary>Creates a private-scanning client backed by the given <see cref="IVtClient"/>.</summary>
    public PrivateScanningClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<AnalysisObject> UploadPrivateFileAsync(Stream file, bool? disableSandbox = null, bool? enableInternet = null, bool? interceptTls = null, string? commandLine = null, string? password = null, int? retentionPeriodDays = null, string? storageRegion = null, CancellationToken cancellationToken = default)
    {
        if (file is null)
            throw new ArgumentNullException(nameof(file));

        using var content = BuildMultipartContent(file, disableSandbox, enableInternet, interceptTls, commandLine, password, retentionPeriodDays, storageRegion);

        var response = await _client.PostAsync<AnalysisObject>("/private/files", content, cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no analysis.");
    }

    private static MultipartFormDataContent BuildMultipartContent(Stream file, bool? disableSandbox, bool? enableInternet, bool? interceptTls, string? commandLine, string? password, int? retentionPeriodDays, string? storageRegion)
    {
        var content = new MultipartFormDataContent();

        var fileContent = new StreamContent(file);
        fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "file", "file");

        if (disableSandbox is not null)
            content.Add(new StringContent(disableSandbox.Value ? "true" : "false"), "disable_sandbox");
        if (enableInternet is not null)
            content.Add(new StringContent(enableInternet.Value ? "true" : "false"), "enable_internet");
        if (interceptTls is not null)
            content.Add(new StringContent(interceptTls.Value ? "true" : "false"), "intercept_tls");
        if (!string.IsNullOrWhiteSpace(commandLine))
            content.Add(new StringContent(commandLine), "command_line");
        if (!string.IsNullOrWhiteSpace(password))
            content.Add(new StringContent(password), "password");
        if (retentionPeriodDays is not null)
            content.Add(new StringContent(retentionPeriodDays.Value.ToString(CultureInfo.InvariantCulture)), "retention_period_days");
        if (!string.IsNullOrWhiteSpace(storageRegion))
            content.Add(new StringContent(storageRegion), "storage_region");

        return content;
    }

    /// <inheritdoc />
    public async Task<string> GetPrivateFileUploadUrlAsync(CancellationToken cancellationToken = default)
    {
        var url = await _client.GetRawAsync<string>("/private/files/upload_url", cancellationToken).ConfigureAwait(false);
        return url ?? throw new InvalidOperationException("The API returned no upload URL.");
    }

    /// <inheritdoc />
    public async Task<VtCollection<PrivateFileObject>> ListPrivateFilesAsync(string? cursor = null, CancellationToken cancellationToken = default)
    {
        var path = "/private/files";
        if (cursor is not null)
            path += $"?cursor={Uri.EscapeDataString(cursor)}";

        var response = await _client.GetAsync<List<PrivateFileObject>>(path, cancellationToken).ConfigureAwait(false);
        return VtCollection<PrivateFileObject>.FromEnvelope(response.EnsureSuccess());
    }

    /// <inheritdoc />
    public async Task<PrivateFileObject> GetPrivateFileAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A private file id is required.", nameof(id));

        var response = await _client.GetAsync<PrivateFileObject>($"/private/files/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no private file.");
    }

    /// <inheritdoc />
    public async Task DeletePrivateFileAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A private file id is required.", nameof(id));

        var response = await _client.DeleteAsync<PrivateFileObject>($"/private/files/{id}", cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
    }

    /// <inheritdoc />
    public async Task<AnalysisObject> AnalysePrivateFileAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A private file id is required.", nameof(id));

        var response = await _client.PostAsync<AnalysisObject>($"/private/files/{id}/analyse", new { }, cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no analysis.");
    }

    /// <inheritdoc />
    public async Task<AnalysisObject> GetPrivateAnalysisAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("An analysis id is required.", nameof(id));

        var response = await _client.GetAsync<AnalysisObject>($"/private/analyses/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no analysis.");
    }

    /// <inheritdoc />
    public async Task<VtCollection<BehaviourObject>> GetPrivateFileBehavioursAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A private file id is required.", nameof(id));

        var response = await _client.GetAsync<List<BehaviourObject>>($"/private/files/{id}/behaviours", cancellationToken).ConfigureAwait(false);
        return VtCollection<BehaviourObject>.FromEnvelope(response.EnsureSuccess());
    }
}