using System.IO;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Clients;

/// <summary>
/// Operations on <c>file</c> resources: scan a sample via multipart upload, retrieve reports,
/// rescan, and download.
/// </summary>
public interface IFileClient
{
    /// <summary>
    /// Uploads a file directly to VirusTotal and starts an analysis (<c>POST /files</c>).
    /// The file must not exceed <see cref="FileClient.MaxScanSize"/> bytes.
    /// </summary>
    /// <param name="stream">The file content to scan.</param>
    /// <param name="fileName">Name sent to the API; often used to infer the file type.</param>
    /// <param name="password">Optional password for password-protected ZIP files.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created analysis object; poll its id to retrieve the completed report.</returns>
    Task<AnalysisObject> ScanFileAsync(Stream stream, string? fileName = null, string? password = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Uploads a file larger than <see cref="FileClient.MaxScanSize"/> using a pre-signed upload URL:
    /// fetches <c>GET /files/upload_url</c> then multipart-POSTs the file to that URL.
    /// </summary>
    /// <param name="stream">The file content to scan (typically larger than 32 MiB).</param>
    /// <param name="fileName">Name sent to the API; often used to infer the file type.</param>
    /// <param name="password">Optional password for password-protected ZIP files.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created analysis object; poll its id to retrieve the completed report.</returns>
    Task<AnalysisObject> ScanLargeFileAsync(Stream stream, string? fileName = null, string? password = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the report of a file identified by its MD5, SHA-1 or SHA-256 digest (<c>GET /files/{id}</c>).
    /// </summary>
    /// <param name="id">MD5, SHA-1 or SHA-256 digest of the file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The file object with its attributes and detection statistics.</returns>
    Task<FileObject> GetFileAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Rescans a file already present on VirusTotal (<c>POST /files/{id}/analyse</c>).
    /// </summary>
    /// <param name="id">MD5, SHA-1 or SHA-256 digest of the file to rescan.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The newly created analysis object.</returns>
    Task<AnalysisObject> AnalyseFileAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Downloads the content of a known file (<c>GET /files/{id}/download</c>; redirects are followed).
    /// </summary>
    /// <param name="id">MD5, SHA-1 or SHA-256 digest of the file to download.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A stream with the raw file bytes; the caller must dispose it.</returns>
    Task<System.IO.Stream> DownloadAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a pre-signed URL that can be used to download the file (<c>GET /files/{id}/download_url</c>).
    /// </summary>
    /// <param name="id">MD5, SHA-1 or SHA-256 digest of the file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The pre-signed download URL.</returns>
    Task<string> GetDownloadUrlAsync(string id, CancellationToken cancellationToken = default);
}

/// <summary>
/// <see cref="IFileClient"/> implementation built on top of <see cref="VtClient"/>.
/// </summary>
public sealed class FileClient : IFileClient
{
    /// <summary>Maximum size in bytes of a file accepted by direct upload (32 MiB).</summary>
    public const long MaxScanSize = 32 * 1024 * 1024;

    private readonly IVtClient _client;

    /// <summary>Creates a file client backed by the given <see cref="IVtClient"/>.</summary>
    public FileClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<AnalysisObject> ScanFileAsync(Stream stream, string? fileName = null, string? password = null, CancellationToken cancellationToken = default)
    {
        if (stream is null)
            throw new ArgumentNullException(nameof(stream));

        if (stream.CanSeek && stream.Length > MaxScanSize)
            throw new ArgumentOutOfRangeException(nameof(stream), $"Files larger than {MaxScanSize} bytes cannot be uploaded directly; use {nameof(ScanLargeFileAsync)} instead.");

        using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer).ConfigureAwait(false);
        var bytes = buffer.ToArray();

        // The multipart body is rebuilt on every attempt: the transport disposes HttpContent after
        // the first send, and VirusTotal answers POST /files with an HTTP 307 that HttpClient
        // re-serializes, so a single reusable StreamContent would be exhausted/disposed mid-flight.
        var response = await _client.PostAsync<AnalysisObject>(
            "/files",
            () => BuildMultipartContent(bytes, fileName, password),
            cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? new AnalysisObject();
    }

    /// <inheritdoc />
    public async Task<AnalysisObject> ScanLargeFileAsync(Stream stream, string? fileName = null, string? password = null, CancellationToken cancellationToken = default)
    {
        if (stream is null)
            throw new ArgumentNullException(nameof(stream));

        var uploadUrlResponse = await _client.GetAsync<string>("/files/upload_url", cancellationToken).ConfigureAwait(false);
        var uploadUrl = uploadUrlResponse.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no upload URL.");

        var response = await _client.PostAsync<AnalysisObject>(
            uploadUrl,
            () =>
            {
                if (stream.CanSeek)
                    stream.Position = 0;
                return BuildMultipartContent(stream, fileName, password);
            },
            cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? new AnalysisObject();
    }

    private static MultipartFormDataContent BuildMultipartContent(byte[] bytes, string? fileName, string? password)
    {
        var content = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "file", fileName ?? "file");
        if (!string.IsNullOrEmpty(password))
            content.Add(new StringContent(password), "password");
        return content;
    }

    private static MultipartFormDataContent BuildMultipartContent(Stream stream, string? fileName, string? password)
    {
        var content = new MultipartFormDataContent();
        var fileContent = new StreamContent(stream);
        fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "file", fileName ?? "file");
        if (!string.IsNullOrEmpty(password))
            content.Add(new StringContent(password), "password");
        return content;
    }

    /// <inheritdoc />
    public async Task<FileObject> GetFileAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A file digest is required.", nameof(id));

        var response = await _client.GetAsync<FileObject>($"/files/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? new FileObject();
    }

    /// <inheritdoc />
    public async Task<AnalysisObject> AnalyseFileAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A file digest is required.", nameof(id));

        var response = await _client.PostAsync<AnalysisObject>($"/files/{id}/analyse", new { }, cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? new AnalysisObject();
    }

    /// <inheritdoc />
    public async Task<System.IO.Stream> DownloadAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A file digest is required.", nameof(id));

        return await _client.GetStreamAsync($"/files/{id}/download", cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<string> GetDownloadUrlAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A file digest is required.", nameof(id));

        var response = await _client.GetAsync<string>($"/files/{id}/download_url", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no download URL.");
    }
}