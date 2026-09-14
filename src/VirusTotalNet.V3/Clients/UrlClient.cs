using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Clients;

/// <summary>
/// Operations on <c>url</c> resources: scan, retrieve, and rescan.
/// </summary>
public interface IUrlClient
{
    /// <summary>
    /// Starts an analysis of a URL (<c>POST /urls</c>).
    /// </summary>
    /// <param name="url">The URL to analyse.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created analysis object.</returns>
    Task<AnalysisObject> ScanUrlAsync(string url, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the object of a URL (<c>GET /urls/{id}</c>). Accepts either the URL itself
    /// (automatically encoded to its base64url id) or an already-encoded id.
    /// </summary>
    /// <param name="urlOrId">The URL (e.g. <c>https://example.com/</c>) or a base64url-encoded URL id.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The URL object with its attributes.</returns>
    Task<UrlObject> GetUrlAsync(string urlOrId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Rescans a URL (<c>POST /urls/{id}/analyse</c>).
    /// </summary>
    /// <param name="urlOrId">The URL or a base64url-encoded URL id.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The newly created analysis object.</returns>
    Task<AnalysisObject> AnalyseUrlAsync(string urlOrId, CancellationToken cancellationToken = default);
}

/// <summary>
/// <see cref="IUrlClient"/> implementation built on top of <see cref="VtClient"/>.
/// </summary>
public sealed class UrlClient : IUrlClient
{
    private readonly IVtClient _client;

    /// <summary>Creates a URL client backed by the given <see cref="IVtClient"/>.</summary>
    public UrlClient(IVtClient client) => _client = client;

    /// <summary>
    /// Encodes a URL to its VirusTotal base64url identifier (no padding), e.g.
    /// <c>https://example.com/</c> → <c>aHR0cHM6Ly9leGFtcGxlLmNvbS8</c>.
    /// </summary>
    public static string EncodeUrlId(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
            throw new ArgumentException("A URL is required.", nameof(url));

        return Convert.ToBase64String(Encoding.UTF8.GetBytes(url))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    /// <inheritdoc />
    public async Task<AnalysisObject> ScanUrlAsync(string url, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(url))
            throw new ArgumentException("A URL is required.", nameof(url));

        var response = await _client.PostAsync<AnalysisObject>(
            "/urls",
            () => new System.Net.Http.FormUrlEncodedContent(
                new[] { new KeyValuePair<string, string>("url", url) }),
            cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? new AnalysisObject();
    }

    /// <inheritdoc />
    public async Task<UrlObject> GetUrlAsync(string urlOrId, CancellationToken cancellationToken = default)
    {
        var id = ResolveId(urlOrId);
        var response = await _client.GetAsync<UrlObject>($"/urls/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? new UrlObject();
    }

    /// <inheritdoc />
    public async Task<AnalysisObject> AnalyseUrlAsync(string urlOrId, CancellationToken cancellationToken = default)
    {
        var id = ResolveId(urlOrId);
        var response = await _client.PostAsync<AnalysisObject>($"/urls/{id}/analyse", new { }, cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? new AnalysisObject();
    }

    private static string ResolveId(string urlOrId)
    {
        if (string.IsNullOrWhiteSpace(urlOrId))
            throw new ArgumentException("A URL or URL id is required.", nameof(urlOrId));

        var trimmed = urlOrId.Trim();
        if (trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return EncodeUrlId(trimmed);

        return trimmed;
    }
}