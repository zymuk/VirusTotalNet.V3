using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.V3.Core;

namespace VirusTotalNet.V3.Clients;

/// <summary>
/// VirusTotal Intelligence feeds: minutely batches of recently-seen files, URLs, domains, IP
/// addresses and file behaviours. Each batch is a bzip2-compressed NDJSON stream.
/// Requires a feed license.
/// </summary>
public interface IFeedsClient
{
    /// <summary>
    /// Downloads a per-minute file feed batch.
    /// The returned stream is bzip2-compressed NDJSON (one <c>FileObject</c> JSON per line).
    /// The caller is responsible for decompression and disposal.
    /// </summary>
    /// <param name="time">Batch time in <c>YYYYMMDDhhmm</c> UTC format (e.g. <c>202609111200</c>).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A bzip2-compressed stream of file objects.</returns>
    Task<Stream> GetFileFeedStreamAsync(string time, CancellationToken cancellationToken = default);

    /// <summary>
    /// Downloads a per-minute URL feed batch.
    /// The returned stream is bzip2-compressed NDJSON (one <c>UrlObject</c> JSON per line).
    /// </summary>
    Task<Stream> GetUrlFeedStreamAsync(string time, CancellationToken cancellationToken = default);

    /// <summary>
    /// Downloads a per-minute domain feed batch.
    /// The returned stream is bzip2-compressed NDJSON (one <c>DomainObject</c> JSON per line).
    /// </summary>
    Task<Stream> GetDomainFeedStreamAsync(string time, CancellationToken cancellationToken = default);

    /// <summary>
    /// Downloads a per-minute IP address feed batch.
    /// The returned stream is bzip2-compressed NDJSON (one <c>IpObject</c> JSON per line).
    /// </summary>
    Task<Stream> GetIpFeedStreamAsync(string time, CancellationToken cancellationToken = default);

    /// <summary>
    /// Downloads a per-minute file behaviour feed batch.
    /// The returned stream is bzip2-compressed NDJSON (one <c>FileBehaviourObject</c> JSON per line).
    /// </summary>
    Task<Stream> GetFileBehaviourFeedStreamAsync(string time, CancellationToken cancellationToken = default);

    /// <summary>
    /// Downloads an hourly file feed package (.tar.bz2 containing 60 per-minute batches).
    /// </summary>
    Task<Stream> GetFileFeedHourlyStreamAsync(string time, CancellationToken cancellationToken = default);

    /// <summary>
    /// Downloads an hourly URL feed package (.tar.bz2 containing 60 per-minute batches).
    /// </summary>
    Task<Stream> GetUrlFeedHourlyStreamAsync(string time, CancellationToken cancellationToken = default);

    /// <summary>
    /// Downloads an hourly domain feed package (.tar.bz2 containing 60 per-minute batches).
    /// </summary>
    Task<Stream> GetDomainFeedHourlyStreamAsync(string time, CancellationToken cancellationToken = default);

    /// <summary>
    /// Downloads an hourly IP address feed package (.tar.bz2 containing 60 per-minute batches).
    /// </summary>
    Task<Stream> GetIpFeedHourlyStreamAsync(string time, CancellationToken cancellationToken = default);

    /// <summary>
    /// Downloads an hourly file behaviour feed package (.tar.bz2 containing 60 per-minute batches).
    /// </summary>
    /// <param name="time">Batch time in <c>YYYYMMDDhh</c> UTC format.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<Stream> GetFileBehaviourFeedHourlyStreamAsync(string time, CancellationToken cancellationToken = default);
}

/// <summary><see cref="IFeedsClient"/> implementation built on top of <see cref="VtClient"/>.</summary>
public sealed class FeedsClient : IFeedsClient
{
    private readonly IVtClient _client;

    /// <summary>Creates a feeds client backed by the given <see cref="IVtClient"/>.</summary>
    public FeedsClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public Task<Stream> GetFileFeedStreamAsync(string time, CancellationToken cancellationToken = default)
        => GetFeedStreamAsync("/feeds/files/", time, null, cancellationToken);

    /// <inheritdoc />
    public Task<Stream> GetUrlFeedStreamAsync(string time, CancellationToken cancellationToken = default)
        => GetFeedStreamAsync("/feeds/urls/", time, null, cancellationToken);

    /// <inheritdoc />
    public Task<Stream> GetDomainFeedStreamAsync(string time, CancellationToken cancellationToken = default)
        => GetFeedStreamAsync("/feeds/domains/", time, null, cancellationToken);

    /// <inheritdoc />
    public Task<Stream> GetIpFeedStreamAsync(string time, CancellationToken cancellationToken = default)
        => GetFeedStreamAsync("/feeds/ip_addresses/", time, null, cancellationToken);

    /// <inheritdoc />
    public Task<Stream> GetFileBehaviourFeedStreamAsync(string time, CancellationToken cancellationToken = default)
        => GetFeedStreamAsync("/feeds/file_behaviours/", time, null, cancellationToken);

    /// <inheritdoc />
    public Task<Stream> GetFileFeedHourlyStreamAsync(string time, CancellationToken cancellationToken = default)
        => GetFeedStreamAsync("/feeds/files/", time, "hourly", cancellationToken);

    /// <inheritdoc />
    public Task<Stream> GetUrlFeedHourlyStreamAsync(string time, CancellationToken cancellationToken = default)
        => GetFeedStreamAsync("/feeds/urls/", time, "hourly", cancellationToken);

    /// <inheritdoc />
    public Task<Stream> GetDomainFeedHourlyStreamAsync(string time, CancellationToken cancellationToken = default)
        => GetFeedStreamAsync("/feeds/domains/", time, "hourly", cancellationToken);

    /// <inheritdoc />
    public Task<Stream> GetIpFeedHourlyStreamAsync(string time, CancellationToken cancellationToken = default)
        => GetFeedStreamAsync("/feeds/ip_addresses/", time, "hourly", cancellationToken);

    /// <inheritdoc />
    public Task<Stream> GetFileBehaviourFeedHourlyStreamAsync(string time, CancellationToken cancellationToken = default)
        => GetFeedStreamAsync("/feeds/file_behaviours/", time, "hourly", cancellationToken);

    private static void ValidateTime(string time)
    {
        if (string.IsNullOrWhiteSpace(time))
            throw new ArgumentException("Time is required.", nameof(time));
    }

    private async Task<Stream> GetFeedStreamAsync(string pathPrefix, string time, string? hourly, CancellationToken cancellationToken)
    {
        ValidateTime(time);
        var path = pathPrefix + (hourly is null ? string.Empty : hourly + "/") + Uri.EscapeDataString(time.Trim());
        return await _client.GetStreamAsync(path, cancellationToken).ConfigureAwait(false);
    }
}
