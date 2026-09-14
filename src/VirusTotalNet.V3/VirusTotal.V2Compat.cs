using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3;

/// <summary>
/// VirusTotal v2 compatibility aliases. Every method in this file mirrors a call that a user of
/// the v2 library (Genbox's <c>VirusTotalNet</c>) would write, so porting an existing integration
/// is a matter of swapping the package and keeping the facade call. The v3 API has no richer data
/// model, so return values are the v3 objects (e.g. <see cref="AnalysisObject"/> instead of the v2
/// <c>ScanResult</c>).
/// </summary>
public sealed partial class VirusTotal
{
    #region VirusTotal v2 compatibility aliases

    /// <summary>
    /// Scans a file from disk (<c>POST /files</c>). Equals the VirusTotal v2 <c>ScanFileAsync(path)</c>.
    /// </summary>
    /// <param name="filePath">Path of the file to scan.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created analysis object.</returns>
    public Task<AnalysisObject> ScanFileAsync(string filePath, CancellationToken cancellationToken = default)
        => ScanFileAsync(new FileInfo(filePath), cancellationToken);

    /// <summary>
    /// Scans a file from disk (<c>POST /files</c>). Equals the VirusTotal v2 <c>ScanFileAsync(FileInfo)</c>.
    /// </summary>
    public async Task<AnalysisObject> ScanFileAsync(FileInfo file, CancellationToken cancellationToken = default)
    {
        if (file is null)
            throw new ArgumentNullException(nameof(file));
        if (!file.Exists)
            throw new FileNotFoundException("The file was not found.", file.FullName);

        using var stream = System.IO.File.OpenRead(file.FullName);
        return await ScanFileAsync(stream, file.Name, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Scans a file from raw bytes. Equals the VirusTotal v2 <c>ScanFileAsync(byte[], filename)</c>.
    /// </summary>
    /// <param name="file">The file content to scan.</param>
    /// <param name="filename">Name sent to the API; often used to infer the file type.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created analysis object.</returns>
    public Task<AnalysisObject> ScanFileAsync(byte[] file, string filename, CancellationToken cancellationToken = default)
    {
        if (file is null)
            throw new ArgumentNullException(nameof(file));
        if (string.IsNullOrWhiteSpace(filename))
            throw new ArgumentException("A filename is required.", nameof(filename));

        using var stream = new MemoryStream(file);
        return ScanFileAsync(stream, filename, cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Scans a large file from disk using the pre-signed upload URL flow.
    /// Equals the VirusTotal v2 <c>ScanLargeFileAsync(path)</c>.
    /// </summary>
    public Task<AnalysisObject> ScanLargeFileAsync(string filePath, CancellationToken cancellationToken = default)
        => ScanLargeFileAsync(new FileInfo(filePath), cancellationToken);

    /// <summary>
    /// Scans a large file from disk using the pre-signed upload URL flow.
    /// Equals the VirusTotal v2 <c>ScanLargeFileAsync(FileInfo)</c>.
    /// </summary>
    public async Task<AnalysisObject> ScanLargeFileAsync(FileInfo file, CancellationToken cancellationToken = default)
    {
        if (file is null)
            throw new ArgumentNullException(nameof(file));
        if (!file.Exists)
            throw new FileNotFoundException("The file was not found.", file.FullName);

        using var stream = System.IO.File.OpenRead(file.FullName);
        return await ScanLargeFileAsync(stream, file.Name, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Scans a large file from raw bytes using the pre-signed upload URL flow.
    /// Equals the VirusTotal v2 <c>ScanLargeFileAsync(byte[], filename)</c>.
    /// </summary>
    public Task<AnalysisObject> ScanLargeFileAsync(byte[] file, string filename, CancellationToken cancellationToken = default)
    {
        if (file is null)
            throw new ArgumentNullException(nameof(file));
        if (string.IsNullOrWhiteSpace(filename))
            throw new ArgumentException("A filename is required.", nameof(filename));

        using var stream = new MemoryStream(file);
        return ScanLargeFileAsync(stream, filename, cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Gets the report of a file from disk. Equals the VirusTotal v2
    /// <c>GetFileReportAsync(FileInfo)</c>: the digest is computed first, and a known file is
    /// returned directly while an unknown one is scanned.
    /// </summary>
    public Task<FileObject> GetFileReportAsync(FileInfo file, CancellationToken cancellationToken = default)
    {
        if (file is null)
            throw new ArgumentNullException(nameof(file));
        if (!file.Exists)
            throw new FileNotFoundException("The file was not found.", file.FullName);

        return GetFileReportAsync(System.IO.File.ReadAllBytes(file.FullName), cancellationToken);
    }

    /// <summary>
    /// Gets the report of a file from a stream. Equals the VirusTotal v2
    /// <c>GetFileReportAsync(Stream)</c>: the digest is computed first, and a known file is
    /// returned directly while an unknown one is scanned.
    /// </summary>
    public Task<FileObject> GetFileReportAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        if (stream is null)
            throw new ArgumentNullException(nameof(stream));

        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return GetFileReportAsync(buffer.ToArray(), cancellationToken);
    }

    /// <summary>
    /// Tells VirusTotal to rescan a file (<c>POST /files/{id}/analyse</c>). Equals the
    /// VirusTotal v2 <c>RescanFileAsync(resource)</c>.
    /// </summary>
    /// <param name="resource">MD5, SHA-1 or SHA-256 digest of the file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The newly created analysis object.</returns>
    public Task<AnalysisObject> RescanFileAsync(string resource, CancellationToken cancellationToken = default)
        => AnalyseFileAsync(resource, cancellationToken);

    /// <summary>
    /// Rescans a file by its content. Equals the VirusTotal v2 <c>RescanFileAsync(byte[])</c>.
    /// </summary>
    public async Task<AnalysisObject> RescanFileAsync(byte[] file, CancellationToken cancellationToken = default)
    {
        if (file is null)
            throw new ArgumentNullException(nameof(file));
        return await AnalyseFileAsync(ComputeSha256(file), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Rescans a file from a stream. Equals the VirusTotal v2 <c>RescanFileAsync(Stream)</c>.
    /// </summary>
    public async Task<AnalysisObject> RescanFileAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        if (stream is null)
            throw new ArgumentNullException(nameof(stream));

        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return await AnalyseFileAsync(ComputeSha256(buffer.ToArray()), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Rescans a file from disk. Equals the VirusTotal v2 <c>RescanFileAsync(FileInfo)</c>.
    /// </summary>
    public async Task<AnalysisObject> RescanFileAsync(FileInfo file, CancellationToken cancellationToken = default)
    {
        if (file is null)
            throw new ArgumentNullException(nameof(file));
        if (!file.Exists)
            throw new FileNotFoundException("The file was not found.", file.FullName);

        return await AnalyseFileAsync(ComputeSha256(System.IO.File.ReadAllBytes(file.FullName)), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Rescans several files by their hashes, one request per file (the v3 API has no batch
    /// rescan endpoint). Equals the VirusTotal v2 <c>RescanFilesAsync(IEnumerable&lt;string&gt;)</c>.
    /// </summary>
    public async Task<IReadOnlyList<AnalysisObject>> RescanFilesAsync(IEnumerable<string> resources, CancellationToken cancellationToken = default)
    {
        if (resources is null)
            throw new ArgumentNullException(nameof(resources));

        var results = new List<AnalysisObject>();
        foreach (var resource in resources)
            results.Add(await AnalyseFileAsync(resource, cancellationToken).ConfigureAwait(false));
        return results;
    }

    /// <summary>
    /// Rescans several files by their content, hashing each file first and sending one request
    /// per file. Equals the VirusTotal v2 <c>RescanFilesAsync(IEnumerable&lt;FileInfo&gt;)</c>.
    /// </summary>
    public async Task<IReadOnlyList<AnalysisObject>> RescanFilesAsync(IEnumerable<FileInfo> files, CancellationToken cancellationToken = default)
    {
        if (files is null)
            throw new ArgumentNullException(nameof(files));

        var results = new List<AnalysisObject>();
        foreach (var file in files)
            results.Add(await RescanFileAsync(file, cancellationToken).ConfigureAwait(false));
        return results;
    }

    /// <summary>
    /// Rescans several files by their raw content, hashing each file first and sending one
    /// request per file. Equals the VirusTotal v2 <c>RescanFilesAsync(IEnumerable&lt;byte[]&gt;)</c>.
    /// </summary>
    public async Task<IReadOnlyList<AnalysisObject>> RescanFilesAsync(IEnumerable<byte[]> files, CancellationToken cancellationToken = default)
    {
        if (files is null)
            throw new ArgumentNullException(nameof(files));

        var results = new List<AnalysisObject>();
        foreach (var file in files)
            results.Add(await RescanFileAsync(file, cancellationToken).ConfigureAwait(false));
        return results;
    }

    /// <summary>
    /// Rescans several files from streams, hashing each stream first and sending one request
    /// per file. Equals the VirusTotal v2 <c>RescanFilesAsync(IEnumerable&lt;Stream&gt;)</c>.
    /// </summary>
    public async Task<IReadOnlyList<AnalysisObject>> RescanFilesAsync(IEnumerable<Stream> streams, CancellationToken cancellationToken = default)
    {
        if (streams is null)
            throw new ArgumentNullException(nameof(streams));

        var results = new List<AnalysisObject>();
        foreach (var stream in streams)
            results.Add(await RescanFileAsync(stream, cancellationToken).ConfigureAwait(false));
        return results;
    }

    /// <summary>
    /// Retrieves the reports of several files by their hashes, one request per file.
    /// Equals the VirusTotal v2 <c>GetFileReportsAsync(IEnumerable&lt;string&gt;)</c>. Unknown
    /// files throw <see cref="NotFoundException"/>.
    /// </summary>
    public async Task<IReadOnlyList<FileObject>> GetFileReportsAsync(IEnumerable<string> resources, CancellationToken cancellationToken = default)
    {
        if (resources is null)
            throw new ArgumentNullException(nameof(resources));

        var results = new List<FileObject>();
        foreach (var resource in resources)
            results.Add(await GetFileReportAsync(resource, cancellationToken).ConfigureAwait(false));
        return results;
    }

    /// <summary>
    /// Retrieves the reports of several files from disk, computing each digest first.
    /// Equals the VirusTotal v2 <c>GetFileReportsAsync(IEnumerable&lt;FileInfo&gt;)</c>.
    /// </summary>
    public async Task<IReadOnlyList<FileObject>> GetFileReportsAsync(IEnumerable<FileInfo> files, CancellationToken cancellationToken = default)
    {
        if (files is null)
            throw new ArgumentNullException(nameof(files));

        var results = new List<FileObject>();
        foreach (var file in files)
            results.Add(await GetFileReportAsync(file, cancellationToken).ConfigureAwait(false));
        return results;
    }

    /// <summary>
    /// Retrieves the reports of several files by their raw content, computing each digest first.
    /// Equals the VirusTotal v2 <c>GetFileReportsAsync(IEnumerable&lt;byte[]&gt;)</c>.
    /// </summary>
    public async Task<IReadOnlyList<FileObject>> GetFileReportsAsync(IEnumerable<byte[]> files, CancellationToken cancellationToken = default)
    {
        if (files is null)
            throw new ArgumentNullException(nameof(files));

        var results = new List<FileObject>();
        foreach (var file in files)
            results.Add(await GetFileReportAsync(file, cancellationToken).ConfigureAwait(false));
        return results;
    }

    /// <summary>
    /// Retrieves the reports of several files from streams, computing each digest first.
    /// Equals the VirusTotal v2 <c>GetFileReportsAsync(IEnumerable&lt;Stream&gt;)</c>.
    /// </summary>
    public async Task<IReadOnlyList<FileObject>> GetFileReportsAsync(IEnumerable<Stream> streams, CancellationToken cancellationToken = default)
    {
        if (streams is null)
            throw new ArgumentNullException(nameof(streams));

        var results = new List<FileObject>();
        foreach (var stream in streams)
            results.Add(await GetFileReportAsync(stream, cancellationToken).ConfigureAwait(false));
        return results;
    }

    /// <summary>
    /// Starts an analysis of a URL (<c>POST /urls</c>). Equals the VirusTotal v2
    /// <c>ScanUrlAsync(Uri)</c>.
    /// </summary>
    public Task<AnalysisObject> ScanUrlAsync(Uri url, CancellationToken cancellationToken = default)
    {
        if (url is null)
            throw new ArgumentNullException(nameof(url));
        return ScanUrlAsync(url.ToString(), cancellationToken);
    }

    /// <summary>
    /// Starts analyses of several URLs, one request per URL (the v3 API has no batch scan
    /// endpoint). Equals the VirusTotal v2 <c>ScanUrlsAsync(IEnumerable&lt;string&gt;)</c>.
    /// </summary>
    public async Task<IReadOnlyList<AnalysisObject>> ScanUrlsAsync(IEnumerable<string> urls, CancellationToken cancellationToken = default)
    {
        if (urls is null)
            throw new ArgumentNullException(nameof(urls));

        var results = new List<AnalysisObject>();
        foreach (var url in urls)
            results.Add(await ScanUrlAsync(url, cancellationToken).ConfigureAwait(false));
        return results;
    }

    /// <summary>
    /// Starts analyses of several URLs, one request per URL.
    /// Equals the VirusTotal v2 <c>ScanUrlsAsync(IEnumerable&lt;Uri&gt;)</c>.
    /// </summary>
    public async Task<IReadOnlyList<AnalysisObject>> ScanUrlsAsync(IEnumerable<Uri> urls, CancellationToken cancellationToken = default)
    {
        if (urls is null)
            throw new ArgumentNullException(nameof(urls));

        return await ScanUrlsAsync(urls.Select(u => u.ToString()), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets a URL report, optionally scanning the URL when it is not in the database.
    /// Equals the VirusTotal v2 <c>GetUrlReportAsync(url, scanIfNoReport)</c>.
    /// </summary>
    /// <param name="url">The URL to look up.</param>
    /// <param name="scanIfNoReport">When <c>true</c>, the URL is scanned if it is not present in the database.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The URL object with its attributes.</returns>
    public async Task<UrlObject> GetUrlReportAsync(string url, bool scanIfNoReport = false, CancellationToken cancellationToken = default)
    {
        try
        {
            return await GetUrlAsync(url, cancellationToken).ConfigureAwait(false);
        }
        catch (NotFoundException) when (scanIfNoReport)
        {
            var analysis = await ScanUrlAsync(url, cancellationToken).ConfigureAwait(false);
            await WaitForCompletionAsync(analysis.Id, cancellationToken: cancellationToken).ConfigureAwait(false);
            return await GetUrlAsync(url, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Gets a URL report. Equals the VirusTotal v2 <c>GetUrlReportAsync(Uri, scanIfNoReport)</c>.
    /// </summary>
    public Task<UrlObject> GetUrlReportAsync(Uri url, bool scanIfNoReport = false, CancellationToken cancellationToken = default)
    {
        if (url is null)
            throw new ArgumentNullException(nameof(url));
        return GetUrlReportAsync(url.ToString(), scanIfNoReport, cancellationToken);
    }

    /// <summary>
    /// Gets the reports of several URLs, one request per URL.
    /// Equals the VirusTotal v2 <c>GetUrlReportsAsync(IEnumerable&lt;string&gt;, scanIfNoReport)</c>.
    /// </summary>
    public async Task<IReadOnlyList<UrlObject>> GetUrlReportsAsync(IEnumerable<string> urls, bool scanIfNoReport = false, CancellationToken cancellationToken = default)
    {
        if (urls is null)
            throw new ArgumentNullException(nameof(urls));

        var results = new List<UrlObject>();
        foreach (var url in urls)
            results.Add(await GetUrlReportAsync(url, scanIfNoReport, cancellationToken).ConfigureAwait(false));
        return results;
    }

    /// <summary>
    /// Gets the reports of several URLs, one request per URL.
    /// Equals the VirusTotal v2 <c>GetUrlReportsAsync(IEnumerable&lt;Uri&gt;, scanIfNoReport)</c>.
    /// </summary>
    public async Task<IReadOnlyList<UrlObject>> GetUrlReportsAsync(IEnumerable<Uri> urls, bool scanIfNoReport = false, CancellationToken cancellationToken = default)
    {
        if (urls is null)
            throw new ArgumentNullException(nameof(urls));

        return await GetUrlReportsAsync(urls.Select(u => u.ToString()), scanIfNoReport, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Retrieves the object of an IP address (<c>GET /ip_addresses/{ip}</c>). Equals the
    /// VirusTotal v2 <c>GetIPReportAsync(ip)</c>.
    /// </summary>
    public Task<IpObject> GetIPReportAsync(string ip, CancellationToken cancellationToken = default)
        => GetIpAsync(ip, cancellationToken);

    /// <summary>
    /// Retrieves the object of an IP address. Equals the VirusTotal v2
    /// <c>GetIPReportAsync(IPAddress)</c>.
    /// </summary>
    public Task<IpObject> GetIPReportAsync(System.Net.IPAddress ip, CancellationToken cancellationToken = default)
    {
        if (ip is null)
            throw new ArgumentNullException(nameof(ip));
        return GetIpAsync(ip.ToString(), cancellationToken);
    }

    /// <summary>
    /// Retrieves the object of a domain (<c>GET /domains/{domain}</c>). Equals the VirusTotal
    /// v2 <c>GetDomainReportAsync(domain)</c>.
    /// </summary>
    public Task<DomainObject> GetDomainReportAsync(string domain, CancellationToken cancellationToken = default)
        => GetDomainAsync(domain, cancellationToken);

    /// <summary>
    /// Retrieves the object of a domain. Equals the VirusTotal v2 <c>GetDomainReportAsync(Uri)</c>.
    /// </summary>
    public Task<DomainObject> GetDomainReportAsync(Uri domain, CancellationToken cancellationToken = default)
    {
        if (domain is null)
            throw new ArgumentNullException(nameof(domain));
        return GetDomainAsync(domain.Host, cancellationToken);
    }

    /// <summary>
    /// Lists the comments of a file by its content. Equals the VirusTotal v2
    /// <c>GetCommentAsync(byte[] file)</c>.
    /// </summary>
    public Task<VtCollection<CommentObject>> GetCommentAsync(byte[] file, CancellationToken cancellationToken = default)
    {
        if (file is null)
            throw new ArgumentNullException(nameof(file));
        return GetCommentsAsync(VtObjectType.File, ComputeSha256(file), cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Lists the comments of a file from disk. Equals the VirusTotal v2
    /// <c>GetCommentAsync(FileInfo file)</c>.
    /// </summary>
    public Task<VtCollection<CommentObject>> GetCommentAsync(FileInfo file, CancellationToken cancellationToken = default)
    {
        if (file is null)
            throw new ArgumentNullException(nameof(file));
        return GetCommentsAsync(VtObjectType.File, ComputeSha256(System.IO.File.ReadAllBytes(file.FullName)), cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Lists the comments of a URL. Equals the VirusTotal v2 <c>GetCommentAsync(Uri uri)</c>.
    /// </summary>
    public Task<VtCollection<CommentObject>> GetCommentAsync(Uri url, CancellationToken cancellationToken = default)
    {
        if (url is null)
            throw new ArgumentNullException(nameof(url));
        return GetCommentsAsync(VtObjectType.Url, VirusTotalNet.V3.Clients.UrlClient.EncodeUrlId(url.ToString()), cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Creates a comment on a file by its content. Equals the VirusTotal v2
    /// <c>CreateCommentAsync(byte[] file, comment)</c>.
    /// </summary>
    public Task<CommentObject> CreateCommentAsync(byte[] file, string comment, CancellationToken cancellationToken = default)
    {
        if (file is null)
            throw new ArgumentNullException(nameof(file));
        return AddCommentAsync(VtObjectType.File, ComputeSha256(file), comment, cancellationToken);
    }

    /// <summary>
    /// Creates a comment on a file from disk. Equals the VirusTotal v2
    /// <c>CreateCommentAsync(FileInfo file, comment)</c>.
    /// </summary>
    public Task<CommentObject> CreateCommentAsync(FileInfo file, string comment, CancellationToken cancellationToken = default)
    {
        if (file is null)
            throw new ArgumentNullException(nameof(file));
        return AddCommentAsync(VtObjectType.File, ComputeSha256(System.IO.File.ReadAllBytes(file.FullName)), comment, cancellationToken);
    }

    /// <summary>
    /// Creates a comment on a URL. Equals the VirusTotal v2 <c>CreateCommentAsync(Uri url, comment)</c>.
    /// </summary>
    public Task<CommentObject> CreateCommentAsync(Uri url, string comment, CancellationToken cancellationToken = default)
    {
        if (url is null)
            throw new ArgumentNullException(nameof(url));
        return AddCommentAsync(VtObjectType.Url, VirusTotalNet.V3.Clients.UrlClient.EncodeUrlId(url.ToString()), comment, cancellationToken);
    }

    /// <summary>
    /// Creates a comment on a resource (a file digest or a URL). Equals the VirusTotal v2
    /// <c>CreateCommentAsync(string resource, comment)</c>.
    /// </summary>
    public Task<CommentObject> CreateCommentAsync(string resource, string comment, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(resource))
            throw new ArgumentException("A resource is required.", nameof(resource));

        return Uri.TryCreate(resource, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps)
            ? AddCommentAsync(VtObjectType.Url, VirusTotalNet.V3.Clients.UrlClient.EncodeUrlId(resource), comment, cancellationToken)
            : AddCommentAsync(VtObjectType.File, resource, comment, cancellationToken);
    }

    /// <summary>
    /// Builds a link to the VirusTotal GUI file report for the given hash. Equals the VirusTotal
    /// v2 <c>GetPublicFileScanLink(hash)</c>.
    /// </summary>
    public static string GetPublicFileScanLink(string hash)
    {
        if (string.IsNullOrWhiteSpace(hash))
            throw new ArgumentException("A hash is required.", nameof(hash));
        return "https://www.virustotal.com/gui/file/" + hash.Trim().ToLowerInvariant();
    }

    /// <summary>
    /// Builds a link to the VirusTotal GUI file report for the given file. Equals the VirusTotal
    /// v2 <c>GetPublicFileScanLink(FileInfo)</c>.
    /// </summary>
    public static string GetPublicFileScanLink(FileInfo file)
    {
        if (file is null)
            throw new ArgumentNullException(nameof(file));
        return GetPublicFileScanLink(ComputeSha256(System.IO.File.ReadAllBytes(file.FullName)));
    }

    /// <summary>
    /// Builds a link to the VirusTotal GUI URL report for the given URL. Equals the VirusTotal
    /// v2 <c>GetPublicUrlScanLink(url)</c>.
    /// </summary>
    public static string GetPublicUrlScanLink(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
            throw new ArgumentException("A URL is required.", nameof(url));
        return "https://www.virustotal.com/gui/url/" + VirusTotalNet.V3.Clients.UrlClient.EncodeUrlId(url.Trim());
    }

    /// <summary>
    /// Builds a link to the VirusTotal GUI URL report. Equals the VirusTotal v2
    /// <c>GetPublicUrlScanLink(Uri)</c>.
    /// </summary>
    public static string GetPublicUrlScanLink(Uri url)
    {
        if (url is null)
            throw new ArgumentNullException(nameof(url));
        return GetPublicUrlScanLink(url.ToString());
    }

    #endregion
}