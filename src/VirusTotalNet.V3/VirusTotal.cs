using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.V3.Clients;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;
using VirusTotalNet.V3.Relationships;

namespace VirusTotalNet.V3;

/// <summary>
/// VirusTotal API v3 client. Following the Genbox one-liner ergonomics, every operation is
/// available directly on this class — scan a file, retrieve a report, search intelligence,
/// manage collections — so a user needs no knowledge of internal clients.
/// </summary>
public sealed class VirusTotal : IDisposable
{
    private readonly IVtClient _client;
    private readonly bool _ownsClient;

    /// <summary>Underlying client shared by all operations.</summary>
    public IVtClient Client => _client;

    /// <summary>File operations: scan, report, rescan, download.</summary>
    public IFileClient FileClient { get; private set; } = null!;

    /// <summary>Analysis operations: retrieve and wait for completion.</summary>
    public IAnalysisClient AnalysisClient { get; private set; } = null!;

    /// <summary>Relationships: typed accessors, generic fallback, descriptor-first ids and traversal.</summary>
    public IRelationshipsClient Relationships { get; private set; } = null!;

    /// <summary>Url operations: scan, report, rescan.</summary>
    public IUrlClient UrlClient { get; private set; } = null!;

    /// <summary>Domain operations: report, rescan, resolutions, subdomains.</summary>
    public IDomainClient DomainClient { get; private set; } = null!;

    /// <summary>IP address operations: report, rescan, resolutions.</summary>
    public IIpClient IpClient { get; private set; } = null!;

    /// <summary>File behaviour reports: retrieve and download raw sandbox artifacts.</summary>
    public IBehaviourClient Behaviour { get; private set; } = null!;

    /// <summary>Comments and votes on any object, plus comment management.</summary>
    public IFeedbackClient Feedback { get; private set; } = null!;

    /// <summary>Intelligence search (<c>/intelligence/search</c>).</summary>
    public ISearchClient Search { get; private set; } = null!;

    /// <summary>Saved searches (<c>/saved_searches</c>).</summary>
    public ISavedSearchClient SavedSearchClient { get; private set; } = null!;

    /// <summary>Collections (<c>/collections</c>) and their element relationships.</summary>
    public ICollectionClient CollectionClient { get; private set; } = null!;

    /// <summary>Graphs (<c>/graphs</c>).</summary>
    public IGraphClient GraphClient { get; private set; } = null!;

    /// <summary>Threat actors (<c>/threat_actors</c>).</summary>
    public IThreatActorClient ThreatActor { get; private set; } = null!;

    /// <summary>Intelligence feeds: minutely bzip2-compressed batches of files, URLs, domains, IPs and behaviours.</summary>
    public IFeedsClient Feeds { get; private set; } = null!;

    /// <summary>Private scanning (<c>/private/files</c>) for samples that must not be shared with the community.</summary>
    public IPrivateScanningClient PrivateScanning { get; private set; } = null!;

    /// <summary>Livehunt: manage YARA hunting rulesets and view notifications.</summary>
    public IHuntingClient Hunting { get; private set; } = null!;

    /// <summary>Retrohunt: run YARA rules against historical samples.</summary>
    public IRetrohuntClient Retrohunt { get; private set; } = null!;

    /// <summary>Users and groups management.</summary>
    public IUsersClient Users { get; private set; } = null!;

    /// <summary>Creates the facade with the given API key.</summary>
    /// <param name="apiKey">VirusTotal API key, sent as the <c>x-apikey</c> header.</param>
    public VirusTotal(string apiKey)
        : this(new VirusTotalOptions { ApiKey = apiKey })
    {
    }

    /// <summary>Creates the facade with the given options.</summary>
    public VirusTotal(VirusTotalOptions options)
    {
        _client = new VtClient(options ?? throw new ArgumentNullException(nameof(options)));
        _ownsClient = true;
        AssignModuleClients();
    }

    /// <summary>Creates the facade sharing an existing client without owning its lifecycle.</summary>
    /// <param name="client">An existing client; the caller is responsible for disposing it.</param>
    public VirusTotal(IVtClient client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _ownsClient = false;
        AssignModuleClients();
    }

    /// <summary>
    /// Retrieves the report of a file already known to VirusTotal, identified by its MD5, SHA-1
    /// or SHA-256 digest (<c>GET /files/{id}</c>).
    /// </summary>
    /// <param name="hash">MD5, SHA-1 or SHA-256 digest of the file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The file object with its attributes and detection statistics.</returns>
    public Task<FileObject> GetFileReportAsync(string hash, CancellationToken cancellationToken = default)
        => FileClient.GetFileAsync(hash, cancellationToken);

    /// <summary>
    /// Convenience "seen before?" check: computes the SHA-256 of the given bytes, retrieves the
    /// report if the file is already known, otherwise submits a scan, waits for completion, and
    /// returns the fresh report. Files above the direct-upload size limit are rejected.
    /// </summary>
    /// <param name="file">The file content to look up (and scan if not yet known).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The file object with its attributes and detection statistics.</returns>
    public async Task<FileObject> GetFileReportAsync(byte[] file, CancellationToken cancellationToken = default)
    {
        if (file is null)
            throw new ArgumentNullException(nameof(file));

        var sha256 = ComputeSha256(file);

        try
        {
            return await FileClient.GetFileAsync(sha256, cancellationToken).ConfigureAwait(false);
        }
        catch (NotFoundException)
        {
            using var stream = new MemoryStream(file);
            var analysis = await FileClient.ScanFileAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            await AnalysisClient.WaitForCompletionAsync(analysis.Id, cancellationToken: cancellationToken).ConfigureAwait(false);
            return await FileClient.GetFileAsync(sha256, cancellationToken).ConfigureAwait(false);
        }
    }

    #region Files

    /// <summary>
    /// Uploads a file directly to VirusTotal and starts an analysis (<c>POST /files</c>).
    /// The file must not exceed <see cref="FileClient.MaxScanSize"/> bytes.
    /// </summary>
    /// <param name="stream">The file content to scan.</param>
    /// <param name="fileName">Name sent to the API; often used to infer the file type.</param>
    /// <param name="password">Optional password for password-protected ZIP files.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created analysis object; poll its id to retrieve the completed report.</returns>
    public Task<AnalysisObject> ScanFileAsync(Stream stream, string? fileName = null, string? password = null, CancellationToken cancellationToken = default)
        => FileClient.ScanFileAsync(stream, fileName, password, cancellationToken);

    /// <summary>
    /// Uploads a file larger than <see cref="FileClient.MaxScanSize"/> using a pre-signed upload URL:
    /// fetches <c>GET /files/upload_url</c> then multipart-POSTs the file to that URL.
    /// </summary>
    /// <param name="stream">The file content to scan (typically larger than 32 MiB).</param>
    /// <param name="fileName">Name sent to the API; often used to infer the file type.</param>
    /// <param name="password">Optional password for password-protected ZIP files.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created analysis object; poll its id to retrieve the completed report.</returns>
    public Task<AnalysisObject> ScanLargeFileAsync(Stream stream, string? fileName = null, string? password = null, CancellationToken cancellationToken = default)
        => FileClient.ScanLargeFileAsync(stream, fileName, password, cancellationToken);

    /// <summary>
    /// Rescans a file already present on VirusTotal (<c>POST /files/{id}/analyse</c>).
    /// </summary>
    /// <param name="id">MD5, SHA-1 or SHA-256 digest of the file to rescan.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The newly created analysis object.</returns>
    public Task<AnalysisObject> AnalyseFileAsync(string id, CancellationToken cancellationToken = default)
        => FileClient.AnalyseFileAsync(id, cancellationToken);

    /// <summary>
    /// Downloads the content of a known file (<c>GET /files/{id}/download</c>; redirects are followed).
    /// </summary>
    /// <param name="id">MD5, SHA-1 or SHA-256 digest of the file to download.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A stream with the raw file bytes; the caller must dispose it.</returns>
    public Task<Stream> DownloadFileAsync(string id, CancellationToken cancellationToken = default)
        => FileClient.DownloadAsync(id, cancellationToken);

    /// <summary>
    /// Retrieves a pre-signed URL that can be used to download the file (<c>GET /files/{id}/download_url</c>).
    /// </summary>
    /// <param name="id">MD5, SHA-1 or SHA-256 digest of the file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The pre-signed download URL.</returns>
    public Task<string> GetFileDownloadUrlAsync(string id, CancellationToken cancellationToken = default)
        => FileClient.GetDownloadUrlAsync(id, cancellationToken);

    #endregion

    #region Analyses

    /// <summary>
    /// Retrieves an analysis by its id (<c>GET /analyses/{id}</c>). The result may still be
    /// <c>queued</c> or <c>in-progress</c>; use <see cref="WaitForCompletionAsync"/> to wait.
    /// </summary>
    /// <param name="id">Id of the analysis, as returned when submitting a scan.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The analysis object, including its current status.</returns>
    public Task<AnalysisObject> GetAnalysisAsync(string id, CancellationToken cancellationToken = default)
        => AnalysisClient.GetAnalysisAsync(id, cancellationToken);

    /// <summary>
    /// Polls the analysis until it reaches an end status (<c>completed</c>) or until the given
    /// <paramref name="cancellationToken"/> is cancelled. Each poll shares the client's rate
    /// limiter. For unknown statuses the current analysis is returned as-is to avoid an
    /// endless loop.
    /// </summary>
    /// <param name="id">Id of the analysis to wait for.</param>
    /// <param name="pollInterval">Delay between polls; defaults to <see cref="AnalysisClient.DefaultPollInterval"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The completed analysis object.</returns>
    public Task<AnalysisObject> WaitForCompletionAsync(string id, TimeSpan? pollInterval = null, CancellationToken cancellationToken = default)
        => AnalysisClient.WaitForCompletionAsync(id, pollInterval, cancellationToken);

    #endregion

    #region URLs

    /// <summary>
    /// Starts an analysis of a URL (<c>POST /urls</c>).
    /// </summary>
    /// <param name="url">The URL to analyse.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created analysis object.</returns>
    public Task<AnalysisObject> ScanUrlAsync(string url, CancellationToken cancellationToken = default)
        => UrlClient.ScanUrlAsync(url, cancellationToken);

    /// <summary>
    /// Retrieves the object of a URL (<c>GET /urls/{id}</c>). Accepts either the URL itself
    /// (automatically encoded to its base64url id) or an already-encoded id.
    /// </summary>
    /// <param name="urlOrId">The URL (e.g. <c>https://example.com/</c>) or a base64url-encoded URL id.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The URL object with its attributes.</returns>
    public Task<UrlObject> GetUrlAsync(string urlOrId, CancellationToken cancellationToken = default)
        => UrlClient.GetUrlAsync(urlOrId, cancellationToken);

    /// <summary>
    /// Rescans a URL (<c>POST /urls/{id}/analyse</c>).
    /// </summary>
    /// <param name="urlOrId">The URL or a base64url-encoded URL id.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The newly created analysis object.</returns>
    public Task<AnalysisObject> AnalyseUrlAsync(string urlOrId, CancellationToken cancellationToken = default)
        => UrlClient.AnalyseUrlAsync(urlOrId, cancellationToken);

    /// <summary>
    /// Encodes a URL to its VirusTotal base64url identifier (no padding), e.g.
    /// <c>https://example.com/</c> → <c>aHR0cHM6Ly9leGFtcGxlLmNvbS8</c>.
    /// </summary>
    public static string EncodeUrlId(string url)
        => VirusTotalNet.V3.Clients.UrlClient.EncodeUrlId(url);

    #endregion

    #region Domains

    /// <summary>
    /// Retrieves the object of a domain (<c>GET /domains/{domain}</c>).
    /// </summary>
    /// <param name="domain">The domain name, e.g. <c>example.com</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The domain object with its attributes.</returns>
    public Task<DomainObject> GetDomainAsync(string domain, CancellationToken cancellationToken = default)
        => DomainClient.GetDomainAsync(domain, cancellationToken);

    /// <summary>
    /// Rescans a domain (<c>POST /domains/{domain}/analyse</c>).
    /// </summary>
    /// <param name="domain">The domain name.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The newly created analysis object.</returns>
    public Task<AnalysisObject> AnalyseDomainAsync(string domain, CancellationToken cancellationToken = default)
        => DomainClient.AnalyseDomainAsync(domain, cancellationToken);

    /// <summary>
    /// Lists the DNS resolutions of a domain (<c>GET /domains/{domain}/resolutions</c>).
    /// </summary>
    /// <param name="domain">The domain name.</param>
    /// <param name="cursor">Optional pagination cursor for the next page.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A page of resolution objects with its next cursor.</returns>
    public Task<VtCollection<ResolutionObject>> GetDomainResolutionsAsync(string domain, string? cursor = null, CancellationToken cancellationToken = default)
        => DomainClient.GetResolutionsAsync(domain, cursor, cancellationToken);

    /// <summary>
    /// Lists the subdomains of a domain (<c>GET /domains/{domain}/subdomains</c>).
    /// </summary>
    /// <param name="domain">The domain name.</param>
    /// <param name="cursor">Optional pagination cursor for the next page.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A page of subdomain objects with its next cursor.</returns>
    public Task<VtCollection<DomainObject>> GetDomainSubdomainsAsync(string domain, string? cursor = null, CancellationToken cancellationToken = default)
        => DomainClient.GetSubdomainsAsync(domain, cursor, cancellationToken);

    #endregion

    #region IP addresses

    /// <summary>
    /// Retrieves the object of an IP address (<c>GET /ip_addresses/{ip}</c>).
    /// </summary>
    /// <param name="ip">The IP address (IPv4 or IPv6), e.g. <c>8.8.8.8</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The IP-address object with its attributes.</returns>
    public Task<IpObject> GetIpAsync(string ip, CancellationToken cancellationToken = default)
        => IpClient.GetIpAsync(ip, cancellationToken);

    /// <summary>
    /// Rescans an IP address (<c>POST /ip_addresses/{ip}/analyse</c>).
    /// </summary>
    /// <param name="ip">The IP address.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The newly created analysis object.</returns>
    public Task<AnalysisObject> AnalyseIpAsync(string ip, CancellationToken cancellationToken = default)
        => IpClient.AnalyseIpAsync(ip, cancellationToken);

    /// <summary>
    /// Lists the domains that resolve to the IP address (<c>GET /ip_addresses/{ip}/resolutions</c>).
    /// </summary>
    /// <param name="ip">The IP address.</param>
    /// <param name="cursor">Optional pagination cursor for the next page.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A page of resolution objects with its next cursor.</returns>
    public Task<VtCollection<ResolutionObject>> GetIpResolutionsAsync(string ip, string? cursor = null, CancellationToken cancellationToken = default)
        => IpClient.GetResolutionsAsync(ip, cursor, cancellationToken);

    #endregion

    #region File behaviours

    /// <summary>
    /// Retrieves the behaviour report of a file (<c>GET /file_behaviours/{id}</c>).
    /// </summary>
    /// <param name="id">Behaviour id (hash of the analysed sample).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The behaviour object with its attributes.</returns>
    public Task<BehaviourObject> GetBehaviourAsync(string id, CancellationToken cancellationToken = default)
        => Behaviour.GetBehaviourAsync(id, cancellationToken);

    /// <summary>
    /// Downloads the Windows Event Log of a behaviour (<c>GET /file_behaviours/{id}/evtx</c>).
    /// </summary>
    /// <param name="id">Behaviour id.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A stream with the raw bytes; the caller must dispose it.</returns>
    public Task<Stream> DownloadBehaviourEvtxAsync(string id, CancellationToken cancellationToken = default)
        => Behaviour.DownloadEvtxAsync(id, cancellationToken);

    /// <summary>
    /// Downloads the network packet capture of a behaviour (<c>GET /file_behaviours/{id}/pcap</c>).
    /// </summary>
    public Task<Stream> DownloadBehaviourPcapAsync(string id, CancellationToken cancellationToken = default)
        => Behaviour.DownloadPcapAsync(id, cancellationToken);

    /// <summary>
    /// Downloads the memory dump of a behaviour (<c>GET /file_behaviours/{id}/memdump</c>).
    /// </summary>
    public Task<Stream> DownloadBehaviourMemdumpAsync(string id, CancellationToken cancellationToken = default)
        => Behaviour.DownloadMemdumpAsync(id, cancellationToken);

    /// <summary>
    /// Downloads the rendered HTML report of a behaviour (<c>GET /file_behaviours/{id}/html</c>).
    /// </summary>
    public Task<Stream> DownloadBehaviourHtmlAsync(string id, CancellationToken cancellationToken = default)
        => Behaviour.DownloadHtmlAsync(id, cancellationToken);

    #endregion

    #region Comments and votes

    /// <summary>
    /// Lists the comments of an object (<c>GET /{objectType}/{id}/comments</c>).
    /// </summary>
    /// <param name="objectType">Object type path segment, see <see cref="VtObjectType"/>.</param>
    /// <param name="id">Object id (for URLs, the base64url-encoded id).</param>
    /// <param name="cursor">Optional pagination cursor for the next page.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<VtCollection<CommentObject>> GetCommentsAsync(string objectType, string id, string? cursor = null, CancellationToken cancellationToken = default)
        => Feedback.GetCommentsAsync(objectType, id, cursor, cancellationToken);

    /// <summary>
    /// Adds a comment to an object (<c>POST /{objectType}/{id}/comments</c>).
    /// </summary>
    /// <param name="objectType">Object type path segment, see <see cref="VtObjectType"/>.</param>
    /// <param name="id">Object id.</param>
    /// <param name="text">The comment text (markdown).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created comment object.</returns>
    public Task<CommentObject> AddCommentAsync(string objectType, string id, string text, CancellationToken cancellationToken = default)
        => Feedback.AddCommentAsync(objectType, id, text, cancellationToken);

    /// <summary>
    /// Lists the votes of an object (<c>GET /{objectType}/{id}/votes</c>).
    /// </summary>
    /// <param name="objectType">Object type path segment, see <see cref="VtObjectType"/>.</param>
    /// <param name="id">Object id.</param>
    /// <param name="cursor">Optional pagination cursor for the next page.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<VtCollection<VoteObject>> GetVotesAsync(string objectType, string id, string? cursor = null, CancellationToken cancellationToken = default)
        => Feedback.GetVotesAsync(objectType, id, cursor, cancellationToken);

    /// <summary>
    /// Casts a vote on an object (<c>POST /{objectType}/{id}/votes</c>).
    /// </summary>
    /// <param name="objectType">Object type path segment, see <see cref="VtObjectType"/>.</param>
    /// <param name="id">Object id.</param>
    /// <param name="verdict">The verdict, e.g. <c>malicious</c> or <c>harmless</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created vote object.</returns>
    public Task<VoteObject> AddVoteAsync(string objectType, string id, string verdict, CancellationToken cancellationToken = default)
        => Feedback.AddVoteAsync(objectType, id, verdict, cancellationToken);

    /// <summary>
    /// Lists the most recent comments across the community (<c>GET /comments</c>).
    /// </summary>
    /// <param name="filter">Optional filter expression, e.g. <c>attributes.date:2020-04-01T00:00:00Z</c>.</param>
    /// <param name="limit">Optional maximum number of comments to return.</param>
    /// <param name="cursor">Optional pagination cursor for the next page.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<VtCollection<CommentObject>> ListLatestCommentsAsync(string? filter = null, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default)
        => Feedback.ListLatestCommentsAsync(filter, limit, cursor, cancellationToken);

    /// <summary>
    /// Retrieves a single comment object (<c>GET /comments/{id}</c>).
    /// </summary>
    /// <param name="commentId">Comment id (see the <c>d|f|g|i|u</c> id prefixes from the API docs).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<CommentObject> GetCommentAsync(string commentId, CancellationToken cancellationToken = default)
        => Feedback.GetCommentAsync(commentId, cancellationToken);

    /// <summary>
    /// Deletes a comment (<c>DELETE /comments/{id}</c>). Only the author can delete it.
    /// </summary>
    /// <param name="commentId">Comment id.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task DeleteCommentAsync(string commentId, CancellationToken cancellationToken = default)
        => Feedback.DeleteCommentAsync(commentId, cancellationToken);

    /// <summary>
    /// Casts a vote on a comment (<c>POST /comments/{id}/vote</c>).
    /// </summary>
    /// <param name="commentId">Comment id.</param>
    /// <param name="vote">The vote category (positive, negative or abuse).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task VoteCommentAsync(string commentId, CommentVoteKind vote, CancellationToken cancellationToken = default)
        => Feedback.VoteCommentAsync(commentId, vote, cancellationToken);

    #endregion

    #region Intelligence search

    /// <summary>
    /// Runs an intelligence search query and returns one page of results (<c>/intelligence/search</c>).
    /// </summary>
    /// <param name="query">The search query, e.g. <c>type:url</c> or <c>name:powershell.exe</c>.</param>
    /// <param name="cursor">Optional pagination cursor for the next page.</param>
    /// <param name="descriptorsOnly">When <c>true</c>, the API returns only <c>(type, id)</c> descriptors to save quota.</param>
    /// <param name="order">Optional sort order, e.g. <c>date+</c> or <c>-last_modification_date</c>.</param>
    /// <param name="limit">Maximum number of results to return (1-300; the API default is 10).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A page of search hits with its next cursor.</returns>
    public Task<VtCollection<VtSearchObject>> SearchAsync(string query, string? cursor = null, bool descriptorsOnly = false, string? order = null, int? limit = null, CancellationToken cancellationToken = default)
        => Search.SearchAsync(query, cursor, descriptorsOnly, order, limit, cancellationToken);

    #endregion

    #region Saved searches

    /// <summary>
    /// Creates a saved search (<c>POST /saved_searches</c>).
    /// The query is stored under the API's <c>search_query</c> attribute.
    /// </summary>
    public Task<SavedSearchObject> CreateSavedSearchAsync(string name, string query, string? description = null, bool? isPrivate = null, IReadOnlyList<string>? tags = null, CancellationToken cancellationToken = default)
        => SavedSearchClient.CreateSavedSearchAsync(name, query, description, isPrivate, tags, cancellationToken);

    /// <summary>Retrieves a saved search (<c>GET /saved_searches/{id}</c>).</summary>
    public Task<SavedSearchObject> GetSavedSearchAsync(string id, CancellationToken cancellationToken = default)
        => SavedSearchClient.GetSavedSearchAsync(id, cancellationToken);

    /// <summary>List saved searches (<c>GET /saved_searches</c>) with cursor pagination.</summary>
    public Task<VtCollection<SavedSearchObject>> ListSavedSearchesAsync(string? cursor = null, CancellationToken cancellationToken = default)
        => SavedSearchClient.ListSavedSearchesAsync(cursor, cancellationToken);

    /// <summary>Deletes a saved search (<c>DELETE /saved_searches/{id}</c>).</summary>
    public Task DeleteSavedSearchAsync(string id, CancellationToken cancellationToken = default)
        => SavedSearchClient.DeleteSavedSearchAsync(id, cancellationToken);

    #endregion

    #region Collections

    /// <summary>Creates a collection (<c>POST /collections</c>).</summary>
    public Task<CollectionObject> CreateCollectionAsync(string name, string? description = null, CancellationToken cancellationToken = default)
        => CollectionClient.CreateCollectionAsync(name, description, cancellationToken);

    /// <summary>Retrieves a collection (<c>GET /collections/{id}</c>).</summary>
    public Task<CollectionObject> GetCollectionAsync(string id, CancellationToken cancellationToken = default)
        => CollectionClient.GetCollectionAsync(id, cancellationToken);

    /// <summary>Updates a collection (<c>PATCH /collections/{id}</c>).</summary>
    public Task<CollectionObject> UpdateCollectionAsync(string id, string? name = null, string? description = null, CancellationToken cancellationToken = default)
        => CollectionClient.UpdateCollectionAsync(id, name, description, cancellationToken);

    /// <summary>Deletes a collection (<c>DELETE /collections/{id}</c>).</summary>
    public Task DeleteCollectionAsync(string id, CancellationToken cancellationToken = default)
        => CollectionClient.DeleteCollectionAsync(id, cancellationToken);

    /// <summary>
    /// Adds elements of one object type to a collection (<c>POST /collections/{id}/{relationship}</c>).
    /// See <see cref="CollectionRelationshipName"/>.
    /// </summary>
    /// <param name="collectionId">Collection id.</param>
    /// <param name="relationship">Element relationship name, e.g. <see cref="CollectionRelationshipName.Files"/>.</param>
    /// <param name="elements">Object descriptors to add.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task AddCollectionElementsAsync(string collectionId, string relationship, IEnumerable<VtObjectId> elements, CancellationToken cancellationToken = default)
        => CollectionClient.AddElementsAsync(collectionId, relationship, elements, cancellationToken);

    /// <summary>
    /// Removes elements of one object type from a collection (<c>DELETE /collections/{id}/{relationship}</c>).
    /// See <see cref="CollectionRelationshipName"/>.
    /// </summary>
    /// <param name="collectionId">Collection id.</param>
    /// <param name="relationship">Element relationship name, e.g. <see cref="CollectionRelationshipName.Urls"/>.</param>
    /// <param name="elements">Object descriptors to remove.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task RemoveCollectionElementsAsync(string collectionId, string relationship, IEnumerable<VtObjectId> elements, CancellationToken cancellationToken = default)
        => CollectionClient.RemoveElementsAsync(collectionId, relationship, elements, cancellationToken);

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
    public Task<VtCollection<T>> ListCollectionElementsAsync<T>(string collectionId, string relationship, string? cursor = null, CancellationToken cancellationToken = default)
        where T : class
        => CollectionClient.ListElementsAsync<T>(collectionId, relationship, cursor, cancellationToken);

    #endregion

    #region Graphs

    /// <summary>
    /// Creates a graph (<c>POST /graphs</c>). At least one of <paramref name="graphData"/>,
    /// <paramref name="nodes"/> or <paramref name="links"/> must be provided.
    /// </summary>
    /// <param name="graphData">Optional graph data payload (name/description and version).</param>
    /// <param name="nodes">Optional list of graph nodes.</param>
    /// <param name="links">Optional list of links between nodes.</param>
    /// <param name="isPrivate">When <c>true</c>, the graph counts against the private graph quota.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<GraphObject> CreateGraphAsync(GraphData? graphData = null, IReadOnlyList<GraphNode>? nodes = null, IReadOnlyList<GraphLink>? links = null, bool? isPrivate = null, CancellationToken cancellationToken = default)
        => GraphClient.CreateGraphAsync(graphData, nodes, links, isPrivate, cancellationToken);

    /// <summary>Retrieves a graph (<c>GET /graphs/{id}</c>).</summary>
    public Task<GraphObject> GetGraphAsync(string id, CancellationToken cancellationToken = default)
        => GraphClient.GetGraphAsync(id, cancellationToken);

    /// <summary>
    /// Updates a graph (<c>PATCH /graphs/{id}</c>). At least one parameter must be provided.
    /// </summary>
    /// <param name="id">Graph id (65-character hex string).</param>
    /// <param name="graphData">Updated graph data payload (name/description and version).</param>
    /// <param name="nodes">Updated node list (replaces the whole list when provided).</param>
    /// <param name="links">Updated link list (replaces the whole list when provided).</param>
    /// <param name="isPrivate">Updated private status.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<GraphObject> UpdateGraphAsync(string id, GraphData? graphData = null, IReadOnlyList<GraphNode>? nodes = null, IReadOnlyList<GraphLink>? links = null, bool? isPrivate = null, CancellationToken cancellationToken = default)
        => GraphClient.UpdateGraphAsync(id, graphData, nodes, links, isPrivate, cancellationToken);

    /// <summary>Deletes a graph (<c>DELETE /graphs/{id}</c>).</summary>
    public Task DeleteGraphAsync(string id, CancellationToken cancellationToken = default)
        => GraphClient.DeleteGraphAsync(id, cancellationToken);

    #endregion

    #region Threat actors

    /// <summary>Retrieves a threat actor (<c>GET /threat_actors/{id}</c>).</summary>
    public Task<ThreatActorObject> GetThreatActorAsync(string id, CancellationToken cancellationToken = default)
        => ThreatActor.GetThreatActorAsync(id, cancellationToken);

    #endregion

    #region Feeds

    /// <summary>
    /// Downloads a per-minute file feed batch (<c>GET /feeds/files/{time}</c>).
    /// The returned stream is bzip2-compressed NDJSON (one <c>FileObject</c> JSON per line).
    /// </summary>
    /// <param name="time">Batch time in <c>YYYYMMDDhhmm</c> UTC format (e.g. <c>202609111200</c>).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A bzip2-compressed stream of file objects.</returns>
    public Task<Stream> GetFileFeedStreamAsync(string time, CancellationToken cancellationToken = default)
        => Feeds.GetFileFeedStreamAsync(time, cancellationToken);

    /// <summary>Downloads a per-minute URL feed batch (bzip2-compressed NDJSON).</summary>
    public Task<Stream> GetUrlFeedStreamAsync(string time, CancellationToken cancellationToken = default)
        => Feeds.GetUrlFeedStreamAsync(time, cancellationToken);

    /// <summary>Downloads a per-minute domain feed batch (bzip2-compressed NDJSON).</summary>
    public Task<Stream> GetDomainFeedStreamAsync(string time, CancellationToken cancellationToken = default)
        => Feeds.GetDomainFeedStreamAsync(time, cancellationToken);

    /// <summary>Downloads a per-minute IP address feed batch (bzip2-compressed NDJSON).</summary>
    public Task<Stream> GetIpFeedStreamAsync(string time, CancellationToken cancellationToken = default)
        => Feeds.GetIpFeedStreamAsync(time, cancellationToken);

    /// <summary>Downloads a per-minute file behaviour feed batch (bzip2-compressed NDJSON).</summary>
    public Task<Stream> GetFileBehaviourFeedStreamAsync(string time, CancellationToken cancellationToken = default)
        => Feeds.GetFileBehaviourFeedStreamAsync(time, cancellationToken);

    /// <summary>Downloads an hourly file feed package (.tar.bz2 containing 60 per-minute batches).</summary>
    public Task<Stream> GetFileFeedHourlyStreamAsync(string time, CancellationToken cancellationToken = default)
        => Feeds.GetFileFeedHourlyStreamAsync(time, cancellationToken);

    /// <summary>Downloads an hourly URL feed package (.tar.bz2 containing 60 per-minute batches).</summary>
    public Task<Stream> GetUrlFeedHourlyStreamAsync(string time, CancellationToken cancellationToken = default)
        => Feeds.GetUrlFeedHourlyStreamAsync(time, cancellationToken);

    /// <summary>Downloads an hourly domain feed package (.tar.bz2 containing 60 per-minute batches).</summary>
    public Task<Stream> GetDomainFeedHourlyStreamAsync(string time, CancellationToken cancellationToken = default)
        => Feeds.GetDomainFeedHourlyStreamAsync(time, cancellationToken);

    /// <summary>Downloads an hourly IP address feed package (.tar.bz2 containing 60 per-minute batches).</summary>
    public Task<Stream> GetIpFeedHourlyStreamAsync(string time, CancellationToken cancellationToken = default)
        => Feeds.GetIpFeedHourlyStreamAsync(time, cancellationToken);

    /// <summary>Downloads an hourly file behaviour feed package (.tar.bz2 containing 60 per-minute batches).</summary>
    public Task<Stream> GetFileBehaviourFeedHourlyStreamAsync(string time, CancellationToken cancellationToken = default)
        => Feeds.GetFileBehaviourFeedHourlyStreamAsync(time, cancellationToken);

    #endregion

    #region Private scanning

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
    public Task<AnalysisObject> UploadPrivateFileAsync(Stream file, bool? disableSandbox = null, bool? enableInternet = null, bool? interceptTls = null, string? commandLine = null, string? password = null, int? retentionPeriodDays = null, string? storageRegion = null, CancellationToken cancellationToken = default)
        => PrivateScanning.UploadPrivateFileAsync(file, disableSandbox, enableInternet, interceptTls, commandLine, password, retentionPeriodDays, storageRegion, cancellationToken);

    /// <summary>
    /// Retrieves a pre-signed URL that can be used to upload a private file (<c>GET /private/files/upload_url</c>).
    /// </summary>
    public Task<string> GetPrivateFileUploadUrlAsync(CancellationToken cancellationToken = default)
        => PrivateScanning.GetPrivateFileUploadUrlAsync(cancellationToken);

    /// <summary>
    /// Lists private files uploaded by the current user (<c>GET /private/files</c>) with cursor pagination.
    /// </summary>
    public Task<VtCollection<PrivateFileObject>> ListPrivateFilesAsync(string? cursor = null, CancellationToken cancellationToken = default)
        => PrivateScanning.ListPrivateFilesAsync(cursor, cancellationToken);

    /// <summary>
    /// Retrieves a private file by its id (<c>GET /private/files/{id}</c>).
    /// </summary>
    public Task<PrivateFileObject> GetPrivateFileAsync(string id, CancellationToken cancellationToken = default)
        => PrivateScanning.GetPrivateFileAsync(id, cancellationToken);

    /// <summary>
    /// Deletes a private file (<c>DELETE /private/files/{id}</c>).
    /// </summary>
    public Task DeletePrivateFileAsync(string id, CancellationToken cancellationToken = default)
        => PrivateScanning.DeletePrivateFileAsync(id, cancellationToken);

    /// <summary>
    /// Starts a new analysis of an already uploaded private file (<c>POST /private/files/{id}/analyse</c>).
    /// </summary>
    public Task<AnalysisObject> AnalysePrivateFileAsync(string id, CancellationToken cancellationToken = default)
        => PrivateScanning.AnalysePrivateFileAsync(id, cancellationToken);

    /// <summary>
    /// Retrieves a private analysis by its id (<c>GET /private/analyses/{id}</c>).
    /// </summary>
    public Task<AnalysisObject> GetPrivateAnalysisAsync(string id, CancellationToken cancellationToken = default)
        => PrivateScanning.GetPrivateAnalysisAsync(id, cancellationToken);

    /// <summary>
    /// Retrieves the behaviour reports of a private file (<c>GET /private/files/{id}/behaviours</c>).
    /// </summary>
    public Task<VtCollection<BehaviourObject>> GetPrivateFileBehavioursAsync(string id, CancellationToken cancellationToken = default)
        => PrivateScanning.GetPrivateFileBehavioursAsync(id, cancellationToken);

    #endregion

    #region Hunting (Livehunt)

    /// <summary>Creates a hunting ruleset (<c>POST /intelligence/hunting_rulesets</c>).</summary>
    public Task<HuntingRulesetObject> CreateRulesetAsync(string name, string rules, bool enabled = true, int limit = 100, List<string>? notificationEmails = null, string? matchObjectType = null, CancellationToken cancellationToken = default)
        => Hunting.CreateRulesetAsync(name, rules, enabled, limit, notificationEmails, matchObjectType, cancellationToken);

    /// <summary>Lists hunting rulesets (<c>GET /intelligence/hunting_rulesets</c>) with optional filtering and ordering.</summary>
    public Task<VtCollection<HuntingRulesetObject>> ListRulesetsAsync(string? filter = null, string? order = null, string? cursor = null, CancellationToken cancellationToken = default)
        => Hunting.ListRulesetsAsync(filter, order, cursor, cancellationToken);

    /// <summary>Retrieves a hunting ruleset by its id (<c>GET /intelligence/hunting_rulesets/{id}</c>).</summary>
    public Task<HuntingRulesetObject> GetRulesetAsync(string id, CancellationToken cancellationToken = default)
        => Hunting.GetRulesetAsync(id, cancellationToken);

    /// <summary>Updates a hunting ruleset (<c>PATCH /intelligence/hunting_rulesets/{id}</c>); only provided fields are changed.</summary>
    public Task<HuntingRulesetObject> UpdateRulesetAsync(string id, string? name = null, string? rules = null, bool? enabled = null, int? limit = null, List<string>? notificationEmails = null, CancellationToken cancellationToken = default)
        => Hunting.UpdateRulesetAsync(id, name, rules, enabled, limit, notificationEmails, cancellationToken);

    /// <summary>Deletes a hunting ruleset (<c>DELETE /intelligence/hunting_rulesets/{id}</c>).</summary>
    public Task DeleteRulesetAsync(string id, CancellationToken cancellationToken = default)
        => Hunting.DeleteRulesetAsync(id, cancellationToken);

    /// <summary>Lists hunting notifications (<c>GET /intelligence/hunting_notifications</c>) with optional filtering, ordering and page size.</summary>
    public Task<VtCollection<HuntingNotificationObject>> ListNotificationsAsync(string? filter = null, string? order = null, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default)
        => Hunting.ListNotificationsAsync(filter, order, limit, cursor, cancellationToken);

    /// <summary>Retrieves a hunting notification by its id (<c>GET /intelligence/hunting_notifications/{id}</c>).</summary>
    public Task<HuntingNotificationObject> GetNotificationAsync(string id, CancellationToken cancellationToken = default)
        => Hunting.GetNotificationAsync(id, cancellationToken);

    /// <summary>
    /// Retrieves objects from the Intelligence IoC Stream (<c>GET /ioc_stream</c>), the
    /// replacement for the deprecated hunting-notifications feed on the web UI.
    /// </summary>
    /// <param name="filter">Filter string, e.g. <c>date:2023-02-07T10:00:00+</c>, <c>origin:hunting</c>, <c>entity_type:file</c>.</param>
    /// <param name="limit">Number of objects to retrieve (1-40; default 10).</param>
    /// <param name="descriptorsOnly">Return only object descriptors instead of full objects.</param>
    /// <param name="order">Sort order: <c>date-</c> (newest first, default) or <c>date+</c>.</param>
    /// <param name="cursor">Continuation cursor.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<VtCollection<VtIocStreamObject>> GetIocStreamObjectsAsync(string? filter = null, int? limit = null, bool? descriptorsOnly = null, string? order = null, string? cursor = null, CancellationToken cancellationToken = default)
        => Hunting.GetIocStreamObjectsAsync(filter, limit, descriptorsOnly, order, cursor, cancellationToken);

    #endregion

    #region Retrohunt

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
    public Task<RetrohuntJobObject> CreateRetrohuntJobAsync(string rules, string? notificationEmail = null, string? corpus = "main", int? timeRangeStart = null, int? timeRangeEnd = null, CancellationToken cancellationToken = default)
        => Retrohunt.CreateJobAsync(rules, notificationEmail, corpus, timeRangeStart, timeRangeEnd, cancellationToken);

    /// <summary>Lists retrohunt jobs (<c>GET /intelligence/retrohunt_jobs</c>) with cursor pagination.</summary>
    public Task<VtCollection<RetrohuntJobObject>> ListRetrohuntJobsAsync(string? cursor = null, CancellationToken cancellationToken = default)
        => Retrohunt.ListJobsAsync(cursor, cancellationToken);

    /// <summary>Retrieves a retrohunt job by its id (<c>GET /intelligence/retrohunt_jobs/{id}</c>).</summary>
    public Task<RetrohuntJobObject> GetRetrohuntJobAsync(string id, CancellationToken cancellationToken = default)
        => Retrohunt.GetJobAsync(id, cancellationToken);

    /// <summary>Aborts a running retrohunt job (<c>DELETE /intelligence/retrohunt_jobs/{id}</c>).</summary>
    public Task AbortRetrohuntJobAsync(string id, CancellationToken cancellationToken = default)
        => Retrohunt.AbortJobAsync(id, cancellationToken);

    /// <summary>Lists the files matching a retrohunt job (<c>GET /intelligence/retrohunt_jobs/{id}/matching_files</c>).</summary>
    public Task<VtCollection<FileObject>> GetRetrohuntMatchingFilesAsync(string id, string? cursor = null, CancellationToken cancellationToken = default)
        => Retrohunt.GetMatchingFilesAsync(id, cursor, cancellationToken);

    #endregion

    #region Users and groups

    /// <summary>Retrieves a user by its id (<c>GET /users/{id}</c>).</summary>
    public Task<UserObject> GetUserAsync(string id, CancellationToken cancellationToken = default)
        => Users.GetUserAsync(id, cancellationToken);

    /// <summary>Updates a user (<c>PATCH /users/{id}</c>); only provided fields are changed.</summary>
    public Task<UserObject> UpdateUserAsync(string id, string? displayName = null, string? email = null, string? name = null, CancellationToken cancellationToken = default)
        => Users.UpdateUserAsync(id, displayName, email, name, cancellationToken);

    /// <summary>Deletes a user (<c>DELETE /users/{id}</c>).</summary>
    public Task DeleteUserAsync(string id, CancellationToken cancellationToken = default)
        => Users.DeleteUserAsync(id, cancellationToken);

    /// <summary>Retrieves a group by its id (<c>GET /groups/{id}</c>).</summary>
    public Task<GroupObject> GetGroupAsync(string id, CancellationToken cancellationToken = default)
        => Users.GetGroupAsync(id, cancellationToken);

    /// <summary>Updates a group (<c>PATCH /groups/{id}</c>).</summary>
    public Task<GroupObject> UpdateGroupAsync(string id, string? name = null, CancellationToken cancellationToken = default)
        => Users.UpdateGroupAsync(id, name, cancellationToken);

    /// <summary>Deletes a group (<c>DELETE /groups/{id}</c>).</summary>
    public Task DeleteGroupAsync(string id, CancellationToken cancellationToken = default)
        => Users.DeleteGroupAsync(id, cancellationToken);

    /// <summary>Lists the members of a group (<c>GET /groups/{id}/users</c>) with cursor pagination.</summary>
    public Task<VtCollection<UserObject>> ListGroupUsersAsync(string id, string? cursor = null, CancellationToken cancellationToken = default)
        => Users.ListGroupUsersAsync(id, cursor, cancellationToken);

    /// <summary>
    /// Adds a user to a group (<c>POST /groups/{id}/relationships/users</c>).
    /// </summary>
    /// <param name="groupId">Group id.</param>
    /// <param name="userEmail">Email of the user to add; a username is rejected by the API.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task AddUserToGroupAsync(string groupId, string userEmail, CancellationToken cancellationToken = default)
        => Users.AddUserToGroupAsync(groupId, userEmail, cancellationToken);

    /// <summary>
    /// Replaces the roles of a user in a group (<c>PATCH /groups/{id}/relationships/users</c>).
    /// Roles must be one of the <see cref="GroupRoles"/> values.
    /// </summary>
    public Task SetGroupUserRolesAsync(string groupId, string userId, IEnumerable<string> roles, CancellationToken cancellationToken = default)
        => Users.SetGroupUserRolesAsync(groupId, userId, roles, cancellationToken);

    /// <summary>
    /// Appends new roles to a user in a group (<c>PATCH /groups/{id}/relationships/users</c>);
    /// existing roles are kept. Roles must be one of the <see cref="GroupRoles"/> values.
    /// </summary>
    public Task AddGroupUserRolesAsync(string groupId, string userId, IEnumerable<string> roles, CancellationToken cancellationToken = default)
        => Users.AddGroupUserRolesAsync(groupId, userId, roles, cancellationToken);

    /// <summary>
    /// Revokes the given roles from a user in a group (<c>PATCH /groups/{id}/relationships/users</c>).
    /// Roles must be one of the <see cref="GroupRoles"/> values.
    /// </summary>
    public Task RemoveGroupUserRolesAsync(string groupId, string userId, IEnumerable<string> roles, CancellationToken cancellationToken = default)
        => Users.RemoveGroupUserRolesAsync(groupId, userId, roles, cancellationToken);

    /// <summary>Removes a user from a group (<c>DELETE /groups/{id}/relationships/users/{userId}</c>).</summary>
    public Task RemoveUserFromGroupAsync(string groupId, string userId, CancellationToken cancellationToken = default)
        => Users.RemoveUserFromGroupAsync(groupId, userId, cancellationToken);

    /// <summary>
    /// Retrieves the API usage of a user broken down by endpoint (<c>GET /users/{id}/api_usage</c>).
    /// </summary>
    /// <param name="id">User id or API key.</param>
    /// <param name="startDate">First day to report, format <c>YYYYMMDD</c>.</param>
    /// <param name="endDate">Last day to report, format <c>YYYYMMDD</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<ApiUsage> GetUserApiUsageAsync(string id, string? startDate = null, string? endDate = null, CancellationToken cancellationToken = default)
        => Users.GetUserApiUsageAsync(id, startDate, endDate, cancellationToken);

    #endregion

    #region Relationships

    /// <summary>
    /// Retrieves one page of related objects (<c>GET /{objectType}/{id}/{relationshipName}</c>).
    /// The first page of each <c>(objectType, id, relationshipName)</c> is memoized per client
    /// for the lifetime of the session.
    /// </summary>
    /// <typeparam name="T">Object type of the related resources (e.g. <see cref="UrlObject"/>).</typeparam>
    /// <param name="objectType">Object type path segment, see <see cref="VtObjectType"/>.</param>
    /// <param name="id">Object id (for URLs, the base64url-encoded id).</param>
    /// <param name="relationshipName">Relationship name, see <see cref="RelationshipName"/>.</param>
    /// <param name="cursor">Optional pagination cursor for the next page.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<VtCollection<T>> GetRelatedAsync<T>(string objectType, string id, string relationshipName, string? cursor = null, CancellationToken cancellationToken = default)
        where T : class
        => Relationships.GetRelatedAsync<T>(objectType, id, relationshipName, cursor, cancellationToken);

    /// <summary>
    /// Descriptor-first: retrieves only the <c>(type, id)</c> pairs of related objects, skipping
    /// attribute materialization to stay light on quota and memory.
    /// </summary>
    public Task<VtCollection<VtObjectId>> GetRelatedIdsAsync(string objectType, string id, string relationshipName, string? cursor = null, CancellationToken cancellationToken = default)
        => Relationships.GetRelatedIdsAsync(objectType, id, relationshipName, cursor, cancellationToken);

#if NET8_0_OR_GREATER
    /// <summary>
    /// Traverses every page of a relationship, yielding the related objects in order.
    /// Cancellable via <paramref name="cancellationToken"/>. Only available on net8.0 and later
    /// (netstandard2.0 lacks <see cref="IAsyncEnumerable{T}"/>).
    /// </summary>
    public IAsyncEnumerable<T> TraverseRelatedAsync<T>(string objectType, string id, string relationshipName, CancellationToken cancellationToken = default)
        where T : class
        => Relationships.TraverseAsync<T>(objectType, id, relationshipName, cancellationToken);
#endif

    /// <summary>Clears the in-session memoization cache of the relationships client.</summary>
    public void ClearRelationshipCache()
        => Relationships.ClearCache();

    #endregion

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

    private void AssignModuleClients()
    {
        FileClient = new FileClient(_client);
        AnalysisClient = new AnalysisClient(_client);
        Relationships = new RelationshipsClient(_client);
        UrlClient = new UrlClient(_client);
        DomainClient = new DomainClient(_client);
        IpClient = new IpClient(_client);
        Behaviour = new BehaviourClient(_client);
        Feedback = new FeedbackClient(_client);
        Search = new SearchClient(_client);
        SavedSearchClient = new SavedSearchClient(_client);
        CollectionClient = new CollectionClient(_client);
        GraphClient = new GraphClient(_client);
        ThreatActor = new ThreatActorClient(_client);
        Feeds = new FeedsClient(_client);
        PrivateScanning = new PrivateScanningClient(_client);
        Hunting = new HuntingClient(_client);
        Retrohunt = new RetrohuntClient(_client);
        Users = new UsersClient(_client);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsClient && _client is IDisposable disposable)
            disposable.Dispose();
    }

    private static string ComputeSha256(byte[] data)
    {
#if NET8_0_OR_GREATER
        return Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
#else
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(data);
        var builder = new StringBuilder(hash.Length * 2);
        foreach (var b in hash)
            builder.Append(b.ToString("x2"));
        return builder.ToString();
#endif
    }
}