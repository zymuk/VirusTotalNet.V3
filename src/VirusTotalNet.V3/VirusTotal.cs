using System;
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
/// Facade for the VirusTotal API v3 that keeps the v2 "one-liner" ergonomics: construct with an
/// API key and call convenience methods such as <see cref="GetFileReportAsync(byte[], CancellationToken)"/>.
/// Module clients (<see cref="FileClient"/>, <see cref="AnalysisClient"/>, ...) are exposed for
/// deeper operations and all share the same underlying <see cref="IVtClient"/>.
/// </summary>
public sealed class VirusTotal : IDisposable
{
    private readonly IVtClient _client;
    private readonly bool _ownsClient;

    /// <summary>Underlying client shared by all module clients.</summary>
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