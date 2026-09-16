# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-09-16

### Fixed
- NuGet packages now include `CHANGELOG.md` and `MIGRATING_FROM_V2.md`

## [1.0.0] - 2026-09-16

First stable release, published to NuGet.

### Added
- netstandard2.0 compatibility verification: `VirusTotalNet.V3.CompatConsumer` consumer library and API-surface checks
- `CHANGELOG.md` + `MIGRATING_FROM_V2.md` (v2 → v3 migration guide)
- Error handling edge cases (#5):
  - `VtNetworkException` for network/timeout failures past retry
  - Malformed/empty success bodies → `JsonException` (throwing) or `VtResult.Failure` (Try*)
  - `TryDeserializeAsync` no longer returns `Success(default)` on bad payloads
  - `RateLimiter` atomic check+enqueue so concurrent bursts never exceed the limit
  - `BuildRelativeUri` percent-encodes path segments (space, `&`, unicode) while preserving `%XX` escapes
  - User cancellation is never wrapped into `VtNetworkException` (stream/raw paths)

### Changed
- Interactive documentation: README links to `CHANGELOG.md` and `MIGRATING_FROM_V2.md`

### Fixed
- 204 NoContent / 304 responses deserialize into an empty envelope instead of crashing
- `GetStreamAsync`/`GetRawAsync` cleanly propagate `OperationCanceledException` when retry is disabled

## [0.8.1-beta] - 2026-09-15

### Added
- Integration test suite expanded from 27 to 32 tests:
  - File states: not-yet-uploaded → 404 `NotFoundError`, in-progress analysis status, finished report with stats
  - Upload-size boundary (4 MiB < 32 MiB direct-limit) scan
  - "Already scanned?" check via `TryGetAsync` (known hash → success, unknown hash → `NotFound` failure)
- 258 unit tests passing

### Changed
- `FileClient.ScanFileAsync`/`ScanLargeFileAsync`, `UrlClient.ScanUrlAsync`, `PrivateScanningClient.UploadPrivateFileAsync` use a content-factory overload so multipart bodies are rebuilt per attempt (safe across 307 redirect + retry)
- `FeedbackClient` comment/vote body `data.type` uses singular `comment`/`vote` (matching the API) instead of plural
- `VtClient.DeserializeResponse` treats 204/205/304 or zero-length bodies as an empty `VtResponse<T>`
- Vote test is idempotent (duplicate "harmless" vote tolerated)

### Fixed
- Upload crash (`ObjectDisposedException` / empty body) when the API redirects (307) or a transient error retriggers `SendAsync` with a disposed `HttpContent`
- DELETE endpoints returning 204 no longer throw `JsonException`
- Windows Defender false positive on EICAR written to disk during integration tests (benign payload used)

## [0.8.0-beta] - 2026-09-14

### Added
- `IVtClient.GetRawAsync<T>` for bare-object endpoints (recursive `data` unwrap; used by private-file upload URL and `api_usage`)
- Feedback latest-comments endpoints: `ListLatestCommentsAsync`, `GetCommentAsync`, `DeleteCommentAsync`, `VoteCommentAsync` (+ `CommentVoteKind`)
- `SearchAsync` `order`/`limit` (1–300)
- Users & groups: role management (`GroupRoles`, PATCH `context_attributes` roles), `GetUserApiUsageAsync` (`ApiUsage`), membership via `/groups/{id}/relationships/users`
- `/intelligence/ioc_stream` → `HuntingClient.GetIocStreamObjectsAsync`
- Typed `AnalysisAttributes.Results` / `AnalysisAttributes.Files`
- XML docs completed and enforced (CS1591 as error)

### Changed
- Facade `VirusTotal` rewritten Genbox-style: ~90 methods over all 18 module clients (split into core + `VirusTotal.V2Compat.cs` alias layer)
- v2-compat batch groups added: `ScanUrlsAsync`, `GetUrlReportsAsync`, `RescanFilesAsync`, `GetFileReportsAsync`, `GetCommentAsync`, `CreateCommentAsync`
- `SavedSearchClient` body fixed to `attributes.search_query` (+ description/private/tags)
- `CollectionClient` elements fixed to `/collections/{id}/{relationship}` (files|urls|domains|ip_addresses)
- `GraphClient` rewritten to real schema (`graph_data`/`nodes`/`links`/`private`/`position`; create requires ≥1 content)
- `FileClient` scan gains optional `password` (encrypted ZIP)
- `AddUserToGroupAsync` simplified to email-based membership; "full_admin" removed

## [0.7.0-beta] - 2026-09-11

### Added
- Premium/private features: `FeedsClient` (per-minute + hourly bz2/tar.bz2 streams), `PrivateScanningClient`, `HuntingClient` (rulesets + notifications, livehunt), `RetrohuntClient` (jobs, abort, matching files), `UsersClient`/`GroupsClient`
- `ReportGenerator` rewritten fully on the v3 API (batch scan → HTML report with per-engine tables, pre-signed large-file flow)
- Typed per-engine results in `VtFileAttributes.LastAnalysisResults`

### Changed
- Relationship descriptor-first call corrected to `/relationships/{name}` (ID-only path, saves quota); cache key split with `ids/` prefix
- `AddVoteAsync` fail-fast validation (only `harmless`/`malicious`)
- Feed hourly path corrected to `/feeds/{type}/hourly/{time}`

## [0.6.0-beta] - 2026-09-11

### Added
- BehaviourClient with full BehaviourAttributes (sandbox info, MITRE ATT&CK, Sigma signatures)
- BehaviourClient download methods: EVTX, PCAP, memdump, HTML
- BehaviourObject/BehaviourAttributes models
- DI registration for BehaviourClient

## [0.5.0-beta] - 2026-09-09

### Added
- Intelligence search: SearchClient with cursor pagination, descriptorsOnly, order, limit
- Result-style VtResult<T> for ThrowOnError=false
- VtClient.GetRawAsync<T> for raw JSON (unwrap recursive data)
- XML documentation for public API (CS1591 as error)
- README completed with examples for M5

### Changed
- VtResult<T> discriminated union: Success/Failure/From/ValueOrThrow
- VtResultException for failed results

## [0.4.0-beta] - 2026-09-09

### Added
- VirusTotalNet.V3.DependencyInjection package with AddVirusTotal()
- DI registration for all 18 clients, singleton VtClient
- Configuration via IOptions<> and IConfiguration

## [0.3.0-alpha] - 2026-09-09

### Added
- FileClient: ScanFileAsync, GetFileAsync, AnalyseFileAsync, DownloadAsync, ScanLargeFileAsync
- AnalysisClient: GetAnalysisAsync, WaitForCompletionAsync
- Facade VirusTotal.GetFileReportAsync (EICAR example)
- Upload URL for files >32MB

## [0.2.0-alpha] - 2026-09-09

### Added
- URL/Domain/IP clients: ScanUrlAsync, GetUrlAsync, GetDomainAsync, GetIpAsync
- Comments & Votes across all types (FeedbackClient)
- Cursor pagination for resolutions, subdomains, relationships
- RelationshipsClient with typed + generic traversal

## [0.1.0-alpha] - 2026-09-08

### Added
- Core infrastructure: VtClient, VtResponse<T> envelope, VtObject<TA>, VtCollection<T>
- RateLimiter sliding-window (4 req/min, 500 req/day default)
- Exception hierarchy: VirusTotalException -> VtHttpException -> concrete types
- Retry policy with exponential backoff + jitter, Retry-After header parsing
- System.Text.Json converters: UnixTimeSeconds, YearMonthDay, "0"/"1", "null"/"N/A"
- VirusTotalOptions, VirusTotalJson shared options
- Test infrastructure: StubHttpMessageHandler, RateLimiter virtual clock, CsCheck property tests

### Fixed
- DNS transient handling in integration tests
- RateLimiter static clock race condition fixed with per-instance clock