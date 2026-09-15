# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Premium/private features: FeedsClient, PrivateScanningClient, HuntingClient, RetrohuntClient, UsersClient, GroupsClient
- SavedSearchClient, ThreatActorClient, CollectionClient, GraphClient, BehaviourClient
- DI integration: `VirusTotalNet.V3.DependencyInjection` package with `AddVirusTotal()`
- ReportGenerator console tool for batch file scanning with HTML output
- Facade `VirusTotal` Genbox-style with ~90 methods covering all 18 clients
- v2-compat alias layer in `VirusTotal.V2Compat.cs` for migration assistance
- File state tracking: upload-size limits, check-already-scanned via TryGetAsync
- Error handling edge cases: malformed JSON → VtResult.Failure, network errors → VtNetworkException
- BuildRelativeUri path encoding for special characters
- RateLimiter atomic check-enqueue for concurrent request limiting

### Changed
- Facade `VirusTotal` realigned to Genbox-style with all 18 module clients exposed
- FileClient.ScanFileAsync fixed multipart upload on redirect/retry (content factory pattern)
- FeedbackClient body type fixed from plural to singular (`comment` vs `comments`)
- VtClient.DeserializeResponse fixed for 204 NoContent / empty body handling
- RateLimiter clock injection per-instance (no more static clock race conditions)
- BuildRelativeUri now percent-encodes path segments, preserves %XX escapes

### Fixed
- Multipart upload content disposal on 307 redirect + retry (content factory pattern)
- Vote idempotency: duplicate "harmless" vote handled gracefully
- EICAR false positive in Windows Defender during integration tests
- DNS transient failures during integration test runs

### Security
- API key only via `x-apikey` header, never in query string
- No secrets in git history or logs

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

---

**Note**: Version 0.8.0-beta published after #2 Audit API surface completion (facade realign + v2-compat alias).