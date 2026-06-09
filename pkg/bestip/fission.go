package bestip

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type FissionConfig struct {
	SeedIPs           []string `json:"seed_ips"`
	Rounds            int      `json:"rounds"`
	Concurrency       int      `json:"concurrency"`
	TimeoutMS         int      `json:"timeout_ms"`
	MaxDomains        int      `json:"max_domains"`
	MaxIPsPerRound    int      `json:"max_ips_per_round"`
	Families          []string `json:"families"`
	ProbePort         int      `json:"probe_port"`
	ProbeCount        int      `json:"probe_count"`
	ResultCount       int      `json:"result_count"`
	HTTPTestEnabled   *bool    `json:"http_test_enabled,omitempty"`
	HTTPTestURL       string   `json:"http_test_url,omitempty"`
	HTTPTestSeconds   int      `json:"http_test_seconds"`
	MinDownloadMBps   float64  `json:"min_download_mbps"`
	WeightLatency     float64  `json:"weight_latency"`
	WeightSuccessRate float64  `json:"weight_success_rate"`
	WeightDownload    float64  `json:"weight_download"`
	StagedScanEnabled bool     `json:"staged_scan_enabled"`
	QuickTCPCount     int      `json:"quick_tcp_count"`
	LatencyCheckCount int      `json:"latency_check_count"`
}

type FissionRoundResult struct {
	Round        int      `json:"round"`
	NewIPs       []string `json:"new_ips"`
	NewDomains   []string `json:"new_domains"`
	TotalIPs     int      `json:"total_ips"`
	TotalDomains int      `json:"total_domains"`
}

type FissionRunResult struct {
	IPs        []string             `json:"ips"`
	Rounds     []FissionRoundResult `json:"rounds"`
	Candidates []CandidateResult    `json:"candidates"`
	ProbeStats *ProbeStats          `json:"probe_stats,omitempty"`
}

const (
	FissionProgressStart                     = "start"
	FissionProgressRoundStart                = "round_start"
	FissionProgressIPLookupStart             = "ip_lookup_start"
	FissionProgressLookupSourceStart         = "lookup_source_start"
	FissionProgressLookupSourceDone          = "lookup_source_done"
	FissionProgressIPLookupDone              = "ip_lookup_done"
	FissionProgressDomainResolveStart        = "domain_resolve_start"
	FissionProgressDomainResolveDone         = "domain_resolve_done"
	FissionProgressRoundDone                 = "round_done"
	FissionProgressCloudflareValidationStart = "cloudflare_validation_start"
	FissionProgressCloudflareValidationDone  = "cloudflare_validation_done"
	FissionProgressProbeStart                = "probe_start"
	FissionProgressProbeStageStart           = "probe_stage_start"
	FissionProgressProbeStageDone            = "probe_stage_done"
	FissionProgressProbeResult               = "probe_result"
	FissionProgressProbeDone                 = "probe_done"
	FissionProgressDone                      = "done"
	FissionProgressError                     = "error"
)

const (
	sourceRequestCacheTTL     = 5 * time.Minute
	sourceFailureThreshold    = 3
	sourceCircuitOpenDuration = 30 * time.Second
	sourceBackoffBase         = 100 * time.Millisecond
	sourceBackoffMax          = time.Second
)

const (
	defaultHTTPTestURL           = "http://speed.cloudflare.com/__down?bytes=20971520"
	defaultResultCount           = 10
	scoreLatencyWeight           = 0.35
	scoreSuccessRateWeight       = 0.25
	scoreDownloadWeight          = 0.40
	downloadScoreBaselineMBps    = 20.0
	cloudflareRangeClientTimeout = 10 * time.Second
	cloudflareRangeCacheTTL      = 24 * time.Hour
	cloudflareIPv4RangesURL      = "https://www.cloudflare.com/ips-v4"
	cloudflareIPv6RangesURL      = "https://www.cloudflare.com/ips-v6"
)

type FissionProgressEvent struct {
	Type                 string              `json:"type"`
	Round                int                 `json:"round,omitempty"`
	IP                   string              `json:"ip,omitempty"`
	Domain               string              `json:"domain,omitempty"`
	Source               string              `json:"source,omitempty"`
	StatusCode           int                 `json:"status_code,omitempty"`
	IPs                  []string            `json:"ips,omitempty"`
	Domains              []string            `json:"domains,omitempty"`
	NewIPs               []string            `json:"new_ips,omitempty"`
	NewDomains           []string            `json:"new_domains,omitempty"`
	FilteredIPs          []string            `json:"filtered_ips,omitempty"`
	TotalIPs             int                 `json:"total_ips,omitempty"`
	TotalDomains         int                 `json:"total_domains,omitempty"`
	ProbePort            int                 `json:"probe_port,omitempty"`
	ProbeCount           int                 `json:"probe_count,omitempty"`
	Stage                string              `json:"stage,omitempty"`
	Workers              int                 `json:"workers,omitempty"`
	Done                 int                 `json:"done,omitempty"`
	CloudflareIPv4Ranges int                 `json:"cloudflare_ipv4_ranges,omitempty"`
	CloudflareIPv6Ranges int                 `json:"cloudflare_ipv6_ranges,omitempty"`
	CloudflareHitRate    float64             `json:"cloudflare_hit_rate,omitempty"`
	Candidate            *CandidateResult    `json:"candidate,omitempty"`
	Result               *FissionRunResult   `json:"result,omitempty"`
	RoundResult          *FissionRoundResult `json:"round_result,omitempty"`
	ProbeStats           *ProbeStats         `json:"probe_stats,omitempty"`
	Error                string              `json:"error,omitempty"`
}

type CandidateResult struct {
	Family       string  `json:"family"`
	IP           string  `json:"ip"`
	Attempts     int     `json:"attempts"`
	Successes    int     `json:"successes"`
	AvgLatencyMS float64 `json:"avg_latency_ms"`
	P95LatencyMS float64 `json:"p95_latency_ms"`
	SuccessRate  float64 `json:"success_rate"`
	DownloadMBps float64 `json:"download_mbps"`
	Score        float64 `json:"score"`
	TimeoutCount int     `json:"timeout_count"`
	RefusedCount int     `json:"refused_count"`
	OtherErrors  int     `json:"other_errors"`
}

type ProbeStats struct {
	TotalProbes      int           `json:"total_probes"`
	SuccessCount     int           `json:"success_count"`
	TimeoutCount     int           `json:"timeout_count"`
	RefusedCount     int           `json:"refused_count"`
	OtherErrorCount  int           `json:"other_error_count"`
	TCPDialAttempts  int           `json:"tcp_dial_attempts"`
	QuickStageCount  int           `json:"quick_stage_count"`
	FullStageCount   int           `json:"full_stage_count"`
	StagedScan       bool          `json:"staged_scan"`
	HTTPTestCount    int           `json:"http_test_count"`
	HTTPSuccessCount int           `json:"http_success_count"`
	HTTPFailCount    int           `json:"http_fail_count"`
	HTTPDuration     time.Duration `json:"http_duration"`
}

type FissionService struct {
	Config               FissionConfig
	LookupDomains        func(context.Context, string) []string
	ResolveDomain        func(context.Context, string) []string
	ProbeIP              func(context.Context, string) CandidateResult
	ProbeIPWithAttempts  func(context.Context, string, int) CandidateResult
	DialIP               func(context.Context, string, time.Duration) error
	MeasureDownload      func(context.Context, string) float64
	LoadCloudflareRanges func(context.Context) (cloudflareRanges, error)
	Progress             func(FissionProgressEvent)

	client          *http.Client
	cloudflareCache *cloudflareRangeCache
	domainCache     map[string][]string
	requestCache    map[string]cacheEntry
	sourceStats     map[string]*sourceRuntimeState
	sources         []domainLookupSource
	fetch           func(context.Context, string) (string, error)
	now             func() time.Time
	mu              sync.RWMutex
}

type domainLookupSource struct {
	name  string
	url   func(ip string) string
	parse func(body string, ip string) []string
}

type cacheEntry struct {
	body      string
	timestamp time.Time
}

type sourceRuntimeState struct {
	Requests            int
	CacheHits           int
	Successes           int
	EmptyResults        int
	Failures            int
	CircuitSkips        int
	ConsecutiveFailures int
	CircuitOpenUntil    time.Time
	LastError           string
}

type SourceStatsSnapshot struct {
	Requests            int       `json:"requests"`
	CacheHits           int       `json:"cache_hits"`
	Successes           int       `json:"successes"`
	EmptyResults        int       `json:"empty_results"`
	Failures            int       `json:"failures"`
	CircuitSkips        int       `json:"circuit_skips"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	CircuitOpenUntil    time.Time `json:"circuit_open_until,omitempty"`
	LastError           string    `json:"last_error,omitempty"`
}

type cloudflareRanges struct {
	v4       []netip.Prefix
	v6       []netip.Prefix
	loadedAt time.Time
}

type cloudflareRangeCache struct {
	mu     sync.RWMutex
	ranges cloudflareRanges
	ttl    time.Duration
	fetch  func(context.Context, string) (string, error)
	now    func() time.Time
}

type httpStatusError struct {
	StatusCode int
}

func (err httpStatusError) Error() string {
	return fmt.Sprintf("HTTP %d", err.StatusCode)
}

const domainLookupUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"

var domainRe = regexp.MustCompile(`(?i)([a-z0-9][-a-z0-9]*\.)+[a-z]{2,}`)
var htmlTagRe = regexp.MustCompile(`(?is)<[^>]+>`)
var tableRowRe = regexp.MustCompile(`(?is)<tr\b[^>]*>.*?</tr>`)
var tableCellRe = regexp.MustCompile(`(?is)<td\b[^>]*>(.*?)</td>`)
var cloudflareHTTPClient = &http.Client{Timeout: cloudflareRangeClientTimeout}
var defaultCloudflareRangeCache = newCloudflareRangeCache(cloudflareRangeCacheTTL, time.Now, fetchCloudflareRangeURL)

func newCloudflareRangeCache(ttl time.Duration, now func() time.Time, fetch func(context.Context, string) (string, error)) *cloudflareRangeCache {
	if now == nil {
		now = time.Now
	}
	if fetch == nil {
		fetch = fetchCloudflareRangeURL
	}
	return &cloudflareRangeCache{
		ttl:   ttl,
		now:   now,
		fetch: fetch,
	}
}

func (c *cloudflareRangeCache) Load(ctx context.Context) (cloudflareRanges, error) {
	c.mu.RLock()
	if c.hasFreshRangesLocked() {
		ranges := c.ranges.clone()
		c.mu.RUnlock()
		return ranges, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hasFreshRangesLocked() {
		return c.ranges.clone(), nil
	}

	ranges, err := c.loadFromNetworkLocked(ctx)
	if err != nil {
		if c.ranges.hasRanges() {
			return c.ranges.clone(), nil
		}
		return cloudflareRanges{}, err
	}
	c.ranges = ranges
	return c.ranges.clone(), nil
}

func (c *cloudflareRangeCache) hasFreshRangesLocked() bool {
	if !c.ranges.hasRanges() || c.ranges.loadedAt.IsZero() {
		return false
	}
	ttl := c.ttl
	if ttl <= 0 {
		ttl = cloudflareRangeCacheTTL
	}
	return c.now().Sub(c.ranges.loadedAt) <= ttl
}

func (c *cloudflareRangeCache) loadFromNetworkLocked(ctx context.Context) (cloudflareRanges, error) {
	v4Body, err := c.fetch(ctx, cloudflareIPv4RangesURL)
	if err != nil {
		return cloudflareRanges{}, fmt.Errorf("加载 IPv4 段失败: %w", err)
	}
	v6Body, err := c.fetch(ctx, cloudflareIPv6RangesURL)
	if err != nil {
		return cloudflareRanges{}, fmt.Errorf("加载 IPv6 段失败: %w", err)
	}
	ranges := cloudflareRanges{
		v4:       parseCloudflarePrefixes(v4Body),
		v6:       parseCloudflarePrefixes(v6Body),
		loadedAt: c.now(),
	}
	if !ranges.hasRanges() {
		return cloudflareRanges{}, fmt.Errorf("未加载到 Cloudflare IP 段")
	}
	return ranges, nil
}

func parseCloudflarePrefixes(body string) []netip.Prefix {
	prefixes := []netip.Prefix{}
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			continue
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

func fetchCloudflareRangeURL(ctx context.Context, sourceURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "bestipd/1.0")
	resp, err := cloudflareHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024*1024))
		return "", httpStatusError{StatusCode: resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (ranges cloudflareRanges) clone() cloudflareRanges {
	return cloudflareRanges{
		v4:       slices.Clone(ranges.v4),
		v6:       slices.Clone(ranges.v6),
		loadedAt: ranges.loadedAt,
	}
}

func (ranges cloudflareRanges) hasRanges() bool {
	return len(ranges.v4) > 0 || len(ranges.v6) > 0
}

func (ranges cloudflareRanges) stats() (int, int) {
	return len(ranges.v4), len(ranges.v6)
}

func (ranges cloudflareRanges) filter(ips []string) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		if ranges.contains(addr) {
			out = append(out, addr.String())
		}
	}
	return out
}

func (ranges cloudflareRanges) contains(addr netip.Addr) bool {
	prefixes := ranges.v4
	if addr.Is6() {
		prefixes = ranges.v6
	}
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func NewFissionService(config FissionConfig) *FissionService {
	config, _ = NormalizeFissionConfig(config)
	timeout := time.Duration(config.TimeoutMS) * time.Millisecond
	service := &FissionService{
		Config: config,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true},
				TLSHandshakeTimeout:   timeout,
				ResponseHeaderTimeout: timeout,
			},
		},
		cloudflareCache: defaultCloudflareRangeCache,
		domainCache:     make(map[string][]string),
		requestCache:    make(map[string]cacheEntry),
		sourceStats:     make(map[string]*sourceRuntimeState),
		now:             time.Now,
	}
	service.fetch = service.fetchDomainLookupURL
	service.sources = service.defaultDomainLookupSources()
	service.LookupDomains = service.lookupDomains
	service.ResolveDomain = service.resolveDomain
	service.MeasureDownload = service.measureDownload
	service.LoadCloudflareRanges = service.loadCloudflareRanges
	return service
}

func NormalizeFissionConfig(config FissionConfig) (FissionConfig, error) {
	if config.Rounds <= 0 {
		config.Rounds = 2
	}
	if config.Rounds > 5 {
		config.Rounds = 5
	}
	if config.Concurrency <= 0 {
		config.Concurrency = 10
	}
	if config.Concurrency > 100 {
		config.Concurrency = 100
	}
	if config.TimeoutMS <= 0 {
		config.TimeoutMS = 3000
	}
	if config.TimeoutMS > 30000 {
		config.TimeoutMS = 30000
	}
	if config.MaxDomains <= 0 {
		config.MaxDomains = 200
	}
	if config.MaxDomains > 5000 {
		config.MaxDomains = 5000
	}
	if config.MaxIPsPerRound <= 0 {
		config.MaxIPsPerRound = 200
	}
	if config.MaxIPsPerRound > 5000 {
		config.MaxIPsPerRound = 5000
	}
	if config.ProbePort <= 0 {
		config.ProbePort = 443
	}
	if config.ProbePort > 65535 {
		config.ProbePort = 65535
	}
	if config.ProbeCount <= 0 {
		config.ProbeCount = 3
	}
	if config.ProbeCount > 10 {
		config.ProbeCount = 10
	}
	if config.ResultCount <= 0 {
		config.ResultCount = defaultResultCount
	}
	if config.ResultCount > 100 {
		config.ResultCount = 100
	}
	if config.HTTPTestSeconds <= 0 {
		config.HTTPTestSeconds = 3
	}
	if config.HTTPTestSeconds > 30 {
		config.HTTPTestSeconds = 30
	}
	if strings.TrimSpace(config.HTTPTestURL) == "" {
		config.HTTPTestURL = defaultHTTPTestURL
	}
	if config.MinDownloadMBps < 0 {
		config.MinDownloadMBps = 0
	}
	if config.WeightLatency < 0 || config.WeightSuccessRate < 0 || config.WeightDownload < 0 {
		return config, fmt.Errorf("weights must not be negative")
	}
	totalWeight := config.WeightLatency + config.WeightSuccessRate + config.WeightDownload
	if totalWeight <= 0 {
		config.WeightLatency = scoreLatencyWeight
		config.WeightSuccessRate = scoreSuccessRateWeight
		config.WeightDownload = scoreDownloadWeight
	} else {
		config.WeightLatency /= totalWeight
		config.WeightSuccessRate /= totalWeight
		config.WeightDownload /= totalWeight
	}
	if config.QuickTCPCount < 0 {
		config.QuickTCPCount = 0
	}
	if config.LatencyCheckCount < 0 {
		config.LatencyCheckCount = 0
	}
	if config.QuickTCPCount == 0 {
		config.QuickTCPCount = max(config.ResultCount*8, 32)
	}
	if config.LatencyCheckCount == 0 {
		config.LatencyCheckCount = max(config.ResultCount*4, 16)
	}
	if config.LatencyCheckCount > config.QuickTCPCount {
		config.LatencyCheckCount = config.QuickTCPCount
	}

	config.Families = normalizeFamilies(config.Families)
	seedIPs := make([]string, 0, len(config.SeedIPs))
	seen := make(map[string]struct{}, len(config.SeedIPs))
	for _, rawIP := range config.SeedIPs {
		rawIP = strings.TrimSpace(rawIP)
		if rawIP == "" {
			continue
		}
		addr, err := netip.ParseAddr(rawIP)
		if err != nil {
			return config, fmt.Errorf("invalid seed ip %q: %w", rawIP, err)
		}
		if addr.Is4() && !slices.Contains(config.Families, "ipv4") {
			continue
		}
		if addr.Is6() && !slices.Contains(config.Families, "ipv6") {
			continue
		}
		ip := addr.String()
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		seedIPs = append(seedIPs, ip)
	}
	if len(seedIPs) == 0 {
		return config, fmt.Errorf("seed_ips must include at least one IP for selected families")
	}
	config.SeedIPs = seedIPs
	return config, nil
}

func (s *FissionService) Run(ctx context.Context) (*FissionRunResult, error) {
	config, err := NormalizeFissionConfig(s.Config)
	if err != nil {
		s.emitProgress(FissionProgressEvent{Type: FissionProgressError, Error: err.Error()})
		return nil, err
	}
	s.Config = config
	if s.MeasureDownload == nil {
		s.MeasureDownload = s.measureDownload
	}
	if s.LoadCloudflareRanges == nil {
		s.LoadCloudflareRanges = s.loadCloudflareRanges
	}

	ipSet := map[string]struct{}{}
	domainSet := map[string]struct{}{}
	for _, ip := range config.SeedIPs {
		ipSet[ip] = struct{}{}
	}

	s.emitProgress(FissionProgressEvent{
		Type:       FissionProgressStart,
		IPs:        slices.Clone(config.SeedIPs),
		TotalIPs:   len(ipSet),
		ProbePort:  config.ProbePort,
		ProbeCount: config.ProbeCount,
	})

	currentIPs := slices.Clone(config.SeedIPs)
	rounds := make([]FissionRoundResult, 0, config.Rounds)
	for round := 1; round <= config.Rounds && len(currentIPs) > 0; round++ {
		if err := ctx.Err(); err != nil {
			s.emitProgress(FissionProgressEvent{Type: FissionProgressError, Error: err.Error()})
			return nil, err
		}

		s.emitProgress(FissionProgressEvent{
			Type:     FissionProgressRoundStart,
			Round:    round,
			IPs:      slices.Clone(currentIPs),
			TotalIPs: len(ipSet),
		})

		discoveredDomains := s.ipToDomains(ctx, currentIPs, round)
		newDomains := make([]string, 0, len(discoveredDomains))
		for _, domain := range discoveredDomains {
			if _, ok := domainSet[domain]; ok {
				continue
			}
			if len(domainSet) >= config.MaxDomains {
				break
			}
			domainSet[domain] = struct{}{}
			newDomains = append(newDomains, domain)
		}

		allDomains := keys(domainSet)
		discoveredIPs := s.domainsToIPs(ctx, allDomains, round)
		newIPs := make([]string, 0, len(discoveredIPs))
		for _, ip := range discoveredIPs {
			if _, ok := ipSet[ip]; ok {
				continue
			}
			ipSet[ip] = struct{}{}
			newIPs = append(newIPs, ip)
		}
		slices.Sort(newIPs)
		if len(newIPs) > config.MaxIPsPerRound {
			for _, ip := range newIPs[config.MaxIPsPerRound:] {
				delete(ipSet, ip)
			}
			newIPs = newIPs[:config.MaxIPsPerRound]
		}

		roundResult := FissionRoundResult{
			Round:        round,
			NewIPs:       newIPs,
			NewDomains:   newDomains,
			TotalIPs:     len(ipSet),
			TotalDomains: len(domainSet),
		}
		rounds = append(rounds, roundResult)
		s.emitProgress(FissionProgressEvent{
			Type:         FissionProgressRoundDone,
			Round:        round,
			NewIPs:       slices.Clone(newIPs),
			NewDomains:   slices.Clone(newDomains),
			TotalIPs:     len(ipSet),
			TotalDomains: len(domainSet),
			RoundResult:  &roundResult,
		})
		currentIPs = newIPs
	}

	ips := keys(ipSet)
	slices.Sort(ips)
	ips, err = s.filterCloudflareIPs(ctx, ips)
	if err != nil {
		s.emitProgress(FissionProgressEvent{Type: FissionProgressError, Error: err.Error()})
		return nil, err
	}
	candidates, stats, err := s.probeCandidatesWithStats(ctx, ips)
	if err != nil {
		s.emitProgress(FissionProgressEvent{Type: FissionProgressError, Error: err.Error()})
		return nil, err
	}
	result := &FissionRunResult{IPs: ips, Rounds: rounds, Candidates: candidates, ProbeStats: stats}
	s.emitProgress(FissionProgressEvent{
		Type:     FissionProgressDone,
		IPs:      slices.Clone(ips),
		TotalIPs: len(ips),
		Result:   result,
	})
	return result, nil
}

func (s *FissionService) filterCloudflareIPs(ctx context.Context, ips []string) ([]string, error) {
	s.emitProgress(FissionProgressEvent{
		Type:     FissionProgressCloudflareValidationStart,
		IPs:      slices.Clone(ips),
		TotalIPs: len(ips),
	})

	ranges, err := s.LoadCloudflareRanges(ctx)
	if err != nil {
		return nil, fmt.Errorf("加载 Cloudflare IP 段失败: %w", err)
	}
	filtered := ranges.filter(ips)
	slices.Sort(filtered)
	v4Count, v6Count := ranges.stats()
	hitRate := 0.0
	if len(ips) > 0 {
		hitRate = float64(len(filtered)) / float64(len(ips))
	}
	s.emitProgress(FissionProgressEvent{
		Type:                 FissionProgressCloudflareValidationDone,
		IPs:                  slices.Clone(ips),
		FilteredIPs:          slices.Clone(filtered),
		TotalIPs:             len(ips),
		CloudflareIPv4Ranges: v4Count,
		CloudflareIPv6Ranges: v6Count,
		CloudflareHitRate:    hitRate,
	})
	if len(filtered) == 0 {
		return nil, fmt.Errorf("未发现有效的 Cloudflare IP")
	}
	return filtered, nil
}

func (s *FissionService) loadCloudflareRanges(ctx context.Context) (cloudflareRanges, error) {
	cache := s.cloudflareCache
	if cache == nil {
		cache = defaultCloudflareRangeCache
	}
	return cache.Load(ctx)
}

func (s *FissionService) probeCandidates(ctx context.Context, ips []string) ([]CandidateResult, error) {
	candidates, _, err := s.probeCandidatesWithStats(ctx, ips)
	return candidates, err
}

func (s *FissionService) probeCandidatesWithStats(ctx context.Context, ips []string) ([]CandidateResult, *ProbeStats, error) {
	stats := &ProbeStats{TotalProbes: len(ips)}
	s.emitProgress(FissionProgressEvent{
		Type:       FissionProgressProbeStart,
		IPs:        slices.Clone(ips),
		TotalIPs:   len(ips),
		ProbePort:  s.Config.ProbePort,
		ProbeCount: s.Config.ProbeCount,
	})

	candidates := s.probePipeline(ctx, ips, stats)
	if err := ctx.Err(); err != nil {
		return nil, stats, err
	}

	emittedProbeResults := s.measureTopDownloadCandidates(ctx, candidates, stats)
	for i := range candidates {
		if candidates[i].Score == 0 {
			candidates[i].Score = scoreCandidateWithConfig(candidates[i].AvgLatencyMS, candidates[i].SuccessRate, candidates[i].DownloadMBps, s.Config)
		}
	}
	slices.SortFunc(candidates, compareCandidateForFinal)
	for _, candidate := range candidates {
		if _, ok := emittedProbeResults[candidate.IP]; ok {
			continue
		}
		s.emitProbeResult(candidate)
	}
	s.emitProgress(FissionProgressEvent{
		Type:       FissionProgressProbeDone,
		TotalIPs:   len(candidates),
		ProbeStats: stats,
	})
	return candidates, stats, nil
}

func (s *FissionService) probePipeline(ctx context.Context, ips []string, stats *ProbeStats) []CandidateResult {
	if !s.useStagedScan(len(ips)) {
		results := s.tcpProbeWithAttempts(ctx, ips, s.Config.ProbeCount, "full")
		recordTCPPhaseStats(stats, results)
		successful, failed := splitProbeResults(results, stats)
		stats.SuccessCount = len(successful)
		return append(successful, failed...)
	}

	stats.StagedScan = true
	quickResults := s.tcpProbeWithAttempts(ctx, ips, 1, "quick")
	recordTCPPhaseStats(stats, quickResults)
	stats.QuickStageCount = len(quickResults)
	quickSuccessful, quickFailed := splitProbeResults(quickResults, stats)
	if len(quickSuccessful) == 0 {
		return quickFailed
	}

	quickPool := selectTopCandidateResults(quickSuccessful, s.effectiveQuickTCPCount(len(quickSuccessful)))
	fullPool := selectTopCandidateResults(quickPool, s.effectiveLatencyCheckCount(len(quickPool)))
	if len(fullPool) == 0 {
		stats.SuccessCount = len(quickPool)
		return append(quickPool, quickFailed...)
	}

	fullResults := s.tcpProbeWithAttempts(ctx, candidateResultsToIPs(fullPool), s.Config.ProbeCount, "full")
	recordTCPPhaseStats(stats, fullResults)
	stats.FullStageCount = len(fullResults)
	fullSuccessful, fullFailed := splitProbeResults(fullResults, stats)
	if len(fullSuccessful) == 0 {
		stats.SuccessCount = len(quickPool)
		return append(append([]CandidateResult{}, quickPool...), append(quickFailed, fullFailed...)...)
	}
	stats.SuccessCount = len(fullSuccessful)
	return append(append([]CandidateResult{}, fullSuccessful...), append(quickFailed, fullFailed...)...)
}

func (s *FissionService) useStagedScan(candidateCount int) bool {
	return s.Config.StagedScanEnabled && candidateCount > 0
}

func (s *FissionService) effectiveQuickTCPCount(candidateCount int) int {
	if candidateCount <= 0 {
		return 0
	}
	return min(candidateCount, s.Config.QuickTCPCount)
}

func (s *FissionService) effectiveLatencyCheckCount(candidateCount int) int {
	if candidateCount <= 0 {
		return 0
	}
	return min(candidateCount, s.Config.LatencyCheckCount)
}

func (s *FissionService) tcpProbeWithAttempts(ctx context.Context, ips []string, attempts int, stage string) []CandidateResult {
	if len(ips) == 0 {
		return nil
	}
	workerCount := max(8, min(s.Config.Concurrency, 1000))
	s.emitProgress(FissionProgressEvent{
		Type:       FissionProgressProbeStageStart,
		Stage:      stage,
		IPs:        slices.Clone(ips),
		TotalIPs:   len(ips),
		ProbePort:  s.Config.ProbePort,
		ProbeCount: attempts,
		Workers:    workerCount,
	})

	jobs := make(chan string, workerCount*2)
	results := make(chan CandidateResult, len(ips))
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				results <- s.probeIPForAttempts(ctx, ip, attempts)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, ip := range ips {
			select {
			case <-ctx.Done():
				return
			case jobs <- ip:
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	out := make([]CandidateResult, 0, len(ips))
	for result := range results {
		out = append(out, result)
	}
	s.emitProgress(FissionProgressEvent{
		Type:       FissionProgressProbeStageDone,
		Stage:      stage,
		TotalIPs:   len(ips),
		Done:       len(out),
		ProbeCount: attempts,
	})
	return out
}

func (s *FissionService) probeIPForAttempts(ctx context.Context, ip string, attempts int) CandidateResult {
	var result CandidateResult
	if s.ProbeIPWithAttempts != nil {
		result = s.ProbeIPWithAttempts(ctx, ip, attempts)
	} else if s.ProbeIP != nil {
		result = s.ProbeIP(ctx, ip)
	} else {
		result = s.probeIPWithAttempts(ctx, ip, attempts)
	}
	if result.IP == "" {
		result.IP = ip
	}
	if result.Family == "" {
		result.Family = ipFamily(ip)
	}
	if result.Attempts == 0 {
		result.Attempts = max(1, attempts)
	}
	if result.SuccessRate == 0 && result.Attempts > 0 && result.Successes > 0 {
		result.SuccessRate = float64(result.Successes) / float64(result.Attempts)
	}
	return result
}

func splitProbeResults(results []CandidateResult, stats *ProbeStats) ([]CandidateResult, []CandidateResult) {
	successful := make([]CandidateResult, 0, len(results))
	failed := make([]CandidateResult, 0, len(results))
	for _, result := range results {
		if stats != nil {
			stats.TimeoutCount += result.TimeoutCount
			stats.RefusedCount += result.RefusedCount
			stats.OtherErrorCount += result.OtherErrors
		}
		if result.Successes > 0 {
			successful = append(successful, result)
			continue
		}
		failed = append(failed, result)
	}
	return successful, failed
}

func recordTCPPhaseStats(stats *ProbeStats, results []CandidateResult) {
	if stats == nil {
		return
	}
	for _, result := range results {
		stats.TCPDialAttempts += result.Attempts
	}
}

func selectTopCandidateResults(results []CandidateResult, limit int) []CandidateResult {
	if len(results) == 0 || limit <= 0 {
		return nil
	}
	grouped := make(map[string][]CandidateResult)
	families := make([]string, 0, 2)
	for _, result := range results {
		if _, ok := grouped[result.Family]; !ok {
			families = append(families, result.Family)
		}
		grouped[result.Family] = append(grouped[result.Family], result)
	}
	slices.Sort(families)
	for _, family := range families {
		slices.SortFunc(grouped[family], compareCandidateForHTTP)
	}
	if limit >= len(results) {
		out := make([]CandidateResult, 0, len(results))
		for _, family := range families {
			out = append(out, grouped[family]...)
		}
		return out
	}
	indices := make(map[string]int, len(families))
	out := make([]CandidateResult, 0, limit)
	for len(out) < limit {
		progressed := false
		for _, family := range families {
			index := indices[family]
			if index >= len(grouped[family]) {
				continue
			}
			out = append(out, grouped[family][index])
			indices[family] = index + 1
			progressed = true
			if len(out) == limit {
				break
			}
		}
		if !progressed {
			break
		}
	}
	return out
}

func candidateResultsToIPs(results []CandidateResult) []string {
	ips := make([]string, 0, len(results))
	for _, result := range results {
		ips = append(ips, result.IP)
	}
	return ips
}

func (s *FissionService) measureTopDownloadCandidates(ctx context.Context, candidates []CandidateResult, stats *ProbeStats) map[string]struct{} {
	emitted := make(map[string]struct{})
	if !httpTestEnabled(s.Config) || strings.TrimSpace(s.Config.HTTPTestURL) == "" || s.MeasureDownload == nil {
		return emitted
	}

	familyGroups := make(map[string][]int)
	for index, candidate := range candidates {
		if candidate.Successes <= 0 || candidate.Score != 0 {
			continue
		}
		familyGroups[candidate.Family] = append(familyGroups[candidate.Family], index)
	}
	if len(familyGroups) == 0 {
		return emitted
	}

	families := make([]string, 0, len(familyGroups))
	for family := range familyGroups {
		families = append(families, family)
	}
	slices.Sort(families)
	for _, family := range families {
		slices.SortFunc(familyGroups[family], func(a, b int) int {
			return compareCandidateForHTTP(candidates[a], candidates[b])
		})
	}

	totalBudget := max(20, s.Config.ResultCount*3)
	perFamilyBudget := totalBudget / max(1, len(families))
	minCandidatesThreshold := max(5, s.Config.ResultCount/2)
	indexes := make([]int, 0, totalBudget)
	for _, family := range families {
		group := familyGroups[family]
		if len(group) < minCandidatesThreshold {
			continue
		}
		takeCount := min(len(group), perFamilyBudget)
		indexes = append(indexes, group[:takeCount]...)
	}
	if len(indexes) == 0 {
		return emitted
	}

	workerCount := s.httpProbeWorkerCount(len(indexes))
	jobs := make(chan int, len(indexes))
	type result struct {
		index int
		mbps  float64
	}
	results := make(chan result, len(indexes))
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				results <- result{index: index, mbps: s.MeasureDownload(ctx, candidates[index].IP)}
			}
		}()
	}

	startedAt := time.Now()
	if stats != nil {
		stats.HTTPTestCount = len(indexes)
	}
	for _, index := range indexes {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			close(results)
			return emitted
		case jobs <- index:
		}
	}
	close(jobs)
	go func() {
		wg.Wait()
		close(results)
	}()
	for result := range results {
		candidates[result.index].DownloadMBps = result.mbps
		candidates[result.index].Score = scoreCandidateWithConfig(candidates[result.index].AvgLatencyMS, candidates[result.index].SuccessRate, candidates[result.index].DownloadMBps, s.Config)
		if stats != nil {
			if result.mbps > 0 {
				stats.HTTPSuccessCount++
			} else {
				stats.HTTPFailCount++
			}
		}
		s.emitProbeResult(candidates[result.index])
		emitted[candidates[result.index].IP] = struct{}{}
	}
	if stats != nil {
		stats.HTTPDuration = time.Since(startedAt)
	}
	return emitted
}

func compareCandidateForHTTP(a, b CandidateResult) int {
	if a.SuccessRate > b.SuccessRate {
		return -1
	}
	if a.SuccessRate < b.SuccessRate {
		return 1
	}
	if a.AvgLatencyMS > 0 && (b.AvgLatencyMS == 0 || a.AvgLatencyMS < b.AvgLatencyMS) {
		return -1
	}
	if b.AvgLatencyMS > 0 && (a.AvgLatencyMS == 0 || b.AvgLatencyMS < a.AvgLatencyMS) {
		return 1
	}
	return strings.Compare(a.IP, b.IP)
}

func compareCandidateForFinal(a, b CandidateResult) int {
	if a.Score > b.Score {
		return -1
	}
	if a.Score < b.Score {
		return 1
	}
	return compareCandidateForHTTP(a, b)
}

func (s *FissionService) httpProbeWorkerCount(candidateCount int) int {
	if candidateCount <= 0 {
		return 0
	}
	workers := max(1, s.Config.Concurrency/32)
	workers = min(workers, 8)
	return min(candidateCount, workers)
}

func (s *FissionService) emitProgress(event FissionProgressEvent) {
	if s.Progress == nil {
		return
	}
	s.Progress(event)
}

func (s *FissionService) emitProbeResult(candidate CandidateResult) {
	eventCandidate := candidate
	s.emitProgress(FissionProgressEvent{
		Type:      FissionProgressProbeResult,
		IP:        candidate.IP,
		Candidate: &eventCandidate,
	})
}

func (s *FissionService) probeIP(ctx context.Context, ip string) CandidateResult {
	return s.probeIPWithAttempts(ctx, ip, s.Config.ProbeCount)
}

func (s *FissionService) probeIPWithAttempts(ctx context.Context, ip string, attemptCount int) CandidateResult {
	attempts := max(1, attemptCount)
	baseTimeout := time.Duration(max(200, s.Config.TimeoutMS)) * time.Millisecond
	latencies := make([]float64, 0, attempts)
	timeoutCount := 0
	refusedCount := 0
	otherErrors := 0
	for attempt := 0; attempt < attempts; attempt++ {
		timeout := baseTimeout
		if attempt > 0 && len(latencies) == 0 {
			timeout += time.Duration(attempt*100) * time.Millisecond
		}
		startedAt := time.Now()
		err := s.dialIPWithTimeout(ctx, ip, timeout)
		if err == nil {
			latencies = append(latencies, float64(time.Since(startedAt).Microseconds())/1000)
			continue
		}
		if errors.Is(err, context.DeadlineExceeded) || isTimeoutError(err) {
			timeoutCount++
		} else if isRefusedError(err) {
			refusedCount++
		} else {
			otherErrors++
		}
	}

	avgLatencyMS := 0.0
	p95LatencyMS := 0.0
	if len(latencies) > 0 {
		slices.Sort(latencies)
		totalLatencyMS := 0.0
		for _, latency := range latencies {
			totalLatencyMS += latency
		}
		avgLatencyMS = totalLatencyMS / float64(len(latencies))
		p95LatencyMS = latencies[min(len(latencies)-1, int(float64(len(latencies))*0.95))]
	}
	successes := len(latencies)
	successRate := float64(successes) / float64(attempts)

	return CandidateResult{
		Family:       ipFamily(ip),
		IP:           ip,
		Attempts:     attempts,
		Successes:    successes,
		AvgLatencyMS: avgLatencyMS,
		P95LatencyMS: p95LatencyMS,
		SuccessRate:  successRate,
		TimeoutCount: timeoutCount,
		RefusedCount: refusedCount,
		OtherErrors:  otherErrors,
	}
}

func (s *FissionService) dialIP(ctx context.Context, ip string) error {
	return s.dialIPWithTimeout(ctx, ip, time.Duration(max(200, s.Config.TimeoutMS))*time.Millisecond)
}

func (s *FissionService) dialIPWithTimeout(ctx context.Context, ip string, timeout time.Duration) error {
	if s.DialIP != nil {
		return s.DialIP(ctx, ip, timeout)
	}
	conn, err := (&net.Dialer{
		Timeout:   timeout,
		KeepAlive: -1,
	}).DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(s.Config.ProbePort)))
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func (s *FissionService) measureDownload(ctx context.Context, ip string) float64 {
	testURL := strings.TrimSpace(s.Config.HTTPTestURL)
	parsedURL, err := url.Parse(testURL)
	if err != nil || parsedURL.Hostname() == "" {
		return 0
	}

	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}

	timeout := time.Duration(max(1, s.Config.HTTPTestSeconds)) * time.Second
	dialer := &net.Dialer{Timeout: 1500 * time.Millisecond}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
		},
		TLSClientConfig:   &tls.Config{ServerName: parsedURL.Hostname()},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		return 0
	}
	req.Host = parsedURL.Hostname()
	req.Header.Set("User-Agent", "bestipd/1.0")

	startedAt := time.Now()
	resp, err := (&http.Client{Transport: transport, Timeout: timeout + time.Second}).Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return 0
	}

	deadline := startedAt.Add(timeout)
	var bytesRead int64
	buf := make([]byte, 64*1024)
	for time.Now().Before(deadline) {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			bytesRead += int64(n)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			break
		}
	}
	elapsed := time.Since(startedAt).Seconds()
	if elapsed <= 0 || bytesRead <= 0 {
		return 0
	}
	return float64(bytesRead) / 1024 / 1024 / elapsed
}

func scoreCandidate(avgLatencyMS, successRate, downloadMBps float64) float64 {
	return scoreCandidateWithWeights(avgLatencyMS, successRate, downloadMBps, scoreLatencyWeight, scoreSuccessRateWeight, scoreDownloadWeight)
}

func scoreCandidateWithConfig(avgLatencyMS, successRate, downloadMBps float64, config FissionConfig) float64 {
	return scoreCandidateWithWeights(avgLatencyMS, successRate, downloadMBps, config.WeightLatency, config.WeightSuccessRate, config.WeightDownload)
}

func scoreCandidateWithWeights(avgLatencyMS, successRate, downloadMBps float64, latencyWeight, successRateWeight, downloadWeight float64) float64 {
	latencyScore := 0.0
	if avgLatencyMS > 0 {
		latencyScore = 1 - math.Min(avgLatencyMS/500, 1)
	}
	downloadScore := math.Min(downloadMBps/downloadScoreBaselineMBps, 1)
	score := latencyScore*latencyWeight + successRate*successRateWeight + downloadScore*downloadWeight
	if score < 0 {
		return 0
	}
	return score
}

func httpTestEnabled(config FissionConfig) bool {
	return config.HTTPTestEnabled == nil || *config.HTTPTestEnabled
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	errText := strings.ToLower(err.Error())
	return strings.Contains(errText, "timeout") || strings.Contains(errText, "i/o timeout")
}

func isRefusedError(err error) bool {
	if err == nil {
		return false
	}
	errText := strings.ToLower(err.Error())
	return strings.Contains(errText, "connection refused") || strings.Contains(errText, "actively refused") || strings.Contains(errText, "refused")
}

func ipFamily(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	if addr.Is6() {
		return "ipv6"
	}
	return "ipv4"
}

func (s *FissionService) ipToDomains(ctx context.Context, ips []string, round int) []string {
	var mu sync.Mutex
	domainSet := map[string]struct{}{}
	sem := make(chan struct{}, max(1, s.Config.Concurrency))
	var wg sync.WaitGroup

	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			s.emitProgress(FissionProgressEvent{Type: FissionProgressIPLookupStart, Round: round, IP: ip})
			domains := s.LookupDomains(ctx, ip)
			s.emitProgress(FissionProgressEvent{
				Type:    FissionProgressIPLookupDone,
				Round:   round,
				IP:      ip,
				Domains: slices.Clone(domains),
			})
			for _, domain := range domains {
				domain = strings.ToLower(strings.TrimSpace(domain))
				if !isValidDomain(domain) {
					continue
				}
				mu.Lock()
				if len(domainSet) < s.Config.MaxDomains {
					domainSet[domain] = struct{}{}
				}
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()
	out := keys(domainSet)
	slices.Sort(out)
	return out
}

func (s *FissionService) domainsToIPs(ctx context.Context, domains []string, round int) []string {
	var mu sync.Mutex
	ipSet := map[string]struct{}{}
	sem := make(chan struct{}, max(1, s.Config.Concurrency))
	var wg sync.WaitGroup

	for _, domain := range domains {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			s.emitProgress(FissionProgressEvent{Type: FissionProgressDomainResolveStart, Round: round, Domain: domain})
			ips := s.ResolveDomain(ctx, domain)
			s.emitProgress(FissionProgressEvent{
				Type:   FissionProgressDomainResolveDone,
				Round:  round,
				Domain: domain,
				IPs:    slices.Clone(ips),
			})
			for _, ip := range ips {
				addr, err := netip.ParseAddr(ip)
				if err != nil {
					continue
				}
				if addr.Is4() && !slices.Contains(s.Config.Families, "ipv4") {
					continue
				}
				if addr.Is6() && !slices.Contains(s.Config.Families, "ipv6") {
					continue
				}
				mu.Lock()
				ipSet[addr.String()] = struct{}{}
				mu.Unlock()
			}
		}(domain)
	}
	wg.Wait()
	return keys(ipSet)
}

func (s *FissionService) lookupDomains(ctx context.Context, ip string) []string {
	return s.queryDomainsForIP(ctx, ip)
}

func (s *FissionService) defaultDomainLookupSources() []domainLookupSource {
	return []domainLookupSource{
		{
			name: "rapiddns",
			url: func(ip string) string {
				return fmt.Sprintf("https://rapiddns.io/sameip/%s?full=1", url.PathEscape(ip))
			},
			parse: parseRapidDNSDomains,
		},
		{
			name: "ip138",
			url: func(ip string) string {
				return fmt.Sprintf("https://site.ip138.com/%s/", url.PathEscape(ip))
			},
			parse: parseIP138Domains,
		},
		{
			name: "ipchaxun",
			url: func(ip string) string {
				return fmt.Sprintf("https://ipchaxun.com/%s/", url.PathEscape(ip))
			},
			parse: parseIPChaxunDomains,
		},
	}
}

func (s *FissionService) domainLookupSources() []domainLookupSource {
	if len(s.sources) > 0 {
		return s.sources
	}
	return s.defaultDomainLookupSources()
}

func (s *FissionService) queryDomainsForIP(ctx context.Context, ip string) []string {
	s.mu.RLock()
	if cached, ok := s.domainCache[ip]; ok {
		s.mu.RUnlock()
		return slices.Clone(cached)
	}
	s.mu.RUnlock()

	var result []string
	cacheable := false
	for index, source := range s.domainLookupSources() {
		sourceURL := source.url(ip)
		s.emitProgress(FissionProgressEvent{Type: FissionProgressLookupSourceStart, IP: ip, Source: source.name})

		s.mu.RLock()
		entry, ok := s.requestCache[sourceURL]
		cacheFresh := ok && s.now().Sub(entry.timestamp) < sourceRequestCacheTTL
		s.mu.RUnlock()
		if cacheFresh {
			s.recordSourceCacheHit(source.name)
			domains := source.parse(entry.body, ip)
			s.emitLookupSourceDone(ip, source.name, 0, domains, "")
			cacheable = true
			if len(domains) > 0 {
				result = slices.Clone(domains)
				break
			}
			continue
		}

		if s.shouldSkipSource(source.name) {
			s.emitLookupSourceDone(ip, source.name, 0, nil, "circuit open")
			continue
		}

		if delay := s.sourceBackoffDelay(source.name); delay > 0 {
			select {
			case <-ctx.Done():
				s.emitLookupSourceDone(ip, source.name, 0, nil, ctx.Err().Error())
				return result
			case <-time.After(delay):
			}
		} else if index > 0 {
			select {
			case <-ctx.Done():
				s.emitLookupSourceDone(ip, source.name, 0, nil, ctx.Err().Error())
				return result
			case <-time.After(sourceBackoffBase):
			}
		}

		body, err := s.fetch(ctx, sourceURL)
		if err != nil {
			s.recordSourceFailure(source.name, err)
			s.emitLookupSourceDone(ip, source.name, statusCodeFromError(err), nil, err.Error())
			continue
		}

		s.mu.Lock()
		s.requestCache[sourceURL] = cacheEntry{body: body, timestamp: s.now()}
		s.mu.Unlock()
		cacheable = true

		domains := source.parse(body, ip)
		if len(domains) > 0 {
			s.recordSourceSuccess(source.name)
			s.emitLookupSourceDone(ip, source.name, http.StatusOK, domains, "")
			result = slices.Clone(domains)
			break
		}
		s.recordSourceEmptyResult(source.name)
		s.emitLookupSourceDone(ip, source.name, http.StatusOK, domains, "")
	}

	if cacheable {
		s.mu.Lock()
		s.domainCache[ip] = slices.Clone(result)
		s.mu.Unlock()
	}
	return result
}

func (s *FissionService) fetchDomainLookupURL(ctx context.Context, sourceURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", domainLookupUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Connection", "keep-alive")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 10*1024*1024))
		return "", httpStatusError{StatusCode: resp.StatusCode}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (s *FissionService) emitLookupSourceDone(ip, source string, statusCode int, domains []string, errorText string) {
	s.emitProgress(FissionProgressEvent{
		Type:         FissionProgressLookupSourceDone,
		IP:           ip,
		Source:       source,
		StatusCode:   statusCode,
		Domains:      slices.Clone(domains),
		TotalDomains: len(domains),
		Error:        errorText,
	})
}

func statusCodeFromError(err error) int {
	var statusErr httpStatusError
	if errors.As(err, &statusErr) {
		return statusErr.StatusCode
	}
	return 0
}

func (s *FissionService) sourceState(name string) *sourceRuntimeState {
	state, ok := s.sourceStats[name]
	if !ok {
		state = &sourceRuntimeState{}
		s.sourceStats[name] = state
	}
	return state
}

func (s *FissionService) recordSourceCacheHit(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sourceState(name).CacheHits++
}

func (s *FissionService) shouldSkipSource(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.sourceState(name)
	now := s.now()
	if state.CircuitOpenUntil.After(now) {
		state.CircuitSkips++
		return true
	}
	if !state.CircuitOpenUntil.IsZero() && !state.CircuitOpenUntil.After(now) {
		state.CircuitOpenUntil = time.Time{}
	}
	return false
}

func (s *FissionService) sourceBackoffDelay(name string) time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.sourceStats[name]
	if !ok || state.ConsecutiveFailures <= 0 {
		return 0
	}
	delay := time.Duration(state.ConsecutiveFailures) * sourceBackoffBase
	if delay > sourceBackoffMax {
		return sourceBackoffMax
	}
	return delay
}

func (s *FissionService) recordSourceSuccess(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.sourceState(name)
	state.Requests++
	state.Successes++
	state.ConsecutiveFailures = 0
	state.CircuitOpenUntil = time.Time{}
	state.LastError = ""
}

func (s *FissionService) recordSourceEmptyResult(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.sourceState(name)
	state.Requests++
	state.EmptyResults++
	state.ConsecutiveFailures = 0
	state.CircuitOpenUntil = time.Time{}
	state.LastError = ""
}

func (s *FissionService) recordSourceFailure(name string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.sourceState(name)
	state.Requests++
	state.Failures++
	state.ConsecutiveFailures++
	if err != nil {
		state.LastError = err.Error()
	}
	if state.ConsecutiveFailures >= sourceFailureThreshold {
		state.CircuitOpenUntil = s.now().Add(sourceCircuitOpenDuration)
	}
}

func (s *FissionService) SourceStatsSnapshot() map[string]SourceStatsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]SourceStatsSnapshot, len(s.sourceStats))
	for name, state := range s.sourceStats {
		out[name] = SourceStatsSnapshot{
			Requests:            state.Requests,
			CacheHits:           state.CacheHits,
			Successes:           state.Successes,
			EmptyResults:        state.EmptyResults,
			Failures:            state.Failures,
			CircuitSkips:        state.CircuitSkips,
			ConsecutiveFailures: state.ConsecutiveFailures,
			CircuitOpenUntil:    state.CircuitOpenUntil,
			LastError:           state.LastError,
		}
	}
	return out
}

func (s *FissionService) resolveDomain(ctx context.Context, domain string) []string {
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(s.Config.TimeoutMS)*time.Millisecond)
	defer cancel()

	out := []string{}
	resolver := net.Resolver{}
	if slices.Contains(s.Config.Families, "ipv4") {
		if ips, err := resolver.LookupIP(timeoutCtx, "ip4", domain); err == nil {
			for _, ip := range ips {
				if ip.To4() != nil && isPublicIP(ip) {
					out = append(out, ip.String())
				}
			}
		}
	}
	if slices.Contains(s.Config.Families, "ipv6") {
		if ips, err := resolver.LookupIP(timeoutCtx, "ip6", domain); err == nil {
			for _, ip := range ips {
				if ip.To4() == nil && isPublicIP(ip) {
					out = append(out, ip.String())
				}
			}
		}
	}
	return out
}

func parseIP138Domains(body string, ip string) []string {
	return extractReverseIPDomains(body, ip)
}

func parseIPChaxunDomains(body string, ip string) []string {
	return extractReverseIPDomains(body, ip)
}

func parseRapidDNSDomains(body string, ip string) []string {
	return extractRapidDNSDomains(body, ip)
}

func extractReverseIPDomains(body string, ip string) []string {
	sections := []string{}
	for _, section := range []string{
		extractElementByID(body, "ul", "list"),
		extractElementByID(body, "div", "J_domain"),
	} {
		if section != "" {
			sections = append(sections, section)
		}
	}
	if len(sections) > 0 {
		return extractDomains(strings.Join(sections, "\n"))
	}

	if rapidDomains := extractRapidDNSDomains(body, ip); len(rapidDomains) > 0 {
		return rapidDomains
	}

	return extractDomains(body)
}

func extractElementByID(body, tag, id string) string {
	pattern := fmt.Sprintf(`(?is)<%s\b[^>]*\bid=["']%s["'][^>]*>.*?</%s>`, regexp.QuoteMeta(tag), regexp.QuoteMeta(id), regexp.QuoteMeta(tag))
	match := regexp.MustCompile(pattern).FindString(body)
	return match
}

func extractRapidDNSDomains(body string, ip string) []string {
	set := map[string]struct{}{}
	for _, row := range tableRowRe.FindAllString(body, -1) {
		if !strings.Contains(row, ip) {
			continue
		}
		cells := tableCellRe.FindAllStringSubmatch(row, -1)
		if len(cells) < 2 {
			continue
		}
		if strings.TrimSpace(stripHTML(cells[1][1])) != ip {
			continue
		}
		for _, domain := range extractDomains(cells[0][1]) {
			set[domain] = struct{}{}
		}
	}
	out := keys(set)
	slices.Sort(out)
	return out
}

func stripHTML(value string) string {
	return strings.TrimSpace(html.UnescapeString(htmlTagRe.ReplaceAllString(value, "")))
}

func extractDomains(body string) []string {
	body = html.UnescapeString(body)
	matches := domainRe.FindAllString(body, -1)
	set := map[string]struct{}{}
	for _, match := range matches {
		domain := strings.ToLower(strings.Trim(strings.TrimSpace(match), "./"))
		if isValidDomain(domain) {
			set[domain] = struct{}{}
		}
	}
	out := keys(set)
	slices.Sort(out)
	return out
}

func normalizeFamilies(families []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, family := range families {
		family = strings.ToLower(strings.TrimSpace(family))
		if family != "ipv4" && family != "ipv6" {
			continue
		}
		if _, ok := seen[family]; ok {
			continue
		}
		seen[family] = struct{}{}
		out = append(out, family)
	}
	if len(out) == 0 {
		return []string{"ipv4"}
	}
	return out
}

func isValidDomain(domain string) bool {
	if len(domain) < 4 || len(domain) > 253 {
		return false
	}
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
	}
	return true
}

func isPublicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !addr.IsMulticast()
}

func keys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	return out
}
