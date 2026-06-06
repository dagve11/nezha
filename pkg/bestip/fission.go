package bestip

import (
	"context"
	"fmt"
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
	SeedIPs         []string `json:"seed_ips"`
	Rounds          int      `json:"rounds"`
	Concurrency     int      `json:"concurrency"`
	TimeoutMS       int      `json:"timeout_ms"`
	MaxDomains      int      `json:"max_domains"`
	MaxIPsPerRound  int      `json:"max_ips_per_round"`
	Families        []string `json:"families"`
	ProbePort       int      `json:"probe_port"`
	ProbeCount      int      `json:"probe_count"`
	HTTPTestURL     string   `json:"http_test_url,omitempty"`
	HTTPTestSeconds int      `json:"http_test_seconds"`
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
}

type CandidateResult struct {
	Family       string  `json:"family"`
	IP           string  `json:"ip"`
	Attempts     int     `json:"attempts"`
	Successes    int     `json:"successes"`
	AvgLatencyMS float64 `json:"avg_latency_ms"`
	SuccessRate  float64 `json:"success_rate"`
	DownloadMBps float64 `json:"download_mbps"`
	Score        float64 `json:"score"`
}

type FissionService struct {
	Config        FissionConfig
	LookupDomains func(context.Context, string) []string
	ResolveDomain func(context.Context, string) []string
	ProbeIP       func(context.Context, string) CandidateResult

	client *http.Client
}

type domainLookupSource struct {
	url string
}

var domainRe = regexp.MustCompile(`(?i)([a-z0-9][-a-z0-9]*\.)+[a-z]{2,}`)

func NewFissionService(config FissionConfig) *FissionService {
	config, _ = NormalizeFissionConfig(config)
	timeout := time.Duration(config.TimeoutMS) * time.Millisecond
	service := &FissionService{
		Config: config,
		client: &http.Client{Timeout: timeout},
	}
	service.LookupDomains = service.lookupDomains
	service.ResolveDomain = service.resolveDomain
	service.ProbeIP = service.probeIP
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
	if config.HTTPTestSeconds <= 0 {
		config.HTTPTestSeconds = 3
	}
	if config.HTTPTestSeconds > 30 {
		config.HTTPTestSeconds = 30
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
		return nil, err
	}
	s.Config = config
	if s.ProbeIP == nil {
		s.ProbeIP = s.probeIP
	}

	ipSet := map[string]struct{}{}
	domainSet := map[string]struct{}{}
	for _, ip := range config.SeedIPs {
		ipSet[ip] = struct{}{}
	}

	currentIPs := slices.Clone(config.SeedIPs)
	rounds := make([]FissionRoundResult, 0, config.Rounds)
	for round := 1; round <= config.Rounds && len(currentIPs) > 0; round++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		discoveredDomains := s.ipToDomains(ctx, currentIPs)
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
		discoveredIPs := s.domainsToIPs(ctx, allDomains)
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

		rounds = append(rounds, FissionRoundResult{
			Round:        round,
			NewIPs:       newIPs,
			NewDomains:   newDomains,
			TotalIPs:     len(ipSet),
			TotalDomains: len(domainSet),
		})
		currentIPs = newIPs
	}

	ips := keys(ipSet)
	slices.Sort(ips)
	candidates, err := s.probeCandidates(ctx, ips)
	if err != nil {
		return nil, err
	}
	return &FissionRunResult{IPs: ips, Rounds: rounds, Candidates: candidates}, nil
}

func (s *FissionService) probeCandidates(ctx context.Context, ips []string) ([]CandidateResult, error) {
	candidates := make([]CandidateResult, len(ips))
	sem := make(chan struct{}, max(1, s.Config.Concurrency))
	var wg sync.WaitGroup

	for index, ip := range ips {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		wg.Add(1)
		go func(index int, ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := s.ProbeIP(ctx, ip)
			if result.IP == "" {
				result.IP = ip
			}
			if result.Family == "" {
				result.Family = ipFamily(ip)
			}
			candidates[index] = result
		}(index, ip)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	slices.SortFunc(candidates, func(a, b CandidateResult) int {
		if a.Score > b.Score {
			return -1
		}
		if a.Score < b.Score {
			return 1
		}
		if a.SuccessRate > b.SuccessRate {
			return -1
		}
		if a.SuccessRate < b.SuccessRate {
			return 1
		}
		if a.AvgLatencyMS > 0 && (b.AvgLatencyMS == 0 || a.AvgLatencyMS < b.AvgLatencyMS) {
			return -1
		}
		if b.AvgLatencyMS > 0 && (a.AvgLatencyMS == 0 || a.AvgLatencyMS > b.AvgLatencyMS) {
			return 1
		}
		return strings.Compare(a.IP, b.IP)
	})
	return candidates, nil
}

func (s *FissionService) probeIP(ctx context.Context, ip string) CandidateResult {
	attempts := max(1, s.Config.ProbeCount)
	successes := 0
	var totalLatency time.Duration
	for range attempts {
		startedAt := time.Now()
		if err := s.dialIP(ctx, ip); err == nil {
			successes++
			totalLatency += time.Since(startedAt)
		}
	}

	avgLatencyMS := 0.0
	if successes > 0 {
		avgLatencyMS = float64(totalLatency.Microseconds()) / 1000 / float64(successes)
	}
	successRate := float64(successes) / float64(attempts)
	downloadMBps := 0.0
	if successes > 0 && strings.TrimSpace(s.Config.HTTPTestURL) != "" {
		downloadMBps = s.measureDownload(ctx, ip)
	}

	return CandidateResult{
		Family:       ipFamily(ip),
		IP:           ip,
		Attempts:     attempts,
		Successes:    successes,
		AvgLatencyMS: avgLatencyMS,
		SuccessRate:  successRate,
		DownloadMBps: downloadMBps,
		Score:        scoreCandidate(avgLatencyMS, successRate, downloadMBps),
	}
}

func (s *FissionService) dialIP(ctx context.Context, ip string) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(s.Config.TimeoutMS)*time.Millisecond)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(timeoutCtx, "tcp", net.JoinHostPort(ip, strconv.Itoa(s.Config.ProbePort)))
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

	timeout := time.Duration(s.Config.HTTPTestSeconds) * time.Second
	downloadCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	transport := &http.Transport{
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip, port))
		},
	}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequestWithContext(downloadCtx, http.MethodGet, testURL, nil)
	if err != nil {
		return 0
	}
	resp, err := (&http.Client{Transport: transport, Timeout: timeout}).Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return 0
	}

	startedAt := time.Now()
	bytesRead, _ := io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(startedAt).Seconds()
	if elapsed <= 0 || bytesRead <= 0 {
		return 0
	}
	return float64(bytesRead) / 1024 / 1024 / elapsed
}

func scoreCandidate(avgLatencyMS, successRate, downloadMBps float64) float64 {
	latencyScore := 0.0
	if avgLatencyMS > 0 {
		latencyScore = 1 - math.Min(avgLatencyMS/500, 1)
	}
	downloadScore := math.Min(downloadMBps/20, 1)
	score := latencyScore*0.5 + successRate*0.4 + downloadScore*0.1
	if score < 0 {
		return 0
	}
	return score
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

func (s *FissionService) ipToDomains(ctx context.Context, ips []string) []string {
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
			for _, domain := range s.LookupDomains(ctx, ip) {
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

func (s *FissionService) domainsToIPs(ctx context.Context, domains []string) []string {
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
			for _, ip := range s.ResolveDomain(ctx, domain) {
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
	sources := []string{
		fmt.Sprintf("https://site.ip138.com/%s/", ip),
		fmt.Sprintf("https://ipchaxun.com/%s/", ip),
	}
	for _, sourceURL := range sources {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
		if err != nil {
			continue
		}
		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if readErr != nil || resp.StatusCode >= http.StatusBadRequest {
			continue
		}
		domains := extractDomains(string(body))
		if len(domains) > 0 {
			return domains
		}
	}
	return nil
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

func extractDomains(body string) []string {
	matches := domainRe.FindAllString(body, -1)
	set := map[string]struct{}{}
	for _, match := range matches {
		domain := strings.ToLower(strings.TrimSpace(match))
		if isValidDomain(domain) {
			set[domain] = struct{}{}
		}
	}
	return keys(set)
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
