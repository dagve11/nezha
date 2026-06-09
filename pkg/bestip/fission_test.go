package bestip

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func boolPtr(value bool) *bool {
	return &value
}

func allowCloudflarePrefixes(service *FissionService, prefixes ...string) {
	ranges := cloudflareRanges{}
	for _, rawPrefix := range prefixes {
		prefix := netip.MustParsePrefix(rawPrefix)
		if prefix.Addr().Is4() {
			ranges.v4 = append(ranges.v4, prefix)
			continue
		}
		ranges.v6 = append(ranges.v6, prefix)
	}
	service.LoadCloudflareRanges = func(context.Context) (cloudflareRanges, error) {
		return ranges, nil
	}
}

func TestLookupDomainsSendsBrowserUserAgent(t *testing.T) {
	service := NewFissionService(FissionConfig{
		SeedIPs:        []string{"1.1.1.1"},
		Rounds:         1,
		Concurrency:    1,
		TimeoutMS:      1000,
		MaxDomains:     10,
		MaxIPsPerRound: 10,
		Families:       []string{"ipv4"},
	})
	service.client = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.UserAgent() == "" || strings.Contains(req.UserAgent(), "Go-http-client") {
				return &http.Response{
					StatusCode: http.StatusBadGateway,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("blocked")),
					Request:    req,
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`<a href="/domain/example.com">example.com</a>`)),
				Request:    req,
			}, nil
		}),
	}

	domains := service.lookupDomains(context.Background(), "1.1.1.1")

	require.Contains(t, domains, "example.com")
}

func TestLookupDomainsEmitsSourceProgressAndParsesReverseIPResults(t *testing.T) {
	service := NewFissionService(FissionConfig{
		SeedIPs:        []string{"104.18.42.54"},
		Rounds:         1,
		Concurrency:    1,
		TimeoutMS:      1000,
		MaxDomains:     10,
		MaxIPsPerRound: 10,
		Families:       []string{"ipv4"},
	})
	service.client = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Host {
			case "rapiddns.io":
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("<table></table>")),
					Request:    req,
				}, nil
			case "site.ip138.com":
				return &http.Response{
					StatusCode: http.StatusServiceUnavailable,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("blocked")),
					Request:    req,
				}, nil
			case "ipchaxun.com":
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body: io.NopCloser(strings.NewReader(`
						<div id="J_domain">
							<p><span class="date">2026-06-07</span><a href="/cloudflare.rainyfall.com/">cloudflare.rainyfall.com</a></p>
							<p><span class="date">2026-06-07</span><a href="/www.nexusmods.com/">www.nexusmods.com</a></p>
						</div>
						<div class="box"><a href="/latest-noise.example.com/">latest-noise.example.com</a></div>
					`)),
					Request: req,
				}, nil
			default:
				t.Fatalf("unexpected lookup source host: %s", req.URL.Host)
			}
			return nil, nil
		}),
	}
	events := []FissionProgressEvent{}
	service.Progress = func(event FissionProgressEvent) {
		events = append(events, event)
	}

	domains := service.lookupDomains(context.Background(), "104.18.42.54")

	require.Equal(t, []string{"cloudflare.rainyfall.com", "www.nexusmods.com"}, domains)
	require.NotContains(t, domains, "latest-noise.example.com")

	eventTypes := make([]string, 0, len(events))
	for _, event := range events {
		eventTypes = append(eventTypes, event.Type)
	}
	require.Contains(t, eventTypes, FissionProgressLookupSourceStart)
	require.Contains(t, eventTypes, FissionProgressLookupSourceDone)

	var failedSource FissionProgressEvent
	var successfulSource FissionProgressEvent
	for _, event := range events {
		if event.Type != FissionProgressLookupSourceDone {
			continue
		}
		if event.Source == "ip138" {
			failedSource = event
		}
		if event.Source == "ipchaxun" {
			successfulSource = event
		}
	}
	require.Equal(t, http.StatusServiceUnavailable, failedSource.StatusCode)
	require.Equal(t, http.StatusOK, successfulSource.StatusCode)
	require.Equal(t, []string{"cloudflare.rainyfall.com", "www.nexusmods.com"}, successfulSource.Domains)
}

func TestLookupDomainsFallsBackToRapidDNS(t *testing.T) {
	service := NewFissionService(FissionConfig{
		SeedIPs:        []string{"104.18.42.54"},
		Rounds:         1,
		Concurrency:    1,
		TimeoutMS:      1000,
		MaxDomains:     10,
		MaxIPsPerRound: 10,
		Families:       []string{"ipv4"},
	})
	service.client = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host != "rapiddns.io" {
				return &http.Response{
					StatusCode: http.StatusServiceUnavailable,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("blocked")),
					Request:    req,
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`
					<tr>
						<th scope="row">1</th>
						<td>staticdelivery.nexusmods.com</td>
						<td><a href="/sameip/104.18.42.54#result">104.18.42.54</a></td>
						<td>A</td>
					</tr>
				`)),
				Request: req,
			}, nil
		}),
	}

	domains := service.lookupDomains(context.Background(), "104.18.42.54")

	require.Equal(t, []string{"staticdelivery.nexusmods.com"}, domains)
}

func TestLookupDomainsUsesRapidDNSBeforeSlowOriginalSources(t *testing.T) {
	service := NewFissionService(FissionConfig{
		SeedIPs:        []string{"104.18.42.54"},
		Rounds:         1,
		Concurrency:    1,
		TimeoutMS:      1000,
		MaxDomains:     10,
		MaxIPsPerRound: 10,
		Families:       []string{"ipv4"},
	})

	requestedHosts := []string{}
	service.fetch = func(_ context.Context, sourceURL string) (string, error) {
		parsed, err := url.Parse(sourceURL)
		require.NoError(t, err)
		requestedHosts = append(requestedHosts, parsed.Host)
		if parsed.Host != "rapiddns.io" {
			return "", errors.New("slow source should not be requested")
		}
		return `
			<tr>
				<th scope="row">1</th>
				<td>staticdelivery.nexusmods.com</td>
				<td><a href="/sameip/104.18.42.54#result">104.18.42.54</a></td>
				<td>A</td>
			</tr>
		`, nil
	}

	domains := service.lookupDomains(context.Background(), "104.18.42.54")

	require.Equal(t, []string{"staticdelivery.nexusmods.com"}, domains)
	require.Equal(t, []string{"rapiddns.io"}, requestedHosts)
}

func TestQueryDomainsForIPDoesNotCachePureFailure(t *testing.T) {
	service := NewFissionService(FissionConfig{
		SeedIPs:        []string{"1.1.1.1"},
		Rounds:         1,
		Concurrency:    1,
		TimeoutMS:      1000,
		MaxDomains:     10,
		MaxIPsPerRound: 10,
		Families:       []string{"ipv4"},
	})
	service.sources = []domainLookupSource{{
		name: "mock",
		url: func(ip string) string {
			return "mock://" + ip
		},
		parse: func(body string, _ string) []string {
			return extractDomains(body)
		},
	}}

	callCount := 0
	service.fetch = func(_ context.Context, _ string) (string, error) {
		callCount++
		if callCount == 1 {
			return "", errors.New("temporary failure")
		}
		return `<a href="/domain/example.com">example.com</a>`, nil
	}

	require.Empty(t, service.queryDomainsForIP(context.Background(), "1.1.1.1"))
	require.Equal(t, []string{"example.com"}, service.queryDomainsForIP(context.Background(), "1.1.1.1"))
	require.Equal(t, 2, callCount)

	stats := service.SourceStatsSnapshot()
	require.Equal(t, 1, stats["mock"].Failures)
	require.Equal(t, 1, stats["mock"].Successes)
}

func TestQueryDomainsForIPCircuitBreakerSkipsFailingSource(t *testing.T) {
	service := NewFissionService(FissionConfig{
		SeedIPs:        []string{"1.1.1.1"},
		Rounds:         1,
		Concurrency:    1,
		TimeoutMS:      1000,
		MaxDomains:     10,
		MaxIPsPerRound: 10,
		Families:       []string{"ipv4"},
	})
	now := time.Unix(1700000000, 0)
	service.now = func() time.Time { return now }
	service.sources = []domainLookupSource{
		{
			name: "primary",
			url: func(ip string) string {
				return "primary://" + ip
			},
			parse: func(body string, _ string) []string {
				return extractDomains(body)
			},
		},
		{
			name: "fallback",
			url: func(ip string) string {
				return "fallback://" + ip
			},
			parse: func(body string, _ string) []string {
				return extractDomains(body)
			},
		},
	}

	primaryCalls := 0
	fallbackCalls := 0
	service.fetch = func(_ context.Context, sourceURL string) (string, error) {
		switch {
		case strings.HasPrefix(sourceURL, "primary://"):
			primaryCalls++
			return "", errors.New("primary down")
		case strings.HasPrefix(sourceURL, "fallback://"):
			fallbackCalls++
			return `<a href="/domain/example.com">example.com</a>`, nil
		default:
			return "", fmt.Errorf("unexpected url: %s", sourceURL)
		}
	}

	for i := 0; i < 3; i++ {
		ip := fmt.Sprintf("1.1.1.%d", i+1)
		require.Equal(t, []string{"example.com"}, service.queryDomainsForIP(context.Background(), ip))
	}
	require.Equal(t, []string{"example.com"}, service.queryDomainsForIP(context.Background(), "1.1.1.10"))
	require.Equal(t, 3, primaryCalls)
	require.Equal(t, 4, fallbackCalls)

	stats := service.SourceStatsSnapshot()
	require.Equal(t, 3, stats["primary"].Failures)
	require.Equal(t, 1, stats["primary"].CircuitSkips)

	now = now.Add(sourceCircuitOpenDuration + time.Second)
	require.Equal(t, []string{"example.com"}, service.queryDomainsForIP(context.Background(), "1.1.1.11"))
	require.Equal(t, 4, primaryCalls)
}

func TestFissionServiceExpandsSeedIPThroughDomains(t *testing.T) {
	service := NewFissionService(FissionConfig{
		SeedIPs:        []string{"1.1.1.1"},
		Rounds:         2,
		Concurrency:    2,
		TimeoutMS:      1000,
		MaxDomains:     10,
		MaxIPsPerRound: 10,
		Families:       []string{"ipv4"},
	})
	allowCloudflarePrefixes(service, "1.1.1.0/24", "1.0.0.0/24", "8.8.8.0/24")
	service.LookupDomains = func(_ context.Context, ip string) []string {
		switch ip {
		case "1.1.1.1":
			return []string{"one.example.com"}
		case "1.0.0.1":
			return []string{"two.example.com"}
		default:
			return nil
		}
	}
	service.ResolveDomain = func(_ context.Context, domain string) []string {
		switch domain {
		case "one.example.com":
			return []string{"1.0.0.1"}
		case "two.example.com":
			return []string{"8.8.8.8"}
		default:
			return nil
		}
	}
	service.ProbeIP = func(_ context.Context, ip string) CandidateResult {
		return CandidateResult{
			Family:       "ipv4",
			IP:           ip,
			Attempts:     1,
			Successes:    1,
			AvgLatencyMS: 10,
			SuccessRate:  1,
			Score:        0.9,
		}
	}

	result, err := service.Run(context.Background())
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"1.1.1.1", "1.0.0.1", "8.8.8.8"}, result.IPs)
	require.Len(t, result.Rounds, 2)
	require.ElementsMatch(t, []string{"1.0.0.1"}, result.Rounds[0].NewIPs)
	require.ElementsMatch(t, []string{"8.8.8.8"}, result.Rounds[1].NewIPs)
}

func TestFissionServiceFiltersCloudflareIPsBeforeProbe(t *testing.T) {
	service := NewFissionService(FissionConfig{
		SeedIPs:        []string{"104.18.42.54"},
		Rounds:         1,
		Concurrency:    2,
		TimeoutMS:      1000,
		MaxDomains:     10,
		MaxIPsPerRound: 10,
		Families:       []string{"ipv4"},
	})
	allowCloudflarePrefixes(service, "104.16.0.0/12")
	service.LookupDomains = func(_ context.Context, ip string) []string {
		require.Equal(t, "104.18.42.54", ip)
		return []string{"one.example.com"}
	}
	service.ResolveDomain = func(_ context.Context, domain string) []string {
		require.Equal(t, "one.example.com", domain)
		return []string{"104.18.43.1", "8.8.8.8"}
	}

	var mu sync.Mutex
	probed := []string{}
	service.ProbeIP = func(_ context.Context, ip string) CandidateResult {
		mu.Lock()
		defer mu.Unlock()
		probed = append(probed, ip)
		return CandidateResult{
			Family:       "ipv4",
			IP:           ip,
			Attempts:     1,
			Successes:    1,
			AvgLatencyMS: 10,
			SuccessRate:  1,
			Score:        0.9,
		}
	}

	events := []FissionProgressEvent{}
	service.Progress = func(event FissionProgressEvent) {
		events = append(events, event)
	}

	result, err := service.Run(context.Background())

	require.NoError(t, err)
	require.ElementsMatch(t, []string{"104.18.42.54", "104.18.43.1"}, result.IPs)
	require.ElementsMatch(t, []string{"104.18.42.54", "104.18.43.1"}, probed)
	require.NotContains(t, result.IPs, "8.8.8.8")

	var validationDone FissionProgressEvent
	for _, event := range events {
		if event.Type == FissionProgressCloudflareValidationDone {
			validationDone = event
			break
		}
	}
	require.Equal(t, 3, validationDone.TotalIPs)
	require.ElementsMatch(t, []string{"104.18.42.54", "104.18.43.1"}, validationDone.FilteredIPs)
	require.InDelta(t, 2.0/3.0, validationDone.CloudflareHitRate, 0.0001)
	require.Equal(t, 1, validationDone.CloudflareIPv4Ranges)
}

func TestFissionServiceReturnsErrorWhenNoCloudflareIPsRemain(t *testing.T) {
	service := NewFissionService(FissionConfig{
		SeedIPs:        []string{"8.8.8.8"},
		Rounds:         1,
		Concurrency:    1,
		TimeoutMS:      1000,
		MaxDomains:     10,
		MaxIPsPerRound: 10,
		Families:       []string{"ipv4"},
	})
	allowCloudflarePrefixes(service, "104.16.0.0/12")
	service.LookupDomains = func(context.Context, string) []string { return nil }
	service.ProbeIP = func(context.Context, string) CandidateResult {
		t.Fatal("probe must not run when Cloudflare filtering removes all IPs")
		return CandidateResult{}
	}

	_, err := service.Run(context.Background())

	require.ErrorContains(t, err, "Cloudflare IP")
}

func TestFissionServiceProbesAndSortsCandidatesByScore(t *testing.T) {
	service := NewFissionService(FissionConfig{
		SeedIPs:        []string{"1.1.1.1"},
		Rounds:         1,
		Concurrency:    2,
		TimeoutMS:      1000,
		MaxDomains:     10,
		MaxIPsPerRound: 10,
		Families:       []string{"ipv4"},
	})
	allowCloudflarePrefixes(service, "1.1.1.0/24", "1.0.0.0/24")
	service.LookupDomains = func(_ context.Context, ip string) []string {
		if ip == "1.1.1.1" {
			return []string{"one.example.com"}
		}
		return nil
	}
	service.ResolveDomain = func(_ context.Context, domain string) []string {
		if domain == "one.example.com" {
			return []string{"1.0.0.1"}
		}
		return nil
	}
	service.ProbeIP = func(_ context.Context, ip string) CandidateResult {
		switch ip {
		case "1.0.0.1":
			return CandidateResult{
				Family:       "ipv4",
				IP:           ip,
				Attempts:     3,
				Successes:    3,
				AvgLatencyMS: 10,
				SuccessRate:  1,
				DownloadMBps: 20,
				Score:        0.98,
			}
		default:
			return CandidateResult{
				Family:       "ipv4",
				IP:           ip,
				Attempts:     3,
				Successes:    1,
				AvgLatencyMS: 200,
				SuccessRate:  0.33,
				DownloadMBps: 2,
				Score:        0.42,
			}
		}
	}

	result, err := service.Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"1.0.0.1", "1.1.1.1"}, []string{result.Candidates[0].IP, result.Candidates[1].IP})
	require.Equal(t, 10.0, result.Candidates[0].AvgLatencyMS)
	require.Equal(t, 1.0, result.Candidates[0].SuccessRate)
	require.Equal(t, 20.0, result.Candidates[0].DownloadMBps)
	require.Equal(t, 0.98, result.Candidates[0].Score)
}

func TestNormalizeFissionConfigUsesOriginalHTTPDefaults(t *testing.T) {
	config, err := NormalizeFissionConfig(FissionConfig{
		SeedIPs:        []string{"1.1.1.1"},
		Rounds:         1,
		Concurrency:    1,
		TimeoutMS:      1000,
		MaxDomains:     10,
		MaxIPsPerRound: 10,
		Families:       []string{"ipv4"},
	})

	require.NoError(t, err)
	require.Equal(t, "http://speed.cloudflare.com/__down?bytes=20971520", config.HTTPTestURL)
	require.Equal(t, 3, config.HTTPTestSeconds)
	require.Equal(t, 10, config.ResultCount)
	require.True(t, httpTestEnabled(config))
	require.InDelta(t, 0.35, config.WeightLatency, 0.0001)
	require.InDelta(t, 0.25, config.WeightSuccessRate, 0.0001)
	require.InDelta(t, 0.40, config.WeightDownload, 0.0001)
	require.Equal(t, 80, config.QuickTCPCount)
	require.Equal(t, 40, config.LatencyCheckCount)
}

func TestScoreCandidateUsesOriginalWeights(t *testing.T) {
	require.InDelta(t, 0.605, scoreCandidate(100, 0.5, 10), 0.0001)
}

func TestNormalizeFissionConfigSupportsHTTPDisableAndCustomWeights(t *testing.T) {
	config, err := NormalizeFissionConfig(FissionConfig{
		SeedIPs:           []string{"1.1.1.1"},
		Rounds:            1,
		Concurrency:       1,
		TimeoutMS:         1000,
		MaxDomains:        10,
		MaxIPsPerRound:    10,
		Families:          []string{"ipv4"},
		HTTPTestEnabled:   boolPtr(false),
		WeightLatency:     2,
		WeightSuccessRate: 1,
		WeightDownload:    1,
		StagedScanEnabled: true,
		ResultCount:       3,
		QuickTCPCount:     5,
		LatencyCheckCount: 9,
	})

	require.NoError(t, err)
	require.False(t, httpTestEnabled(config))
	require.InDelta(t, 0.5, config.WeightLatency, 0.0001)
	require.InDelta(t, 0.25, config.WeightSuccessRate, 0.0001)
	require.InDelta(t, 0.25, config.WeightDownload, 0.0001)
	require.Equal(t, 5, config.QuickTCPCount)
	require.Equal(t, 5, config.LatencyCheckCount)
}

func TestMeasureDownloadUsesOriginalHostHeader(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != "speed.cloudflare.com" {
				http.Error(w, "bad host", http.StatusMisdirectedRequest)
				return
			}
			_, _ = io.WriteString(w, strings.Repeat("x", 128*1024))
		}),
	}
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Shutdown(context.Background())

	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)

	service := NewFissionService(FissionConfig{
		SeedIPs:         []string{"1.1.1.1"},
		Rounds:          1,
		Concurrency:     1,
		TimeoutMS:       1000,
		MaxDomains:      10,
		MaxIPsPerRound:  10,
		Families:        []string{"ipv4"},
		HTTPTestURL:     "http://speed.cloudflare.com:" + port + "/__down?bytes=131072",
		HTTPTestSeconds: 1,
	})

	require.Greater(t, service.measureDownload(context.Background(), "127.0.0.1"), 0.0)
}

func TestProbeCandidatesLimitsHTTPDownloadToTopCandidates(t *testing.T) {
	service := NewFissionService(FissionConfig{
		SeedIPs:         []string{"1.1.1.1"},
		Rounds:          1,
		Concurrency:     64,
		TimeoutMS:       1000,
		MaxDomains:      10,
		MaxIPsPerRound:  10,
		ResultCount:     5,
		Families:        []string{"ipv4"},
		HTTPTestEnabled: boolPtr(true),
		HTTPTestURL:     "http://speed.cloudflare.com/__down?bytes=20971520",
		HTTPTestSeconds: 1,
	})
	service.ProbeIP = func(_ context.Context, ip string) CandidateResult {
		parts := strings.Split(ip, ".")
		latency, err := strconv.Atoi(parts[len(parts)-1])
		require.NoError(t, err)
		return CandidateResult{
			Family:       "ipv4",
			IP:           ip,
			Attempts:     1,
			Successes:    1,
			AvgLatencyMS: float64(latency),
			SuccessRate:  1,
		}
	}

	var mu sync.Mutex
	measured := map[string]bool{}
	service.MeasureDownload = func(_ context.Context, ip string) float64 {
		mu.Lock()
		defer mu.Unlock()
		measured[ip] = true
		return 10
	}

	ips := make([]string, 0, 40)
	for i := 1; i <= 40; i++ {
		ips = append(ips, fmt.Sprintf("10.0.0.%d", i))
	}

	candidates, err := service.probeCandidates(context.Background(), ips)

	require.NoError(t, err)
	require.Len(t, measured, 20)
	require.True(t, measured["10.0.0.1"])
	require.True(t, measured["10.0.0.20"])
	require.False(t, measured["10.0.0.21"])
	require.Equal(t, "10.0.0.1", candidates[0].IP)
	require.Equal(t, 10.0, candidates[0].DownloadMBps)
}

func TestProbeCandidatesSkipsHTTPDownloadWhenDisabled(t *testing.T) {
	service := NewFissionService(FissionConfig{
		SeedIPs:         []string{"1.1.1.1"},
		Rounds:          1,
		Concurrency:     8,
		TimeoutMS:       1000,
		MaxDomains:      10,
		MaxIPsPerRound:  10,
		ResultCount:     10,
		Families:        []string{"ipv4"},
		HTTPTestEnabled: boolPtr(false),
		HTTPTestURL:     "http://speed.cloudflare.com/__down?bytes=20971520",
		HTTPTestSeconds: 1,
	})
	service.ProbeIP = func(_ context.Context, ip string) CandidateResult {
		return CandidateResult{
			Family:       "ipv4",
			IP:           ip,
			Attempts:     1,
			Successes:    1,
			AvgLatencyMS: 10,
			SuccessRate:  1,
		}
	}
	measured := 0
	service.MeasureDownload = func(context.Context, string) float64 {
		measured++
		return 10
	}

	candidates, err := service.probeCandidates(context.Background(), []string{"10.0.0.1", "10.0.0.2"})

	require.NoError(t, err)
	require.Len(t, candidates, 2)
	require.Equal(t, 0, measured)
	require.Equal(t, 0.0, candidates[0].DownloadMBps)
}

func TestProbeCandidatesUsesStagedScan(t *testing.T) {
	service := NewFissionService(FissionConfig{
		SeedIPs:           []string{"1.1.1.1"},
		Rounds:            1,
		Concurrency:       8,
		TimeoutMS:         1000,
		MaxDomains:        10,
		MaxIPsPerRound:    10,
		ResultCount:       2,
		Families:          []string{"ipv4"},
		HTTPTestEnabled:   boolPtr(false),
		StagedScanEnabled: true,
		QuickTCPCount:     4,
		LatencyCheckCount: 2,
		WeightLatency:     1,
		WeightSuccessRate: 0,
		WeightDownload:    0,
	})
	attemptsByIP := map[string][]int{}
	var attemptsMu sync.Mutex
	service.ProbeIPWithAttempts = func(_ context.Context, ip string, attempts int) CandidateResult {
		attemptsMu.Lock()
		attemptsByIP[ip] = append(attemptsByIP[ip], attempts)
		attemptsMu.Unlock()
		parts := strings.Split(ip, ".")
		latency, err := strconv.Atoi(parts[len(parts)-1])
		require.NoError(t, err)
		return CandidateResult{
			Family:       "ipv4",
			IP:           ip,
			Attempts:     attempts,
			Successes:    attempts,
			AvgLatencyMS: float64(latency),
			SuccessRate:  1,
		}
	}

	candidates, err := service.probeCandidates(context.Background(), []string{
		"10.0.0.6",
		"10.0.0.5",
		"10.0.0.4",
		"10.0.0.3",
		"10.0.0.2",
		"10.0.0.1",
	})

	require.NoError(t, err)
	require.Len(t, candidates, 2)
	require.Equal(t, "10.0.0.1", candidates[0].IP)
	require.Equal(t, "10.0.0.2", candidates[1].IP)
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"} {
		require.Contains(t, attemptsByIP[ip], 1)
	}
	require.Equal(t, []int{1, 3}, attemptsByIP["10.0.0.1"])
	require.Equal(t, []int{1, 3}, attemptsByIP["10.0.0.2"])
	require.Equal(t, []int{1}, attemptsByIP["10.0.0.5"])
}

func TestProbeIPClassifiesDialErrorsAndCalculatesP95(t *testing.T) {
	service := NewFissionService(FissionConfig{
		SeedIPs:        []string{"104.18.42.54"},
		Rounds:         1,
		Concurrency:    1,
		TimeoutMS:      1000,
		MaxDomains:     10,
		MaxIPsPerRound: 10,
		Families:       []string{"ipv4"},
		ProbeCount:     5,
	})
	call := 0
	service.DialIP = func(context.Context, string, time.Duration) error {
		call++
		switch call {
		case 1:
			time.Sleep(2 * time.Millisecond)
			return nil
		case 2:
			time.Sleep(4 * time.Millisecond)
			return nil
		case 3:
			return errors.New("i/o timeout")
		case 4:
			return errors.New("connect: connection refused")
		default:
			return errors.New("network unreachable")
		}
	}

	result := service.probeIPWithAttempts(context.Background(), "104.18.42.54", 5)

	require.Equal(t, 5, result.Attempts)
	require.Equal(t, 2, result.Successes)
	require.Equal(t, 1, result.TimeoutCount)
	require.Equal(t, 1, result.RefusedCount)
	require.Equal(t, 1, result.OtherErrors)
	require.InDelta(t, 0.4, result.SuccessRate, 0.0001)
	require.GreaterOrEqual(t, result.P95LatencyMS, result.AvgLatencyMS)
	require.Greater(t, result.P95LatencyMS, 0.0)
}

func TestProbeResultsStreamDuringHTTPMeasurements(t *testing.T) {
	ips := []string{
		"10.0.0.1",
		"10.0.0.2",
		"10.0.0.3",
		"10.0.0.4",
		"10.0.0.5",
	}
	service := NewFissionService(FissionConfig{
		SeedIPs:         []string{"10.0.0.1"},
		Rounds:          1,
		Concurrency:     64,
		TimeoutMS:       1000,
		MaxDomains:      10,
		MaxIPsPerRound:  10,
		Families:        []string{"ipv4"},
		ProbePort:       443,
		ProbeCount:      1,
		ResultCount:     10,
		HTTPTestURL:     "http://speed.cloudflare.com/__down?bytes=1024",
		HTTPTestSeconds: 1,
	})
	service.ProbeIPWithAttempts = func(_ context.Context, ip string, attempts int) CandidateResult {
		return CandidateResult{
			Family:       "ipv4",
			IP:           ip,
			Attempts:     attempts,
			Successes:    attempts,
			AvgLatencyMS: 10,
			SuccessRate:  1,
		}
	}

	started := make(chan string, len(ips))
	releaseFirst := make(chan struct{})
	releaseRest := make(chan struct{})
	var downloadMu sync.Mutex
	downloadCalls := 0
	service.MeasureDownload = func(_ context.Context, ip string) float64 {
		started <- ip
		downloadMu.Lock()
		downloadCalls++
		call := downloadCalls
		downloadMu.Unlock()
		if call == 1 {
			<-releaseFirst
			return 10
		}
		<-releaseRest
		return 5
	}

	var eventMu sync.Mutex
	eventTypes := []string{}
	service.Progress = func(event FissionProgressEvent) {
		eventMu.Lock()
		defer eventMu.Unlock()
		eventTypes = append(eventTypes, event.Type)
	}

	done := make(chan error, 1)
	go func() {
		_, _, err := service.probeCandidatesWithStats(context.Background(), ips)
		done <- err
	}()

	require.Eventually(t, func() bool {
		return len(started) > 0
	}, time.Second, 10*time.Millisecond)
	close(releaseFirst)

	require.Eventually(t, func() bool {
		eventMu.Lock()
		defer eventMu.Unlock()
		return slices.Contains(eventTypes, FissionProgressProbeResult) &&
			!slices.Contains(eventTypes, FissionProgressProbeDone)
	}, time.Second, 10*time.Millisecond)

	close(releaseRest)
	require.NoError(t, <-done)
}

func TestFissionServiceEmitsProgressEvents(t *testing.T) {
	service := NewFissionService(FissionConfig{
		SeedIPs:        []string{"1.1.1.1"},
		Rounds:         1,
		Concurrency:    1,
		TimeoutMS:      1000,
		MaxDomains:     10,
		MaxIPsPerRound: 10,
		Families:       []string{"ipv4"},
		ProbePort:      443,
		ProbeCount:     1,
	})
	allowCloudflarePrefixes(service, "1.1.1.0/24", "1.0.0.0/24")
	service.LookupDomains = func(_ context.Context, ip string) []string {
		require.Equal(t, "1.1.1.1", ip)
		return []string{"one.example.com"}
	}
	service.ResolveDomain = func(_ context.Context, domain string) []string {
		require.Equal(t, "one.example.com", domain)
		return []string{"1.0.0.1"}
	}
	service.ProbeIP = func(_ context.Context, ip string) CandidateResult {
		return CandidateResult{
			Family:       "ipv4",
			IP:           ip,
			Attempts:     1,
			Successes:    1,
			AvgLatencyMS: 10,
			SuccessRate:  1,
			Score:        0.9,
		}
	}

	var mu sync.Mutex
	events := []FissionProgressEvent{}
	service.Progress = func(event FissionProgressEvent) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
	}

	result, err := service.Run(context.Background())

	require.NoError(t, err)
	require.NotNil(t, result)
	eventTypes := make([]string, 0, len(events))
	for _, event := range events {
		eventTypes = append(eventTypes, event.Type)
	}
	require.Contains(t, eventTypes, FissionProgressStart)
	require.Contains(t, eventTypes, FissionProgressRoundStart)
	require.Contains(t, eventTypes, FissionProgressIPLookupStart)
	require.Contains(t, eventTypes, FissionProgressIPLookupDone)
	require.Contains(t, eventTypes, FissionProgressDomainResolveStart)
	require.Contains(t, eventTypes, FissionProgressDomainResolveDone)
	require.Contains(t, eventTypes, FissionProgressProbeStart)
	require.Contains(t, eventTypes, FissionProgressCloudflareValidationStart)
	require.Contains(t, eventTypes, FissionProgressCloudflareValidationDone)
	require.Contains(t, eventTypes, FissionProgressProbeResult)
	require.Contains(t, eventTypes, FissionProgressDone)

	var lookupDone FissionProgressEvent
	var resolveDone FissionProgressEvent
	for _, event := range events {
		if event.Type == FissionProgressIPLookupDone {
			lookupDone = event
		}
		if event.Type == FissionProgressDomainResolveDone {
			resolveDone = event
		}
	}
	require.Equal(t, "1.1.1.1", lookupDone.IP)
	require.Equal(t, []string{"one.example.com"}, lookupDone.Domains)
	require.Equal(t, "one.example.com", resolveDone.Domain)
	require.Equal(t, []string{"1.0.0.1"}, resolveDone.IPs)
}

func TestNormalizeFissionConfigRejectsInvalidSeedIP(t *testing.T) {
	_, err := NormalizeFissionConfig(FissionConfig{
		SeedIPs:        []string{"not-an-ip"},
		Rounds:         1,
		Concurrency:    1,
		TimeoutMS:      1000,
		MaxDomains:     10,
		MaxIPsPerRound: 10,
		Families:       []string{"ipv4"},
	})
	require.Error(t, err)
}
