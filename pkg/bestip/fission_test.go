package bestip

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

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

	result, err := service.Run(context.Background())
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"1.1.1.1", "1.0.0.1", "8.8.8.8"}, result.IPs)
	require.Len(t, result.Rounds, 2)
	require.ElementsMatch(t, []string{"1.0.0.1"}, result.Rounds[0].NewIPs)
	require.ElementsMatch(t, []string{"8.8.8.8"}, result.Rounds[1].NewIPs)
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
