package model

import "github.com/nezhahq/nezha/pkg/bestip"

type BestIPFissionForm = bestip.FissionConfig
type BestIPFissionResult = bestip.FissionRunResult
type BestIPFissionRoundResult = bestip.FissionRoundResult

const (
	BestIPFissionTaskResultProgress = "progress"
	BestIPFissionTaskResultDone     = "done"
	BestIPFissionTaskResultError    = "error"
)

type BestIPFissionTaskRequest struct {
	Config bestip.FissionConfig `json:"config"`
}

type BestIPFissionTaskResult struct {
	Kind   string                       `json:"kind"`
	Event  *bestip.FissionProgressEvent `json:"event,omitempty"`
	Result *bestip.FissionRunResult     `json:"result,omitempty"`
	Error  string                       `json:"error,omitempty"`
}

type BestIPDNSWriteForm struct {
	DDNSProfiles    []uint64 `json:"ddns_profiles,omitempty"`
	DDNSCredentials []uint64 `json:"ddns_credentials,omitempty"`
	Domains         []string `json:"domains,omitempty"`
	IPv4            string   `json:"ipv4,omitempty"`
	IPv6            string   `json:"ipv6,omitempty"`
	IPv4Records     []string `json:"ipv4_records,omitempty"`
	IPv6Records     []string `json:"ipv6_records,omitempty"`
}

type BestIPDNSWriteResult struct {
	ProfileID    uint64   `json:"profile_id,omitempty"`
	CredentialID uint64   `json:"credential_id,omitempty"`
	Provider     string   `json:"provider"`
	Domains      []string `json:"domains"`
	Success      bool     `json:"success"`
	Error        string   `json:"error,omitempty"`
}

type BestIPNotifyForm struct {
	NotificationGroupID uint64                   `json:"notification_group_id"`
	Domains             []string                 `json:"domains,omitempty"`
	IPv4                string                   `json:"ipv4,omitempty"`
	IPv6                string                   `json:"ipv6,omitempty"`
	IPv4Records         []string                 `json:"ipv4_records,omitempty"`
	IPv6Records         []string                 `json:"ipv6_records,omitempty"`
	Candidates          []bestip.CandidateResult `json:"candidates,omitempty"`
	WriteTopN           int                      `json:"write_top_n,omitempty"`
}

type BestIPNotifyResult struct {
	Success bool     `json:"success"`
	IPv4    []string `json:"ipv4_records,omitempty"`
	IPv6    []string `json:"ipv6_records,omitempty"`
}
