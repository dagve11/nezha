package model

import (
	"time"

	"github.com/nezhahq/nezha/pkg/bestip"
	"gorm.io/gorm"
)

const (
	BestIPAutomationActionRun      = "run"
	BestIPAutomationActionRollback = "rollback"
)

type BestIPAutomation struct {
	Common
	Enabled             bool                     `json:"enabled"`
	Scheduler           string                   `json:"scheduler"`
	AutoWriteDNS        bool                     `json:"auto_write_dns"`
	PushSuccessful      bool                     `json:"push_successful"`
	PushFailed          bool                     `json:"push_failed"`
	NotificationGroupID uint64                   `json:"notification_group_id"`
	WriteTopN           int                      `json:"write_top_n"`
	DDNSProfiles        []uint64                 `json:"ddns_profiles" gorm:"-"`
	DDNSCredentials     []uint64                 `json:"ddns_credentials" gorm:"-"`
	Domains             []string                 `json:"domains" gorm:"-"`
	Fission             bestip.FissionConfig     `json:"fission" gorm:"-"`
	LastIPv4Records     []string                 `json:"last_ipv4_records" gorm:"-"`
	LastIPv6Records     []string                 `json:"last_ipv6_records" gorm:"-"`
	RollbackIPv4Records []string                 `json:"rollback_ipv4_records" gorm:"-"`
	RollbackIPv6Records []string                 `json:"rollback_ipv6_records" gorm:"-"`
	LastCandidates      []bestip.CandidateResult `json:"last_candidates" gorm:"-"`
	LastDNSResults      []BestIPDNSWriteResult   `json:"last_dns_results" gorm:"-"`
	LastRunAt           time.Time                `json:"last_run_at,omitempty"`
	LastResult          bool                     `json:"last_result"`
	LastError           string                   `json:"last_error,omitempty"`
	CronJobID           uint64                   `json:"cron_job_id,omitempty" gorm:"-"`
	DDNSProfilesRaw     string                   `json:"-" gorm:"type:text"`
	DDNSCredentialsRaw  string                   `json:"-" gorm:"type:text"`
	DomainsRaw          string                   `json:"-" gorm:"type:text"`
	FissionRaw          string                   `json:"-" gorm:"type:text"`
	LastIPv4RecordsRaw  string                   `json:"-" gorm:"type:text"`
	LastIPv6RecordsRaw  string                   `json:"-" gorm:"type:text"`
	RollbackIPv4Raw     string                   `json:"-" gorm:"type:text"`
	RollbackIPv6Raw     string                   `json:"-" gorm:"type:text"`
	LastCandidatesRaw   string                   `json:"-" gorm:"type:text"`
	LastDNSResultsRaw   string                   `json:"-" gorm:"type:text"`
}

type BestIPAutomationHistory struct {
	Common
	AutomationID        uint64                   `json:"automation_id" gorm:"index"`
	Action              string                   `json:"action"`
	StartedAt           time.Time                `json:"started_at"`
	FinishedAt          time.Time                `json:"finished_at"`
	Success             bool                     `json:"success"`
	Error               string                   `json:"error,omitempty"`
	IPv4Records         []string                 `json:"ipv4_records" gorm:"-"`
	IPv6Records         []string                 `json:"ipv6_records" gorm:"-"`
	RollbackIPv4Records []string                 `json:"rollback_ipv4_records" gorm:"-"`
	RollbackIPv6Records []string                 `json:"rollback_ipv6_records" gorm:"-"`
	Candidates          []bestip.CandidateResult `json:"candidates" gorm:"-"`
	DNSResults          []BestIPDNSWriteResult   `json:"dns_results" gorm:"-"`
	IPv4RecordsRaw      string                   `json:"-" gorm:"type:text"`
	IPv6RecordsRaw      string                   `json:"-" gorm:"type:text"`
	RollbackIPv4Raw     string                   `json:"-" gorm:"type:text"`
	RollbackIPv6Raw     string                   `json:"-" gorm:"type:text"`
	CandidatesRaw       string                   `json:"-" gorm:"type:text"`
	DNSResultsRaw       string                   `json:"-" gorm:"type:text"`
}

type BestIPAutomationForm struct {
	Enabled             bool                 `json:"enabled"`
	Scheduler           string               `json:"scheduler"`
	AutoWriteDNS        bool                 `json:"auto_write_dns"`
	PushSuccessful      bool                 `json:"push_successful"`
	PushFailed          bool                 `json:"push_failed"`
	NotificationGroupID uint64               `json:"notification_group_id,omitempty"`
	WriteTopN           int                  `json:"write_top_n"`
	DDNSProfiles        []uint64             `json:"ddns_profiles,omitempty"`
	DDNSCredentials     []uint64             `json:"ddns_credentials,omitempty"`
	Domains             []string             `json:"domains,omitempty"`
	Fission             bestip.FissionConfig `json:"fission"`
}

func (a *BestIPAutomation) BeforeSave(tx *gorm.DB) error {
	return firstJSONError(
		marshalRaw(a.DDNSProfiles, &a.DDNSProfilesRaw),
		marshalRaw(a.DDNSCredentials, &a.DDNSCredentialsRaw),
		marshalRaw(a.Domains, &a.DomainsRaw),
		marshalRaw(a.Fission, &a.FissionRaw),
		marshalRaw(a.LastIPv4Records, &a.LastIPv4RecordsRaw),
		marshalRaw(a.LastIPv6Records, &a.LastIPv6RecordsRaw),
		marshalRaw(a.RollbackIPv4Records, &a.RollbackIPv4Raw),
		marshalRaw(a.RollbackIPv6Records, &a.RollbackIPv6Raw),
		marshalRaw(a.LastCandidates, &a.LastCandidatesRaw),
		marshalRaw(a.LastDNSResults, &a.LastDNSResultsRaw),
	)
}

func (a *BestIPAutomation) AfterFind(tx *gorm.DB) error {
	return firstJSONError(
		unmarshalRaw(a.DDNSProfilesRaw, &a.DDNSProfiles),
		unmarshalRaw(a.DDNSCredentialsRaw, &a.DDNSCredentials),
		unmarshalRaw(a.DomainsRaw, &a.Domains),
		unmarshalRaw(a.FissionRaw, &a.Fission),
		unmarshalRaw(a.LastIPv4RecordsRaw, &a.LastIPv4Records),
		unmarshalRaw(a.LastIPv6RecordsRaw, &a.LastIPv6Records),
		unmarshalRaw(a.RollbackIPv4Raw, &a.RollbackIPv4Records),
		unmarshalRaw(a.RollbackIPv6Raw, &a.RollbackIPv6Records),
		unmarshalRaw(a.LastCandidatesRaw, &a.LastCandidates),
		unmarshalRaw(a.LastDNSResultsRaw, &a.LastDNSResults),
	)
}

func (h *BestIPAutomationHistory) BeforeSave(tx *gorm.DB) error {
	return firstJSONError(
		marshalRaw(h.IPv4Records, &h.IPv4RecordsRaw),
		marshalRaw(h.IPv6Records, &h.IPv6RecordsRaw),
		marshalRaw(h.RollbackIPv4Records, &h.RollbackIPv4Raw),
		marshalRaw(h.RollbackIPv6Records, &h.RollbackIPv6Raw),
		marshalRaw(h.Candidates, &h.CandidatesRaw),
		marshalRaw(h.DNSResults, &h.DNSResultsRaw),
	)
}

func (h *BestIPAutomationHistory) AfterFind(tx *gorm.DB) error {
	return firstJSONError(
		unmarshalRaw(h.IPv4RecordsRaw, &h.IPv4Records),
		unmarshalRaw(h.IPv6RecordsRaw, &h.IPv6Records),
		unmarshalRaw(h.RollbackIPv4Raw, &h.RollbackIPv4Records),
		unmarshalRaw(h.RollbackIPv6Raw, &h.RollbackIPv6Records),
		unmarshalRaw(h.CandidatesRaw, &h.Candidates),
		unmarshalRaw(h.DNSResultsRaw, &h.DNSResults),
	)
}
