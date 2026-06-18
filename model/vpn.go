package model

import (
	"time"

	"github.com/goccy/go-json"
	"gorm.io/gorm"
)

const (
	VPNActionPrepare      = "prepare"
	VPNActionStart        = "start"
	VPNActionStop         = "stop"
	VPNActionRestart      = "restart"
	VPNActionControl      = "control"
	VPNActionStatus       = "status"
	VPNActionLogs         = "logs"
	VPNActionCleanup      = "cleanup"
	VPNActionRulesPrepare = "rules_prepare"
	VPNActionRulesCleanup = "rules_cleanup"
)

const (
	VPNRoleEntry = "entry"
	VPNRoleExit  = "exit"
)

const (
	VPNModeSystemProxy = "system_proxy"
	VPNModeTunSplit    = "tun_split"
	VPNModeTunGlobal   = "tun_global"
)

const (
	VPNRelayModeDashboard = "dashboard"
	VPNRelayModeDirect    = "direct"
	VPNRelayModeAuto      = "auto"
)

const (
	VPNDirectTransportTCPTLS = "tcp_tls"
	VPNDirectTransportWSTLS  = "ws_tls"
	VPNDirectCryptoLegacy    = "legacy"
	VPNDirectCryptoV2        = "direct_v2"
)

const (
	VPNRuleModeGlobal = "global"
	VPNRuleModeDomain = "domain"
	VPNRuleModeIP     = "ip"
	VPNRuleModeDirect = "direct"
)

const (
	VPNStatePending  = "pending"
	VPNStatePrepared = "prepared"
	VPNStateStarting = "starting"
	VPNStateRunning  = "running"
	VPNStateStopped  = "stopped"
	VPNStateFailed   = "failed"
	VPNStateLost     = "lost"
	VPNStateUnknown  = "unknown"
)

const (
	VPNAuditActionCreatePolicy  = "create_policy"
	VPNAuditActionUpdatePolicy  = "update_policy"
	VPNAuditActionDeletePolicy  = "delete_policy"
	VPNAuditActionStartSession  = "start_session"
	VPNAuditActionStopSession   = "stop_session"
	VPNAuditActionDeleteSession = "delete_session"
	VPNAuditActionRestart       = "restart_session"
	VPNAuditActionStatus        = "status_session"
	VPNAuditActionControl       = "control_session"
)

type VPNControlRequest struct {
	SessionID       string            `json:"session_id"`
	Action          string            `json:"action"`
	Role            string            `json:"role"`
	Mode            string            `json:"mode"`
	RelayMode       string            `json:"relay_mode"`
	PeerServerID    uint64            `json:"peer_server_id"`
	RelayStreamID   string            `json:"relay_stream_id"`
	Token           string            `json:"token"`
	ExpiresAtUnix   int64             `json:"expires_at"`
	ListenHTTP      string            `json:"listen_http,omitempty"`
	ListenSOCKS     string            `json:"listen_socks,omitempty"`
	TunName         string            `json:"tun_name,omitempty"`
	DNSServer       string            `json:"dns_server,omitempty"`
	Rules           VPNRules          `json:"rules"`
	Limits          VPNLimits         `json:"limits"`
	Core            VPNCoreSpec       `json:"core"`
	DashboardBypass []string          `json:"dashboard_bypass"`
	Extra           map[string]string `json:"extra,omitempty"`
}

type VPNRules struct {
	Mode        string   `json:"mode"`
	Domains     []string `json:"domains,omitempty"`
	CIDRs       []string `json:"cidrs,omitempty"`
	DirectCIDRs []string `json:"direct_cidrs,omitempty"`
}

type VPNLimits struct {
	MaxUploadBytes     uint64 `json:"max_upload_bytes,omitempty"`
	MaxDownloadBytes   uint64 `json:"max_download_bytes,omitempty"`
	MaxConnections     uint32 `json:"max_connections,omitempty"`
	IdleTimeoutSeconds uint32 `json:"idle_timeout_seconds,omitempty"`
}

type VPNCoreSpec struct {
	Name              string `json:"name"`
	Version           string `json:"version"`
	SHA256            string `json:"sha256"`
	DownloadURL       string `json:"download_url,omitempty"`
	DownloadBaseURL   string `json:"download_base_url,omitempty"`
	CNDownloadBaseURL string `json:"cn_download_base_url,omitempty"`
	ManifestURL       string `json:"manifest_url,omitempty"`
	CNManifestURL     string `json:"cn_manifest_url,omitempty"`
}

type VPNControlResult struct {
	SessionID           string   `json:"session_id"`
	Action              string   `json:"action"`
	Role                string   `json:"role"`
	State               string   `json:"state"`
	CheckID             string   `json:"check_id,omitempty"`
	RuntimeStatus       string   `json:"runtime_status,omitempty"`
	ModeStatus          string   `json:"mode_status,omitempty"`
	RuleModeStatus      string   `json:"rule_mode_status,omitempty"`
	CoreVersion         string   `json:"core_version,omitempty"`
	CoreStatus          string   `json:"core_status,omitempty"`
	CorePath            string   `json:"core_path,omitempty"`
	RulesStatus         string   `json:"rules_status,omitempty"`
	RulesPath           string   `json:"rules_path,omitempty"`
	RulesVersion        string   `json:"rules_version,omitempty"`
	LocalHTTP           string   `json:"local_http,omitempty"`
	LocalSOCKS          string   `json:"local_socks,omitempty"`
	TunName             string   `json:"tun_name,omitempty"`
	SystemProxyApplied  *bool    `json:"system_proxy_applied,omitempty"`
	SystemProxyStatus   string   `json:"system_proxy_status,omitempty"`
	SystemProxyCurrent  string   `json:"system_proxy_current,omitempty"`
	SystemProxyExpected string   `json:"system_proxy_expected,omitempty"`
	TunStatus           string   `json:"tun_status,omitempty"`
	TunInterface        string   `json:"tun_interface,omitempty"`
	TrafficReported     bool     `json:"traffic_reported,omitempty"`
	UploadBytes         uint64   `json:"upload_bytes,omitempty"`
	DownloadBytes       uint64   `json:"download_bytes,omitempty"`
	ActiveConns         uint32   `json:"active_conns,omitempty"`
	LastError           string   `json:"last_error,omitempty"`
	Logs                []string `json:"logs,omitempty"`
	StartedAtUnix       int64    `json:"started_at,omitempty"`
	StoppedAtUnix       int64    `json:"stopped_at,omitempty"`
}

type AgentVPNDebugResult struct {
	ID                 uint64           `json:"id"`
	ReportedAt         time.Time        `json:"reported_at"`
	ReporterServerID   uint64           `json:"reporter_server_id"`
	ReporterServerName string           `json:"reporter_server_name,omitempty"`
	SessionID          string           `json:"session_id"`
	Action             string           `json:"action"`
	Role               string           `json:"role"`
	State              string           `json:"state"`
	LastError          string           `json:"last_error,omitempty"`
	Result             VPNControlResult `json:"result"`
}

type AgentVPNPolicyForm struct {
	Name                    string   `json:"name"`
	EntryServerID           uint64   `json:"entry_server_id"`
	ExitServerID            uint64   `json:"exit_server_id"`
	Mode                    string   `json:"mode"`
	RuleMode                string   `json:"rule_mode"`
	RelayMode               string   `json:"relay_mode"`
	DirectTransport         string   `json:"direct_transport"`
	DirectHost              string   `json:"direct_host"`
	DirectPort              uint32   `json:"direct_port"`
	DirectTLSServerName     string   `json:"direct_tls_server_name"`
	DirectWSPath            string   `json:"direct_ws_path"`
	DirectTLSVerify         bool     `json:"direct_tls_verify"`
	DirectCertSHA256        string   `json:"direct_cert_sha256"`
	ExitNATEnabled          bool     `json:"exit_nat_enabled"`
	ExitNATHost             string   `json:"exit_nat_host"`
	ExitNATPort             uint32   `json:"exit_nat_port"`
	Domains                 []string `json:"domains"`
	CIDRs                   []string `json:"cidrs"`
	DirectCIDRs             []string `json:"direct_cidrs"`
	ListenHTTP              string   `json:"listen_http"`
	ListenSOCKS             string   `json:"listen_socks"`
	TunName                 string   `json:"tun_name"`
	DNSServer               string   `json:"dns_server"`
	ExpiresSeconds          uint32   `json:"expires_seconds"`
	MaxUploadBytes          uint64   `json:"max_upload_bytes"`
	MaxDownloadBytes        uint64   `json:"max_download_bytes"`
	MaxConnections          uint32   `json:"max_connections"`
	IdleTimeoutSeconds      uint32   `json:"idle_timeout_seconds"`
	NotificationGroupID     uint64   `json:"notification_group_id"`
	AutoRestart             bool     `json:"auto_restart"`
	SetSystemProxy          bool     `json:"set_system_proxy"`
	TunHealthURL            string   `json:"tun_health_url"`
	TunHealthTimeoutSeconds uint32   `json:"tun_health_timeout_seconds"`
	EgressProbeURL          string   `json:"egress_probe_url"`
	CoreVersion             string   `json:"core_version"`
	CoreDownloadURL         string   `json:"core_download_url"`
	CoreSHA256              string   `json:"core_sha256"`
}

type AgentVPNSessionStartForm struct {
	PolicyID uint64 `json:"policy_id"`
}

type AgentVPNSessionControlForm struct {
	Mode           string `json:"mode"`
	RuleMode       string `json:"rule_mode"`
	SetSystemProxy bool   `json:"set_system_proxy"`
}

type AgentVPNPolicyStatusCheck struct {
	PolicyID   uint64                     `json:"policy_id"`
	PolicyName string                     `json:"policy_name"`
	CheckID    string                     `json:"check_id"`
	CheckedAt  time.Time                  `json:"checked_at"`
	TimedOut   bool                       `json:"timed_out,omitempty"`
	Nodes      []AgentVPNPolicyNodeStatus `json:"nodes"`
}

type AgentVPNPolicyNodeStatus struct {
	Role         string   `json:"role"`
	ServerID     uint64   `json:"server_id"`
	ServerName   string   `json:"server_name"`
	Online       bool     `json:"online"`
	Responded    bool     `json:"responded"`
	State        string   `json:"state"`
	CoreStatus   string   `json:"core_status"`
	CorePath     string   `json:"core_path,omitempty"`
	CoreVersion  string   `json:"core_version,omitempty"`
	RulesStatus  string   `json:"rules_status"`
	RulesPath    string   `json:"rules_path,omitempty"`
	RulesVersion string   `json:"rules_version,omitempty"`
	LastError    string   `json:"last_error,omitempty"`
	Logs         []string `json:"logs,omitempty"`
}

type AgentVPNPolicy struct {
	Common
	Name                    string   `json:"name"`
	EntryServerID           uint64   `json:"entry_server_id" gorm:"index"`
	ExitServerID            uint64   `json:"exit_server_id" gorm:"index"`
	Mode                    string   `json:"mode" gorm:"index"`
	RuleMode                string   `json:"rule_mode"`
	RelayMode               string   `json:"relay_mode"`
	DirectTransport         string   `json:"direct_transport"`
	DirectHost              string   `json:"direct_host"`
	DirectPort              uint32   `json:"direct_port"`
	DirectTLSServerName     string   `json:"direct_tls_server_name"`
	DirectWSPath            string   `json:"direct_ws_path"`
	DirectTLSVerify         bool     `json:"direct_tls_verify"`
	DirectCertSHA256        string   `json:"direct_cert_sha256"`
	ExitNATEnabled          bool     `json:"exit_nat_enabled"`
	ExitNATHost             string   `json:"exit_nat_host"`
	ExitNATPort             uint32   `json:"exit_nat_port"`
	Domains                 []string `json:"domains" gorm:"-"`
	CIDRs                   []string `json:"cidrs" gorm:"-"`
	DirectCIDRs             []string `json:"direct_cidrs" gorm:"-"`
	DomainsRaw              string   `json:"-" gorm:"type:text"`
	CIDRsRaw                string   `json:"-" gorm:"type:text"`
	DirectCIDRsRaw          string   `json:"-" gorm:"type:text"`
	ListenHTTP              string   `json:"listen_http"`
	ListenSOCKS             string   `json:"listen_socks"`
	TunName                 string   `json:"tun_name"`
	DNSServer               string   `json:"dns_server"`
	ExpiresSeconds          uint32   `json:"expires_seconds"`
	MaxUploadBytes          uint64   `json:"max_upload_bytes"`
	MaxDownloadBytes        uint64   `json:"max_download_bytes"`
	MaxConnections          uint32   `json:"max_connections"`
	IdleTimeoutSeconds      uint32   `json:"idle_timeout_seconds"`
	NotificationGroupID     uint64   `json:"notification_group_id"`
	AutoRestart             bool     `json:"auto_restart"`
	SetSystemProxy          bool     `json:"set_system_proxy"`
	TunHealthURL            string   `json:"tun_health_url"`
	TunHealthTimeoutSeconds uint32   `json:"tun_health_timeout_seconds"`
	EgressProbeURL          string   `json:"egress_probe_url"`
	CoreVersion             string   `json:"core_version"`
	CoreDownloadURL         string   `json:"core_download_url"`
	CoreSHA256              string   `json:"core_sha256"`
}

func (p *AgentVPNPolicy) BeforeSave(tx *gorm.DB) error {
	return firstJSONError(
		marshalRaw(p.Domains, &p.DomainsRaw),
		marshalRaw(p.CIDRs, &p.CIDRsRaw),
		marshalRaw(p.DirectCIDRs, &p.DirectCIDRsRaw),
	)
}

func (p *AgentVPNPolicy) AfterFind(tx *gorm.DB) error {
	return firstJSONError(
		unmarshalRaw(p.DomainsRaw, &p.Domains),
		unmarshalRaw(p.CIDRsRaw, &p.CIDRs),
		unmarshalRaw(p.DirectCIDRsRaw, &p.DirectCIDRs),
	)
}

type AgentVPNSession struct {
	Common
	PolicyID            uint64     `json:"policy_id" gorm:"index"`
	EntryServerID       uint64     `json:"entry_server_id" gorm:"index"`
	ExitServerID        uint64     `json:"exit_server_id" gorm:"index"`
	SessionID           string     `json:"session_id" gorm:"uniqueIndex"`
	TokenHash           string     `json:"-" gorm:"type:char(71)"`
	Mode                string     `json:"mode"`
	RuleMode            string     `json:"rule_mode"`
	RelayMode           string     `json:"relay_mode"`
	State               string     `json:"state" gorm:"index"`
	EntryState          string     `json:"entry_state"`
	ExitState           string     `json:"exit_state"`
	EntryStreamID       string     `json:"entry_stream_id"`
	ExitStreamID        string     `json:"exit_stream_id"`
	RuntimeStatus       string     `json:"runtime_status"`
	ModeStatus          string     `json:"mode_status"`
	RuleModeStatus      string     `json:"rule_mode_status"`
	CoreStatus          string     `json:"core_status"`
	CorePath            string     `json:"core_path"`
	CoreVersion         string     `json:"core_version"`
	RulesStatus         string     `json:"rules_status"`
	RulesPath           string     `json:"rules_path"`
	RulesVersion        string     `json:"rules_version"`
	LocalHTTP           string     `json:"local_http"`
	LocalSOCKS          string     `json:"local_socks"`
	TunName             string     `json:"tun_name"`
	SetSystemProxy      bool       `json:"set_system_proxy"`
	SystemProxyApplied  *bool      `json:"system_proxy_applied,omitempty"`
	SystemProxyStatus   string     `json:"system_proxy_status"`
	SystemProxyCurrent  string     `json:"system_proxy_current"`
	SystemProxyExpected string     `json:"system_proxy_expected"`
	TunStatus           string     `json:"tun_status"`
	TunInterface        string     `json:"tun_interface"`
	ControlOverride     bool       `json:"control_override"`
	UploadBytes         uint64     `json:"upload_bytes"`
	DownloadBytes       uint64     `json:"download_bytes"`
	ActiveConnections   uint32     `json:"active_connections"`
	LastError           string     `json:"last_error"`
	StartedAt           time.Time  `json:"started_at"`
	ExpiresAt           time.Time  `json:"expires_at"`
	StoppedAt           *time.Time `json:"stopped_at,omitempty"`
}

type AgentVPNAuditLog struct {
	Common
	SessionID     string            `json:"session_id" gorm:"index"`
	UserID        uint64            `json:"user_id" gorm:"index"`
	Action        string            `json:"action" gorm:"index"`
	EntryServerID uint64            `json:"entry_server_id"`
	ExitServerID  uint64            `json:"exit_server_id"`
	Success       bool              `json:"success"`
	Message       string            `json:"message"`
	Detail        map[string]string `json:"detail" gorm:"-"`
	DetailRaw     string            `json:"-" gorm:"type:text"`
}

func (a *AgentVPNAuditLog) BeforeSave(tx *gorm.DB) error {
	return marshalRaw(a.Detail, &a.DetailRaw)
}

func (a *AgentVPNAuditLog) AfterFind(tx *gorm.DB) error {
	return unmarshalRaw(a.DetailRaw, &a.Detail)
}

func marshalRaw(value any, raw *string) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	*raw = string(data)
	return nil
}

func unmarshalRaw(raw string, value any) error {
	if raw == "" {
		return nil
	}
	return json.Unmarshal([]byte(raw), value)
}

func firstJSONError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
