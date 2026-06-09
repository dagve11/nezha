package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestVPNTaskTypesUseAgentWireValues(t *testing.T) {
	cases := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"exec", TaskTypeExec, 15},
		{"fs_list", TaskTypeFsList, 16},
		{"fs_read", TaskTypeFsRead, 17},
		{"fs_write", TaskTypeFsWrite, 18},
		{"fs_delete", TaskTypeFsDelete, 19},
		{"fs_transfer", TaskTypeFsTransfer, 20},
		{"destroy_agent", TaskTypeDestroyAgent, 21},
		{"vpn_control", TaskTypeVPNControl, 22},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("%s task type = %d, want %d", tc.name, tc.got, tc.want)
			}
		})
	}

	if IsServiceSentinelNeeded(TaskTypeVPNControl) {
		t.Fatal("TaskTypeVPNControl must not be routed to service sentinel")
	}
}

func TestVPNControlRequestAndResultJSONContract(t *testing.T) {
	req := VPNControlRequest{
		SessionID:     "vpn-1",
		Action:        VPNActionStart,
		Role:          VPNRoleEntry,
		Mode:          VPNModeTunSplit,
		RelayMode:     VPNRelayModeDashboard,
		PeerServerID:  42,
		RelayStreamID: "stream-entry",
		Token:         "plain-session-token",
		ExpiresAtUnix: 1710000000,
		ListenHTTP:    "127.0.0.1:8088",
		ListenSOCKS:   "127.0.0.1:1080",
		TunName:       "nezha0",
		DNSServer:     "1.1.1.1",
		Rules: VPNRules{
			Mode:        VPNRuleModeDomain,
			Domains:     []string{"github.com"},
			CIDRs:       []string{"140.82.112.0/20"},
			DirectCIDRs: []string{"127.0.0.0/8"},
		},
		Limits: VPNLimits{
			MaxUploadBytes:     1,
			MaxDownloadBytes:   2,
			MaxConnections:     3,
			IdleTimeoutSeconds: 4,
		},
		Core: VPNCoreSpec{
			Name:        "sing-box",
			Version:     "1.12.0",
			SHA256:      "abc",
			DownloadURL: "https://example.com/sing-box.zip",
		},
		DashboardBypass: []string{"dashboard.example.com"},
		Extra:           map[string]string{"egress_probe_url": "https://ifconfig.example/ip"},
	}

	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	var gotReq map[string]any
	if err := json.Unmarshal(raw, &gotReq); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	for _, key := range []string{
		"session_id", "action", "role", "mode", "relay_mode", "peer_server_id",
		"relay_stream_id", "token", "expires_at", "listen_http", "listen_socks",
		"tun_name", "dns_server", "rules", "limits", "core", "dashboard_bypass", "extra",
	} {
		if _, ok := gotReq[key]; !ok {
			t.Fatalf("request JSON missing key %q: %s", key, raw)
		}
	}

	result := VPNControlResult{
		SessionID:     "vpn-1",
		Action:        VPNActionStart,
		Role:          VPNRoleEntry,
		State:         VPNStateRunning,
		CoreVersion:   "1.12.0",
		LocalHTTP:     "127.0.0.1:8088",
		LocalSOCKS:    "127.0.0.1:1080",
		TunName:       "nezha0",
		UploadBytes:   12,
		DownloadBytes: 34,
		ActiveConns:   5,
		LastError:     "none",
		Logs:          []string{"ready"},
		StartedAtUnix: 1710000001,
		StoppedAtUnix: 1710000002,
	}

	raw, err = json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	for _, part := range []string{
		`"session_id":"vpn-1"`,
		`"action":"start"`,
		`"role":"entry"`,
		`"state":"running"`,
		`"active_conns":5`,
	} {
		if !strings.Contains(string(raw), part) {
			t.Fatalf("result JSON %s missing %s", raw, part)
		}
	}
}

func TestAgentVPNPolicySerializesRules(t *testing.T) {
	policy := AgentVPNPolicy{
		Name:             "GitHub",
		EntryServerID:    1,
		ExitServerID:     2,
		Mode:             VPNModeTunSplit,
		RuleMode:         VPNRuleModeDomain,
		Domains:          []string{"github.com", "api.github.com"},
		CIDRs:            []string{"140.82.112.0/20"},
		DirectCIDRs:      []string{"127.0.0.0/8", "::1/128"},
		ListenHTTP:       "127.0.0.1:8088",
		ListenSOCKS:      "127.0.0.1:1080",
		ExpiresSeconds:   3600,
		MaxUploadBytes:   1024,
		MaxDownloadBytes: 2048,
		MaxConnections:   128,
		AutoRestart:      true,
	}

	if err := policy.BeforeSave(nil); err != nil {
		t.Fatalf("BeforeSave: %v", err)
	}
	if !strings.Contains(policy.DomainsRaw, "github.com") {
		t.Fatalf("DomainsRaw = %q, want serialized domains", policy.DomainsRaw)
	}

	loaded := AgentVPNPolicy{
		DomainsRaw:     policy.DomainsRaw,
		CIDRsRaw:       policy.CIDRsRaw,
		DirectCIDRsRaw: policy.DirectCIDRsRaw,
	}
	if err := loaded.AfterFind(nil); err != nil {
		t.Fatalf("AfterFind: %v", err)
	}
	if len(loaded.Domains) != 2 || loaded.Domains[1] != "api.github.com" {
		t.Fatalf("Domains = %#v, want original domain list", loaded.Domains)
	}
	if len(loaded.CIDRs) != 1 || loaded.CIDRs[0] != "140.82.112.0/20" {
		t.Fatalf("CIDRs = %#v, want original CIDR list", loaded.CIDRs)
	}
	if len(loaded.DirectCIDRs) != 2 || loaded.DirectCIDRs[1] != "::1/128" {
		t.Fatalf("DirectCIDRs = %#v, want original direct CIDR list", loaded.DirectCIDRs)
	}
}

func TestAgentVPNSessionDoesNotExposeTokenHash(t *testing.T) {
	session := AgentVPNSession{
		SessionID:     "vpn-1",
		TokenHash:     "sha256:secret-token-hash",
		Mode:          VPNModeSystemProxy,
		RelayMode:     VPNRelayModeDashboard,
		State:         VPNStateRunning,
		EntryState:    VPNStateRunning,
		ExitState:     VPNStateRunning,
		StartedAt:     time.Unix(1710000000, 0),
		ExpiresAt:     time.Unix(1710003600, 0),
		EntryStreamID: "entry-stream",
		ExitStreamID:  "exit-stream",
	}

	raw, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	if strings.Contains(string(raw), "secret-token-hash") || strings.Contains(string(raw), "TokenHash") || strings.Contains(string(raw), "token_hash") {
		t.Fatalf("session JSON leaked token hash: %s", raw)
	}
	if !strings.Contains(string(raw), `"session_id":"vpn-1"`) {
		t.Fatalf("session JSON missing public session id: %s", raw)
	}
}

func TestAgentVPNAuditLogSerializesDetail(t *testing.T) {
	audit := AgentVPNAuditLog{
		SessionID:     "vpn-1",
		UserID:        100,
		Action:        VPNAuditActionStartSession,
		EntryServerID: 1,
		ExitServerID:  2,
		Success:       true,
		Message:       "started",
		Detail: map[string]string{
			"mode": VPNModeSystemProxy,
		},
	}

	if err := audit.BeforeSave(nil); err != nil {
		t.Fatalf("BeforeSave: %v", err)
	}
	if !strings.Contains(audit.DetailRaw, VPNModeSystemProxy) {
		t.Fatalf("DetailRaw = %q, want serialized detail", audit.DetailRaw)
	}

	loaded := AgentVPNAuditLog{DetailRaw: audit.DetailRaw}
	if err := loaded.AfterFind(nil); err != nil {
		t.Fatalf("AfterFind: %v", err)
	}
	if loaded.Detail["mode"] != VPNModeSystemProxy {
		t.Fatalf("Detail = %#v, want mode detail", loaded.Detail)
	}
}

func TestVPNModelsAutoMigrate(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&AgentVPNPolicy{}, &AgentVPNSession{}, &AgentVPNAuditLog{}); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}

	for _, table := range []string{"agent_vpn_policies", "agent_vpn_sessions", "agent_vpn_audit_logs"} {
		if !db.Migrator().HasTable(table) {
			t.Fatalf("expected table %s to be migrated", table)
		}
	}

	policy := AgentVPNPolicy{
		Name:            "core policy",
		EntryServerID:   1,
		ExitServerID:    2,
		Mode:            VPNModeSystemProxy,
		RuleMode:        VPNRuleModeGlobal,
		CoreVersion:     "1.12.0",
		CoreDownloadURL: "https://download.example.com/sing-box",
		CoreSHA256:      "sha256:abcdef",
		EgressProbeURL:  "https://ifconfig.example/ip",
	}
	if err := db.Create(&policy).Error; err != nil {
		t.Fatalf("create policy with core fields: %v", err)
	}
	var loaded AgentVPNPolicy
	if err := db.First(&loaded, policy.ID).Error; err != nil {
		t.Fatalf("load policy with core fields: %v", err)
	}
	if loaded.CoreVersion != "1.12.0" || loaded.CoreDownloadURL != "https://download.example.com/sing-box" || loaded.CoreSHA256 != "sha256:abcdef" {
		t.Fatalf("core fields were not persisted: version=%q url=%q sha256=%q", loaded.CoreVersion, loaded.CoreDownloadURL, loaded.CoreSHA256)
	}
	if loaded.EgressProbeURL != "https://ifconfig.example/ip" {
		t.Fatalf("egress probe URL was not persisted: %q", loaded.EgressProbeURL)
	}
}
