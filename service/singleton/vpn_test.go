package singleton

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/patrickmn/go-cache"
	"github.com/robfig/cron/v3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/nezhahq/nezha/model"
	pb "github.com/nezhahq/nezha/proto"
)

type vpnNotificationCapture struct {
	groupID uint64
	message string
	mute    string
}

type vpnRelayCreateCapture struct {
	sessionID     string
	entryStreamID string
	entryServerID uint64
	exitStreamID  string
	exitServerID  uint64
}

type vpnHarness struct {
	vpn           *VPNClass
	entryStream   *capturedTaskStream
	exitStream    *capturedTaskStream
	foreignStream *capturedTaskStream
	notifications *[]vpnNotificationCapture
	relayCreates  *[]vpnRelayCreateCapture
	relayCloses   *[]string
	sqlDB         *sql.DB
}

func vpnCapableHost() *model.Host {
	return &model.Host{
		VPNEnabled:          true,
		VPNAllowSystemProxy: true,
		VPNAllowTun:         true,
		VPNCoreVersion:      "1.12.0",
	}
}

func newVPNHarness(t *testing.T) *vpnHarness {
	t.Helper()

	originalDB := DB
	originalCache := Cache
	originalServerShared := ServerShared
	originalVPNShared := VPNShared
	originalTokenGenerator := VPNTokenGenerator
	originalIDGenerator := VPNIDGenerator
	originalNotificationSender := VPNNotificationSender
	originalRelayCreator := VPNRelayCreator
	originalRelayCloser := VPNRelayCloser
	originalConf := Conf

	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)

	DB = db
	Cache = cache.New(time.Minute, time.Minute)
	if err := DB.AutoMigrate(
		model.Server{},
		model.NotificationGroup{},
		model.AgentVPNPolicy{},
		model.AgentVPNSession{},
		model.AgentVPNAuditLog{},
	); err != nil {
		t.Fatal(err)
	}
	if err := DB.Create(&model.NotificationGroup{
		Common: model.Common{ID: 9, UserID: 100},
		Name:   "vpn-notify",
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := DB.Create(&model.NotificationGroup{
		Common: model.Common{ID: 10, UserID: 200},
		Name:   "foreign-notify",
	}).Error; err != nil {
		t.Fatal(err)
	}

	entryStream := newCapturedTaskStream()
	exitStream := newCapturedTaskStream()
	foreignStream := newCapturedTaskStream()
	ServerShared = &ServerClass{
		class: class[uint64, *model.Server]{
			list: map[uint64]*model.Server{
				1: withTaskStream(&model.Server{
					Common: model.Common{ID: 1, UserID: 100},
					Name:   "entry-cn",
					Host:   vpnCapableHost(),
				}, entryStream),
				2: withTaskStream(&model.Server{
					Common: model.Common{ID: 2, UserID: 100},
					Name:   "exit-jp",
					Host:   vpnCapableHost(),
					GeoIP: &model.GeoIP{
						IP: model.IP{
							IPv4Addr: "198.51.100.20",
							IPv6Addr: "2001:db8::20",
						},
					},
				}, exitStream),
				3: withTaskStream(&model.Server{
					Common: model.Common{ID: 3, UserID: 200},
					Name:   "foreign-us",
					Host:   vpnCapableHost(),
				}, foreignStream),
			},
		},
		uuidToID: map[string]uint64{},
	}
	Conf = &ConfigClass{Config: &model.Config{
		ConfigDashboard: model.ConfigDashboard{
			InstallHost: "dashboard.example.com:8008",
		},
	}}

	tokens := []string{"session-token-1", "session-token-2", "session-token-3"}
	tokenIndex := 0
	VPNTokenGenerator = func() (string, error) {
		token := tokens[tokenIndex%len(tokens)]
		tokenIndex++
		return token, nil
	}
	ids := []string{
		"vpn_session_1",
		"vpn_entry_stream_1",
		"vpn_exit_stream_1",
		"vpn_session_2",
		"vpn_entry_stream_2",
		"vpn_exit_stream_2",
	}
	idIndex := 0
	VPNIDGenerator = func(prefix string) (string, error) {
		id := ids[idIndex%len(ids)]
		idIndex++
		return id, nil
	}

	notifications := make([]vpnNotificationCapture, 0)
	VPNNotificationSender = func(groupID uint64, message string, mute string) {
		notifications = append(notifications, vpnNotificationCapture{
			groupID: groupID,
			message: message,
			mute:    mute,
		})
	}
	relayCreates := make([]vpnRelayCreateCapture, 0)
	VPNRelayCreator = func(sessionID string, entryStreamID string, entryServerID uint64, exitStreamID string, exitServerID uint64) {
		relayCreates = append(relayCreates, vpnRelayCreateCapture{
			sessionID:     sessionID,
			entryStreamID: entryStreamID,
			entryServerID: entryServerID,
			exitStreamID:  exitStreamID,
			exitServerID:  exitServerID,
		})
	}
	relayCloses := make([]string, 0)
	VPNRelayCloser = func(sessionID string) {
		relayCloses = append(relayCloses, sessionID)
	}

	vpn := NewVPNClass()
	VPNShared = vpn

	t.Cleanup(func() {
		DB = originalDB
		Cache = originalCache
		ServerShared = originalServerShared
		VPNShared = originalVPNShared
		VPNTokenGenerator = originalTokenGenerator
		VPNIDGenerator = originalIDGenerator
		VPNNotificationSender = originalNotificationSender
		VPNRelayCreator = originalRelayCreator
		VPNRelayCloser = originalRelayCloser
		Conf = originalConf
		_ = sqlDB.Close()
	})

	return &vpnHarness{
		vpn:           vpn,
		entryStream:   entryStream,
		exitStream:    exitStream,
		foreignStream: foreignStream,
		notifications: &notifications,
		relayCreates:  &relayCreates,
		relayCloses:   &relayCloses,
		sqlDB:         sqlDB,
	}
}

func (h *vpnHarness) mustServer(id uint64) *model.Server {
	server, ok := ServerShared.Get(id)
	if !ok || server == nil {
		panic(fmt.Sprintf("test server %d not found", id))
	}
	return server
}

func TestVPNSavePolicyRejectsForeignExitForMember(t *testing.T) {
	h := newVPNHarness(t)

	_, err := h.vpn.SavePolicy(VPNActor{UserID: 100, Role: model.RoleMember}, model.AgentVPNPolicyForm{
		Name:           "foreign exit",
		EntryServerID:  1,
		ExitServerID:   3,
		Mode:           model.VPNModeSystemProxy,
		RuleMode:       model.VPNRuleModeGlobal,
		ListenSOCKS:    "127.0.0.1:1080",
		ExpiresSeconds: 3600,
	})
	if err == nil {
		t.Fatal("member must not create a VPN policy using another user's exit server")
	}

	policy, err := h.vpn.SavePolicy(VPNActor{UserID: 1, Role: model.RoleAdmin}, model.AgentVPNPolicyForm{
		Name:           "admin cross owner",
		EntryServerID:  1,
		ExitServerID:   3,
		Mode:           model.VPNModeSystemProxy,
		RuleMode:       model.VPNRuleModeGlobal,
		ListenSOCKS:    "127.0.0.1:1080",
		ExpiresSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("admin should be able to create a cross-owner VPN policy: %v", err)
	}
	if policy.UserID != 1 {
		t.Fatalf("expected policy owner 1, got %d", policy.UserID)
	}
}

func TestVPNSavePolicyRejectsForeignNotificationGroupAtServiceLayer(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}

	_, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "foreign notification group",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 10,
	})
	if err == nil {
		t.Fatal("service layer must reject foreign notification group")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("error = %q, want permission denied", err.Error())
	}
}

func TestVPNUpdatePolicyRejectsForeignNotificationGroupAtServiceLayer(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}

	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "owned notification group",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}

	_, err = h.vpn.UpdatePolicy(actor, policy.ID, model.AgentVPNPolicyForm{
		Name:                "foreign notification group",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 10,
	})
	if err == nil {
		t.Fatal("service layer must reject foreign notification group on update")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("error = %q, want permission denied", err.Error())
	}
}

func TestVPNSavePolicyValidatesUserInput(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	base := model.AgentVPNPolicyForm{
		Name:                "validated policy",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeDomain,
		Domains:             []string{"example.com"},
		DirectCIDRs:         []string{"127.0.0.0/8"},
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	}
	cases := []struct {
		name    string
		mutate  func(*model.AgentVPNPolicyForm)
		wantErr string
	}{
		{
			name: "invalid listen address",
			mutate: func(form *model.AgentVPNPolicyForm) {
				form.ListenSOCKS = "127.0.0.1"
			},
			wantErr: "listen address",
		},
		{
			name: "non loopback listen address",
			mutate: func(form *model.AgentVPNPolicyForm) {
				form.ListenSOCKS = "0.0.0.0:1080"
			},
			wantErr: "loopback",
		},
		{
			name: "invalid cidr",
			mutate: func(form *model.AgentVPNPolicyForm) {
				form.DirectCIDRs = []string{"not-a-cidr"}
			},
			wantErr: "CIDR",
		},
		{
			name: "blank domain",
			mutate: func(form *model.AgentVPNPolicyForm) {
				form.Domains = []string{"example.com", " "}
			},
			wantErr: "domain",
		},
		{
			name: "domain with whitespace",
			mutate: func(form *model.AgentVPNPolicyForm) {
				form.Domains = []string{"bad domain.com"}
			},
			wantErr: "domain",
		},
		{
			name: "zero expires",
			mutate: func(form *model.AgentVPNPolicyForm) {
				form.ExpiresSeconds = 0
			},
			wantErr: "expires",
		},
		{
			name: "invalid mode",
			mutate: func(form *model.AgentVPNPolicyForm) {
				form.Mode = "wireguard"
			},
			wantErr: "unsupported vpn mode",
		},
		{
			name: "invalid rule mode",
			mutate: func(form *model.AgentVPNPolicyForm) {
				form.RuleMode = "suffix"
			},
			wantErr: "unsupported vpn rule mode",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := base
			form.Domains = append([]string(nil), base.Domains...)
			form.CIDRs = append([]string(nil), base.CIDRs...)
			form.DirectCIDRs = append([]string(nil), base.DirectCIDRs...)
			tc.mutate(&form)

			_, err := h.vpn.SavePolicy(actor, form)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestVPNSavePolicyAllowsLocalhostListenAddress(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}

	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "localhost listen policy",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeDomain,
		Domains:             []string{"example.com"},
		ListenSOCKS:         "localhost:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("localhost listen address should match frontend validation and be accepted: %v", err)
	}
	if policy.ListenSOCKS != "localhost:1080" {
		t.Fatalf("listen socks = %q, want localhost:1080", policy.ListenSOCKS)
	}
}

func TestVPNStartSessionStagesExitBeforeEntry(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)

	session, err := h.vpn.StartSession(actor, policy.ID)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	if session.State != model.VPNStateStarting {
		t.Fatalf("expected session starting, got %q", session.State)
	}
	if session.ExitState != model.VPNStateStarting || session.EntryState != model.VPNStateStarting {
		t.Fatalf("unexpected role states: entry=%q exit=%q", session.EntryState, session.ExitState)
	}

	exitTask, exitReq := readVPNTask(t, h.exitStream)
	if exitTask.GetId() != session.ID {
		t.Fatalf("expected task id %d, got %d", session.ID, exitTask.GetId())
	}
	if exitReq.Action != model.VPNActionPrepare || exitReq.Role != model.VPNRoleExit {
		t.Fatalf("expected prepare exit request, got action=%q role=%q", exitReq.Action, exitReq.Role)
	}
	if exitReq.PeerServerID != 0 || exitReq.RelayStreamID != "" || exitReq.Token != "" {
		t.Fatalf("prepare request must not include runtime relay fields, got peer=%d stream=%q token=%q", exitReq.PeerServerID, exitReq.RelayStreamID, exitReq.Token)
	}
	if !strings.HasPrefix(session.TokenHash, "sha256:") {
		t.Fatalf("session token must be stored only as a sha256 hash, got %q", session.TokenHash)
	}
	entryTask, entryPrepareReq := readVPNTask(t, h.entryStream)
	if entryTask.GetId() != session.ID {
		t.Fatalf("expected entry prepare task id %d, got %d", session.ID, entryTask.GetId())
	}
	if entryPrepareReq.Action != model.VPNActionPrepare || entryPrepareReq.Role != model.VPNRoleEntry {
		t.Fatalf("expected prepare entry request, got action=%q role=%q", entryPrepareReq.Action, entryPrepareReq.Role)
	}
	if entryPrepareReq.PeerServerID != 0 || entryPrepareReq.RelayStreamID != "" || entryPrepareReq.Token != "" {
		t.Fatalf("entry prepare request must not include runtime relay fields, got peer=%d stream=%q token=%q", entryPrepareReq.PeerServerID, entryPrepareReq.RelayStreamID, entryPrepareReq.Token)
	}
	if len(*h.relayCreates) != 0 {
		t.Fatalf("relay must not be created before core prepare completes, got %#v", *h.relayCreates)
	}

	session, err = h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionPrepare,
		Role:      model.VPNRoleExit,
		State:     model.VPNStatePrepared,
		Logs:      []string{"[core] prepare=downloaded path=/tmp/sing-box temporary=true"},
	})
	if err != nil {
		t.Fatalf("handle exit prepared: %v", err)
	}
	if session.ExitState != model.VPNStatePrepared || session.EntryState != model.VPNStateStarting {
		t.Fatalf("expected exit prepared and entry still preparing, got entry=%q exit=%q", session.EntryState, session.ExitState)
	}
	assertNoTask(t, h.exitStream)

	session, err = h.vpn.HandleControlResult(policy.EntryServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionPrepare,
		Role:      model.VPNRoleEntry,
		State:     model.VPNStatePrepared,
		Logs:      []string{"[core] prepare=reused path=/tmp/sing-box temporary=true"},
	})
	if err != nil {
		t.Fatalf("handle entry prepared: %v", err)
	}
	if session.ExitState != model.VPNStateStarting || session.EntryState != model.VPNStatePending {
		t.Fatalf("expected exit starting and entry pending after both prepared, got entry=%q exit=%q", session.EntryState, session.ExitState)
	}
	if len(*h.relayCreates) != 1 {
		t.Fatalf("relay must be created once after both agents prepare, got %#v", *h.relayCreates)
	}
	_, exitStartReq := readVPNTask(t, h.exitStream)
	if exitStartReq.Action != model.VPNActionStart || exitStartReq.Role != model.VPNRoleExit {
		t.Fatalf("expected start exit request, got action=%q role=%q", exitStartReq.Action, exitStartReq.Role)
	}
	if exitStartReq.Token == "" {
		t.Fatal("exit start must include the per-session token")
	}
	if strings.Contains(session.TokenHash, exitStartReq.Token) {
		t.Fatalf("session token must be stored only as a sha256 hash, got %q", session.TokenHash)
	}

	session, err = h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	})
	if err != nil {
		t.Fatalf("handle exit running: %v", err)
	}
	if session.ExitState != model.VPNStateRunning || session.EntryState != model.VPNStateStarting {
		t.Fatalf("expected exit running and entry starting, got entry=%q exit=%q", session.EntryState, session.ExitState)
	}
	entryTask, entryReq := readVPNTask(t, h.entryStream)
	if entryTask.GetId() != session.ID {
		t.Fatalf("expected entry task id %d, got %d", session.ID, entryTask.GetId())
	}
	if entryReq.Action != model.VPNActionStart || entryReq.Role != model.VPNRoleEntry {
		t.Fatalf("expected start entry request, got action=%q role=%q", entryReq.Action, entryReq.Role)
	}
	if entryReq.PeerServerID != policy.ExitServerID {
		t.Fatalf("entry request peer must be exit server %d, got %d", policy.ExitServerID, entryReq.PeerServerID)
	}
	if entryReq.RelayStreamID != session.EntryStreamID {
		t.Fatalf("entry relay stream mismatch: want %q got %q", session.EntryStreamID, entryReq.RelayStreamID)
	}
	if entryReq.Token != exitStartReq.Token {
		t.Fatal("entry and exit agents must receive the same per-session token")
	}

	session, err = h.vpn.HandleControlResult(policy.EntryServerID, model.VPNControlResult{
		SessionID:     session.SessionID,
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		State:         model.VPNStateRunning,
		LocalSOCKS:    "127.0.0.1:1080",
		UploadBytes:   12,
		DownloadBytes: 34,
		ActiveConns:   2,
		Logs:          []string{"[egress] observed_ip=198.51.100.20 expected=198.51.100.20 match=true"},
	})
	if err != nil {
		t.Fatalf("handle entry running: %v", err)
	}
	if session.State != model.VPNStateRunning {
		t.Fatalf("expected session running, got %q", session.State)
	}
	if session.UploadBytes != 12 || session.DownloadBytes != 34 || session.ActiveConnections != 2 {
		t.Fatalf("traffic counters not updated: upload=%d download=%d conns=%d", session.UploadBytes, session.DownloadBytes, session.ActiveConnections)
	}
	if session.LocalSOCKS != "127.0.0.1:1080" {
		t.Fatalf("local SOCKS was not updated from agent result: %q", session.LocalSOCKS)
	}
	logs := strings.Join(h.vpn.SessionLogs(session.SessionID), "\n")
	if !strings.Contains(logs, "sent prepare request to exit agent") ||
		!strings.Contains(logs, "[core] prepare=downloaded") ||
		!strings.Contains(logs, "sent start request to exit agent") ||
		!strings.Contains(logs, "agent report server=") ||
		!strings.Contains(logs, "session started; entry and exit agents are running") {
		t.Fatalf("control plane logs missing dispatch/result/running markers: %s", logs)
	}
	if len(*h.notifications) != 1 {
		t.Fatalf("expected one start-success notification, got %d", len(*h.notifications))
	}
	notification := (*h.notifications)[0]
	if notification.groupID != policy.NotificationGroupID {
		t.Fatalf("expected notification group %d, got %d", policy.NotificationGroupID, notification.groupID)
	}
	if !strings.Contains(notification.message, "[Agent VPN] 已启动") || !strings.Contains(notification.message, "入口节点: entry-cn") || !strings.Contains(notification.message, "出口节点: exit-jp") {
		t.Fatalf("notification content is incomplete: %q", notification.message)
	}
	for _, want := range []string{
		"策略: GitHub Split",
		"状态: running",
		"本地代理: SOCKS 127.0.0.1:1080",
		"上传/下载: 12 B / 34 B",
		"时间:",
	} {
		if !strings.Contains(notification.message, want) {
			t.Fatalf("start notification must include %q, got %q", want, notification.message)
		}
	}
	if !strings.Contains(notification.message, "出口探测: observed_ip=198.51.100.20 expected=198.51.100.20 match=true") {
		t.Fatalf("start notification must include the entry egress probe summary, got %q", notification.message)
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionStartSession, session.SessionID, true).Last(&audit).Error; err != nil {
		t.Fatalf("start success must write an audit record: %v", err)
	}
	if audit.Detail["egress_probe"] != "observed_ip=198.51.100.20 expected=198.51.100.20 match=true" {
		t.Fatalf("start success audit must persist egress probe summary, got detail=%#v", audit.Detail)
	}
}

func TestVPNPolicyWithoutNotificationGroupDoesNotSendNotifications(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:           "silent vpn",
		EntryServerID:  1,
		ExitServerID:   2,
		Mode:           model.VPNModeSystemProxy,
		RuleMode:       model.VPNRuleModeGlobal,
		ListenSOCKS:    "127.0.0.1:1080",
		ExpiresSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("save silent policy: %v", err)
	}

	startAndRunTestVPNSession(t, h, actor, policy)

	if len(*h.notifications) != 0 {
		t.Fatalf("notification group 0 must not send VPN notifications, got %#v", *h.notifications)
	}
}

func TestVPNStartSessionRejectsServersWithoutReportedCapabilities(t *testing.T) {
	cases := []struct {
		name       string
		form       model.AgentVPNPolicyForm
		mutate     func(*vpnHarness)
		wantErr    string
		wantAudits int64
	}{
		{
			name: "entry missing host report",
			form: model.AgentVPNPolicyForm{
				Name:                "missing entry capability",
				EntryServerID:       1,
				ExitServerID:        2,
				Mode:                model.VPNModeSystemProxy,
				RuleMode:            model.VPNRuleModeGlobal,
				ListenSOCKS:         "127.0.0.1:1080",
				ExpiresSeconds:      3600,
				NotificationGroupID: 9,
			},
			mutate: func(h *vpnHarness) {
				h.mustServer(1).Host = nil
			},
			wantErr: "entry server 1 has not reported Agent VPN capability",
		},
		{
			name: "entry disallows system proxy mode",
			form: model.AgentVPNPolicyForm{
				Name:                "system proxy disallowed",
				EntryServerID:       1,
				ExitServerID:        2,
				Mode:                model.VPNModeSystemProxy,
				RuleMode:            model.VPNRuleModeGlobal,
				ListenSOCKS:         "127.0.0.1:1080",
				ExpiresSeconds:      3600,
				NotificationGroupID: 9,
			},
			mutate: func(h *vpnHarness) {
				h.mustServer(1).Host.VPNAllowSystemProxy = false
			},
			wantErr: "entry server 1 does not allow Agent VPN system_proxy mode",
		},
		{
			name: "entry disallows TUN mode",
			form: model.AgentVPNPolicyForm{
				Name:                "tun disallowed",
				EntryServerID:       1,
				ExitServerID:        2,
				Mode:                model.VPNModeTunSplit,
				RuleMode:            model.VPNRuleModeGlobal,
				TunName:             "nezha-vpn",
				ExpiresSeconds:      3600,
				NotificationGroupID: 9,
			},
			mutate: func(h *vpnHarness) {
				h.mustServer(1).Host.VPNAllowTun = false
			},
			wantErr: "entry server 1 does not allow Agent VPN TUN mode",
		},
		{
			name: "exit VPN disabled",
			form: model.AgentVPNPolicyForm{
				Name:                "exit disabled",
				EntryServerID:       1,
				ExitServerID:        2,
				Mode:                model.VPNModeSystemProxy,
				RuleMode:            model.VPNRuleModeGlobal,
				ListenSOCKS:         "127.0.0.1:1080",
				ExpiresSeconds:      3600,
				NotificationGroupID: 9,
			},
			mutate: func(h *vpnHarness) {
				h.mustServer(2).Host.VPNEnabled = false
			},
			wantErr: "exit server 2 has not reported Agent VPN capability",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newVPNHarness(t)
			actor := VPNActor{UserID: 100, Role: model.RoleMember}
			if tc.mutate != nil {
				tc.mutate(h)
			}
			policy, err := h.vpn.SavePolicy(actor, tc.form)
			if err != nil {
				t.Fatalf("save policy: %v", err)
			}

			session, err := h.vpn.StartSession(actor, policy.ID)
			if err == nil {
				t.Fatal("expected start session to reject unsupported Agent VPN capability")
			}
			if session != nil {
				t.Fatalf("unsupported capability must fail before creating a session, got %#v", session)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
			assertNoTask(t, h.entryStream)
			assertNoTask(t, h.exitStream)
			if len(*h.relayCreates) != 0 {
				t.Fatalf("unsupported capability must not create relay endpoints, got %#v", *h.relayCreates)
			}
			var count int64
			if err := DB.Model(&model.AgentVPNSession{}).Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatalf("unsupported capability must not persist a session, got %d", count)
			}
			if len(*h.notifications) != 1 {
				t.Fatalf("unsupported capability must send one start-failure notification, got %#v", *h.notifications)
			}
			notification := (*h.notifications)[0]
			if notification.groupID != policy.NotificationGroupID {
				t.Fatalf("failure notification group mismatch: want %d got %d", policy.NotificationGroupID, notification.groupID)
			}
			if !strings.Contains(notification.message, "[Agent VPN] 启动失败") || !strings.Contains(notification.message, tc.wantErr) {
				t.Fatalf("failure notification must include the capability error, got %q", notification.message)
			}
			var audit model.AgentVPNAuditLog
			if err := DB.Where("action = ? AND entry_server_id = ? AND exit_server_id = ?", model.VPNAuditActionStartSession, policy.EntryServerID, policy.ExitServerID).Last(&audit).Error; err != nil {
				t.Fatalf("unsupported capability must write start-failure audit: %v", err)
			}
			if audit.Success {
				t.Fatal("unsupported capability audit must be marked failed")
			}
			if !strings.Contains(audit.Message, tc.wantErr) {
				t.Fatalf("unsupported capability audit must include the capability error, got %q", audit.Message)
			}
		})
	}
}

func TestVPNStartSessionRejectsLegacyPolicyWithInvalidModeBeforeRuntime(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}

	if err := DB.Create(&model.AgentVPNPolicy{
		Common:              model.Common{ID: 991, UserID: actor.UserID},
		Name:                "legacy invalid mode",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                "wireguard",
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	}).Error; err != nil {
		t.Fatal(err)
	}

	session, err := h.vpn.StartSession(actor, 991)
	if err == nil {
		t.Fatal("legacy policy with invalid mode must be rejected before runtime")
	}
	if session != nil {
		t.Fatalf("legacy invalid mode must fail before creating session, got %#v", session)
	}
	if !strings.Contains(err.Error(), `unsupported vpn mode "wireguard"`) {
		t.Fatalf("error = %q, want unsupported vpn mode", err.Error())
	}
	assertNoTask(t, h.entryStream)
	assertNoTask(t, h.exitStream)
	if len(*h.relayCreates) != 0 {
		t.Fatalf("legacy invalid mode must not create relay endpoints, got %#v", *h.relayCreates)
	}
	var count int64
	if err := DB.Model(&model.AgentVPNSession{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("legacy invalid mode must not persist session, got %d", count)
	}
}

func TestVPNStartSessionRejectsLegacyPolicyWithInvalidRuleModeBeforeRuntime(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}

	if err := DB.Create(&model.AgentVPNPolicy{
		Common:              model.Common{ID: 992, UserID: actor.UserID},
		Name:                "legacy invalid rule mode",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            "suffix",
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	}).Error; err != nil {
		t.Fatal(err)
	}

	session, err := h.vpn.StartSession(actor, 992)
	if err == nil {
		t.Fatal("legacy policy with invalid rule mode must be rejected before runtime")
	}
	if session != nil {
		t.Fatalf("legacy invalid rule mode must fail before creating session, got %#v", session)
	}
	if !strings.Contains(err.Error(), `unsupported vpn rule mode "suffix"`) {
		t.Fatalf("error = %q, want unsupported vpn rule mode", err.Error())
	}
	assertNoTask(t, h.entryStream)
	assertNoTask(t, h.exitStream)
	if len(*h.relayCreates) != 0 {
		t.Fatalf("legacy invalid rule mode must not create relay endpoints, got %#v", *h.relayCreates)
	}
	var count int64
	if err := DB.Model(&model.AgentVPNSession{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("legacy invalid rule mode must not persist session, got %d", count)
	}
}

func TestVPNStartSessionRejectsLegacyPolicyWithInvalidListenAddressBeforeRuntime(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}

	if err := DB.Create(&model.AgentVPNPolicy{
		Common:              model.Common{ID: 993, UserID: actor.UserID},
		Name:                "legacy invalid listen",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "0.0.0.0:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	}).Error; err != nil {
		t.Fatal(err)
	}

	session, err := h.vpn.StartSession(actor, 993)
	if err == nil {
		t.Fatal("legacy policy with invalid listen address must be rejected before runtime")
	}
	if session != nil {
		t.Fatalf("legacy invalid listen address must fail before creating session, got %#v", session)
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("error = %q, want loopback validation", err.Error())
	}
	assertNoTask(t, h.entryStream)
	assertNoTask(t, h.exitStream)
	if len(*h.relayCreates) != 0 {
		t.Fatalf("legacy invalid listen address must not create relay endpoints, got %#v", *h.relayCreates)
	}
	var count int64
	if err := DB.Model(&model.AgentVPNSession{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("legacy invalid listen address must not persist session, got %d", count)
	}
}

func TestVPNStartSessionNotifiesAndAuditsOfflinePreflightFailure(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	h.mustServer(policy.EntryServerID).SetTaskStream(nil)

	session, err := h.vpn.StartSession(actor, policy.ID)
	if err == nil {
		t.Fatal("offline entry must reject VPN start")
	}
	if session != nil {
		t.Fatalf("offline preflight failure must not create a session, got %#v", session)
	}
	if !strings.Contains(err.Error(), "entry server 1 is offline") {
		t.Fatalf("error = %q, want offline entry reason", err.Error())
	}
	assertNoTask(t, h.exitStream)
	if len(*h.relayCreates) != 0 {
		t.Fatalf("offline preflight failure must not create relay endpoints, got %#v", *h.relayCreates)
	}
	if len(*h.notifications) != 1 {
		t.Fatalf("offline preflight failure must send one start-failure notification, got %#v", *h.notifications)
	}
	if (*h.notifications)[0].groupID != policy.NotificationGroupID || !strings.Contains((*h.notifications)[0].message, "entry server 1 is offline") {
		t.Fatalf("offline preflight notification is incomplete: %#v", *h.notifications)
	}
	notification := (*h.notifications)[0].message
	for _, want := range []string{
		"策略: GitHub Split",
		"Session: -",
		"入口节点: entry-cn",
		"出口节点: exit-jp",
		"模式: system_proxy",
		"状态: failed",
		"本地代理: SOCKS 127.0.0.1:1080",
		"错误原因: entry server 1 is offline",
		"时间:",
	} {
		if !strings.Contains(notification, want) {
			t.Fatalf("offline preflight notification must include %q, got %q", want, notification)
		}
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND entry_server_id = ? AND exit_server_id = ?", model.VPNAuditActionStartSession, policy.EntryServerID, policy.ExitServerID).Last(&audit).Error; err != nil {
		t.Fatalf("offline preflight failure must write start-failure audit: %v", err)
	}
	if audit.Success || !strings.Contains(audit.Message, "entry server 1 is offline") {
		t.Fatalf("offline preflight audit must be failed and include reason, got success=%v message=%q", audit.Success, audit.Message)
	}
}

func TestVPNStartSessionNotifiesAndAuditsTokenGenerationFailure(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	VPNTokenGenerator = func() (string, error) {
		return "", errors.New("token entropy unavailable")
	}

	session, err := h.vpn.StartSession(actor, policy.ID)
	if err == nil {
		t.Fatal("token generation failure must reject VPN start")
	}
	if session != nil {
		t.Fatalf("token generation failure must not create a session, got %#v", session)
	}
	if !strings.Contains(err.Error(), "token entropy unavailable") {
		t.Fatalf("error = %q, want token generator reason", err.Error())
	}
	assertNoTask(t, h.exitStream)
	if len(*h.relayCreates) != 0 {
		t.Fatalf("token generation failure must not create relay endpoints, got %#v", *h.relayCreates)
	}
	if len(*h.notifications) != 1 {
		t.Fatalf("token generation failure must send one start-failure notification, got %#v", *h.notifications)
	}
	if (*h.notifications)[0].groupID != policy.NotificationGroupID || !strings.Contains((*h.notifications)[0].message, "token entropy unavailable") {
		t.Fatalf("token generation failure notification is incomplete: %#v", *h.notifications)
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND entry_server_id = ? AND exit_server_id = ?", model.VPNAuditActionStartSession, policy.EntryServerID, policy.ExitServerID).Last(&audit).Error; err != nil {
		t.Fatalf("token generation failure must write start-failure audit: %v", err)
	}
	if audit.Success || !strings.Contains(audit.Message, "token entropy unavailable") {
		t.Fatalf("token generation audit must be failed and include reason, got success=%v message=%q", audit.Success, audit.Message)
	}
	if audit.Detail["stage"] != "token_generation" {
		t.Fatalf("token generation audit detail mismatch: %#v", audit.Detail)
	}
}

func TestVPNStartSessionNotifiesAndAuditsIDGenerationFailure(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	VPNIDGenerator = func(prefix string) (string, error) {
		if prefix == "vpn_entry_" {
			return "", errors.New("entry stream id generator unavailable")
		}
		return prefix + "ok", nil
	}

	session, err := h.vpn.StartSession(actor, policy.ID)
	if err == nil {
		t.Fatal("id generation failure must reject VPN start")
	}
	if session != nil {
		t.Fatalf("id generation failure must not create a session, got %#v", session)
	}
	if !strings.Contains(err.Error(), "entry stream id generator unavailable") {
		t.Fatalf("error = %q, want id generator reason", err.Error())
	}
	assertNoTask(t, h.exitStream)
	if len(*h.relayCreates) != 0 {
		t.Fatalf("id generation failure must not create relay endpoints, got %#v", *h.relayCreates)
	}
	if len(*h.notifications) != 1 {
		t.Fatalf("id generation failure must send one start-failure notification, got %#v", *h.notifications)
	}
	if (*h.notifications)[0].groupID != policy.NotificationGroupID || !strings.Contains((*h.notifications)[0].message, "entry stream id generator unavailable") {
		t.Fatalf("id generation failure notification is incomplete: %#v", *h.notifications)
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND entry_server_id = ? AND exit_server_id = ?", model.VPNAuditActionStartSession, policy.EntryServerID, policy.ExitServerID).Last(&audit).Error; err != nil {
		t.Fatalf("id generation failure must write start-failure audit: %v", err)
	}
	if audit.Success || !strings.Contains(audit.Message, "entry stream id generator unavailable") {
		t.Fatalf("id generation audit must be failed and include reason, got success=%v message=%q", audit.Success, audit.Message)
	}
	if audit.Detail["stage"] != "entry_stream_id_generation" {
		t.Fatalf("id generation audit detail mismatch: %#v", audit.Detail)
	}
}

func TestVPNSavePolicyWritesAuditWithRulesAndLimits(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}

	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                    "audited policy",
		EntryServerID:           1,
		ExitServerID:            2,
		Mode:                    model.VPNModeTunSplit,
		RuleMode:                model.VPNRuleModeDomain,
		Domains:                 []string{"github.com", "api.github.com"},
		CIDRs:                   []string{"140.82.112.0/20"},
		DirectCIDRs:             []string{"127.0.0.0/8"},
		TunName:                 "nezha-vpn",
		ExpiresSeconds:          7200,
		MaxUploadBytes:          1024,
		MaxDownloadBytes:        2048,
		MaxConnections:          32,
		IdleTimeoutSeconds:      60,
		NotificationGroupID:     9,
		SetSystemProxy:          true,
		TunHealthURL:            "https://health.example.com/generate_204",
		TunHealthTimeoutSeconds: 12,
		EgressProbeURL:          "https://ip.example.com/json",
		CoreVersion:             "1.12.0",
		CoreDownloadURL:         "https://download.example.com/sing-box",
		CoreSHA256:              "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}

	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND entry_server_id = ? AND exit_server_id = ?", model.VPNAuditActionCreatePolicy, policy.EntryServerID, policy.ExitServerID).Last(&audit).Error; err != nil {
		t.Fatalf("load audit: %v", err)
	}
	for key, want := range map[string]string{
		"policy_id":                  fmt.Sprint(policy.ID),
		"mode":                       model.VPNModeTunSplit,
		"rule_mode":                  model.VPNRuleModeDomain,
		"domains":                    "github.com,api.github.com",
		"cidrs":                      "140.82.112.0/20",
		"direct_cidrs":               "127.0.0.0/8",
		"expires_seconds":            "7200",
		"max_upload_bytes":           "1024",
		"max_download_bytes":         "2048",
		"max_connections":            "32",
		"idle_timeout_seconds":       "60",
		"set_system_proxy":           "true",
		"tun_health_url":             "https://health.example.com/generate_204",
		"tun_health_timeout_seconds": "12",
		"egress_probe_url":           "https://ip.example.com/json",
		"core_version":               "1.12.0",
		"core_download_url":          "https://download.example.com/sing-box",
		"core_sha256":                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	} {
		if audit.Detail[key] != want {
			t.Fatalf("audit detail %q = %q, want %q; detail=%#v", key, audit.Detail[key], want, audit.Detail)
		}
	}
}

func TestVPNDeletePoliciesWritesAuditWithPolicySnapshot(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}

	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "delete audited policy",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeDomain,
		Domains:             []string{"example.com"},
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}

	if err := h.vpn.DeletePolicies(actor, []uint64{policy.ID}); err != nil {
		t.Fatalf("delete policy: %v", err)
	}

	var policyCount int64
	if err := DB.Model(&model.AgentVPNPolicy{}).Where("id = ?", policy.ID).Count(&policyCount).Error; err != nil {
		t.Fatalf("count policies: %v", err)
	}
	if policyCount != 0 {
		t.Fatalf("policy must be deleted, count=%d", policyCount)
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND entry_server_id = ? AND exit_server_id = ?", model.VPNAuditActionDeletePolicy, policy.EntryServerID, policy.ExitServerID).Last(&audit).Error; err != nil {
		t.Fatalf("delete policy must write audit: %v", err)
	}
	if !audit.Success || audit.Message != "policy deleted" {
		t.Fatalf("delete audit mismatch: success=%v message=%q", audit.Success, audit.Message)
	}
	for key, want := range map[string]string{
		"policy_id":    fmt.Sprint(policy.ID),
		"policy_name":  "delete audited policy",
		"mode":         model.VPNModeSystemProxy,
		"rule_mode":    model.VPNRuleModeDomain,
		"domains":      "example.com",
		"listen_socks": "127.0.0.1:1080",
	} {
		if audit.Detail[key] != want {
			t.Fatalf("delete audit detail %q = %q, want %q; detail=%#v", key, audit.Detail[key], want, audit.Detail)
		}
	}
}

func TestVPNDeletePoliciesRejectsPolicyWhenServerOwnershipChanged(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}

	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "transferred server policy",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}
	entry := h.mustServer(1)
	entry.SetUserID(200)

	err = h.vpn.DeletePolicies(actor, []uint64{policy.ID})

	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("delete must reject policy whose entry or exit server is no longer permitted, err=%v", err)
	}
	var policyCount int64
	if err := DB.Model(&model.AgentVPNPolicy{}).Where("id = ?", policy.ID).Count(&policyCount).Error; err != nil {
		t.Fatalf("count policies: %v", err)
	}
	if policyCount != 1 {
		t.Fatalf("policy must remain after permission denial, count=%d", policyCount)
	}
	var deleteAuditCount int64
	if err := DB.Model(&model.AgentVPNAuditLog{}).Where("action = ?", model.VPNAuditActionDeletePolicy).Count(&deleteAuditCount).Error; err != nil {
		t.Fatalf("count delete audits: %v", err)
	}
	if deleteAuditCount != 0 {
		t.Fatalf("permission denial must not write delete audit, count=%d", deleteAuditCount)
	}
}

func TestVPNStartSessionPassesSystemProxyFlagToEntryAgent(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "system proxy auto apply",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
		SetSystemProxy:      true,
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}
	session, err := h.vpn.StartSession(actor, policy.ID)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	prepareAndDispatchExitStartForTest(t, h, session, policy)

	if _, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	}); err != nil {
		t.Fatalf("handle exit running: %v", err)
	}
	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.Extra["set_system_proxy"] != "true" {
		t.Fatalf("entry start must enable system proxy setup when policy requests it, extra=%#v", entryReq.Extra)
	}
}

func TestVPNStartSessionPassesIdleTimeoutLimitToEntryAgent(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "idle timeout vpn",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		MaxConnections:      128,
		IdleTimeoutSeconds:  45,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}
	session, err := h.vpn.StartSession(actor, policy.ID)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	prepareAndDispatchExitStartForTest(t, h, session, policy)

	if _, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	}); err != nil {
		t.Fatalf("handle exit running: %v", err)
	}
	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.Limits.IdleTimeoutSeconds != 45 {
		t.Fatalf("entry start must include idle timeout limit, got %d", entryReq.Limits.IdleTimeoutSeconds)
	}
}

func TestVPNStartSessionPassesPolicyCoreSpecToAgents(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	coreSHA256 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "downloaded core vpn",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
		CoreVersion:         "1.12.0",
		CoreDownloadURL:     " https://download.example.com/sing-box.exe ",
		CoreSHA256:          " " + coreSHA256 + " ",
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}
	if policy.CoreDownloadURL != "https://download.example.com/sing-box.exe" {
		t.Fatalf("policy core download URL must be normalized, got %q", policy.CoreDownloadURL)
	}
	if policy.CoreSHA256 != coreSHA256 {
		t.Fatalf("policy core sha256 must be normalized, got %q", policy.CoreSHA256)
	}

	if _, err := h.vpn.StartSession(actor, policy.ID); err != nil {
		t.Fatalf("start session: %v", err)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.Action != model.VPNActionPrepare || exitReq.Role != model.VPNRoleExit {
		t.Fatalf("expected exit prepare request, got %+v", exitReq)
	}
	assertVPNCoreSpec(t, exitReq.Core)
	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.Action != model.VPNActionPrepare || entryReq.Role != model.VPNRoleEntry {
		t.Fatalf("expected entry prepare request, got %+v", entryReq)
	}
	assertVPNCoreSpec(t, entryReq.Core)
}

func TestVPNStartSessionPassesDefaultCoreMirrorsToAgents(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)

	if _, err := h.vpn.StartSession(actor, policy.ID); err != nil {
		t.Fatalf("start session: %v", err)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.Action != model.VPNActionPrepare || exitReq.Role != model.VPNRoleExit {
		t.Fatalf("expected exit prepare request, got %+v", exitReq)
	}
	if exitReq.Core.DownloadURL != "" {
		t.Fatalf("default core spec must not force a single download URL, got %q", exitReq.Core.DownloadURL)
	}
	if exitReq.Core.DownloadBaseURL != defaultVPNCoreDownloadBaseURL {
		t.Fatalf("default core base URL = %q, want %q", exitReq.Core.DownloadBaseURL, defaultVPNCoreDownloadBaseURL)
	}
	if exitReq.Core.CNDownloadBaseURL != defaultVPNCoreCNDownloadBaseURL {
		t.Fatalf("default core CN base URL = %q, want %q", exitReq.Core.CNDownloadBaseURL, defaultVPNCoreCNDownloadBaseURL)
	}
	if exitReq.Core.ManifestURL != defaultVPNCoreManifestURL {
		t.Fatalf("default core manifest URL = %q, want %q", exitReq.Core.ManifestURL, defaultVPNCoreManifestURL)
	}
	if exitReq.Core.CNManifestURL != defaultVPNCoreCNManifestURL {
		t.Fatalf("default core CN manifest URL = %q, want %q", exitReq.Core.CNManifestURL, defaultVPNCoreCNManifestURL)
	}
}

func TestVPNSavePolicyRejectsInvalidCoreSHA256(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}

	_, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "bad core hash",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
		CoreSHA256:          "sha256:abcdef",
	})
	if err == nil {
		t.Fatal("invalid core sha256 must be rejected")
	}
	if !strings.Contains(err.Error(), "core sha256 must be a 64-character hex digest without prefix") {
		t.Fatalf("error = %q, want core sha256 validation reason", err.Error())
	}
}

func TestVPNSavePolicyRejectsPrefixedCoreSHA256(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}

	_, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "prefixed core hash",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
		CoreSHA256:          "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	if err == nil {
		t.Fatal("prefixed core sha256 must be rejected")
	}
	if !strings.Contains(err.Error(), "core sha256 must be a 64-character hex digest without prefix") {
		t.Fatalf("error = %q, want no-prefix validation reason", err.Error())
	}
}

func TestVPNSavePolicyRejectsInvalidProbeURLs(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	cases := []struct {
		name    string
		form    model.AgentVPNPolicyForm
		wantErr string
	}{
		{
			name: "egress probe must use HTTP",
			form: model.AgentVPNPolicyForm{
				Name:                "bad egress probe",
				EntryServerID:       1,
				ExitServerID:        2,
				Mode:                model.VPNModeSystemProxy,
				RuleMode:            model.VPNRuleModeGlobal,
				ListenSOCKS:         "127.0.0.1:1080",
				ExpiresSeconds:      3600,
				NotificationGroupID: 9,
				EgressProbeURL:      "ftp://ifconfig.example/ip",
			},
			wantErr: "egress probe url must use http or https",
		},
		{
			name: "tun health only supports TUN mode",
			form: model.AgentVPNPolicyForm{
				Name:                "bad tun health mode",
				EntryServerID:       1,
				ExitServerID:        2,
				Mode:                model.VPNModeSystemProxy,
				RuleMode:            model.VPNRuleModeGlobal,
				ListenSOCKS:         "127.0.0.1:1080",
				ExpiresSeconds:      3600,
				NotificationGroupID: 9,
				TunHealthURL:        "https://connectivity.example.com/generate_204",
			},
			wantErr: "tun health probe is only supported for TUN mode",
		},
		{
			name: "tun health must use HTTP",
			form: model.AgentVPNPolicyForm{
				Name:                "bad tun health url",
				EntryServerID:       1,
				ExitServerID:        2,
				Mode:                model.VPNModeTunSplit,
				RuleMode:            model.VPNRuleModeGlobal,
				TunName:             "nezha-vpn",
				ExpiresSeconds:      3600,
				NotificationGroupID: 9,
				TunHealthURL:        "file:///tmp/health",
			},
			wantErr: "tun health url must use http or https",
		},
		{
			name: "core download must use HTTP",
			form: model.AgentVPNPolicyForm{
				Name:                "bad core download",
				EntryServerID:       1,
				ExitServerID:        2,
				Mode:                model.VPNModeSystemProxy,
				RuleMode:            model.VPNRuleModeGlobal,
				ListenSOCKS:         "127.0.0.1:1080",
				ExpiresSeconds:      3600,
				NotificationGroupID: 9,
				CoreDownloadURL:     "file:///tmp/sing-box",
			},
			wantErr: "core download url must use http or https",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.vpn.SavePolicy(actor, tc.form)
			if err == nil {
				t.Fatal("invalid probe/core URL must be rejected")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestVPNStartSessionPassesTunHealthProbeToEntryTunAgent(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                    "tun health",
		EntryServerID:           1,
		ExitServerID:            2,
		Mode:                    model.VPNModeTunGlobal,
		RuleMode:                model.VPNRuleModeGlobal,
		TunName:                 "nezha-vpn",
		ExpiresSeconds:          3600,
		NotificationGroupID:     9,
		TunHealthURL:            "https://connectivity.example.com/generate_204",
		TunHealthTimeoutSeconds: 7,
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}
	session, err := h.vpn.StartSession(actor, policy.ID)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if _, ok := exitReq.Extra["tun_health_url"]; ok {
		t.Fatalf("exit agent must not receive entry TUN health probe config, extra=%#v", exitReq.Extra)
	}
	readVPNTask(t, h.entryStream)
	exitStartReq := dispatchExitStartAfterPreparedForTest(t, h, session, policy)
	if _, ok := exitStartReq.Extra["tun_health_url"]; ok {
		t.Fatalf("exit start must not receive entry TUN health probe config, extra=%#v", exitStartReq.Extra)
	}

	if _, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	}); err != nil {
		t.Fatalf("handle exit running: %v", err)
	}
	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.Extra["tun_health_url"] != "https://connectivity.example.com/generate_204" {
		t.Fatalf("entry TUN start must include health probe URL, extra=%#v", entryReq.Extra)
	}
	if entryReq.Extra["tun_health_timeout_seconds"] != "7" {
		t.Fatalf("entry TUN start must include health probe timeout, extra=%#v", entryReq.Extra)
	}
}

func TestVPNSavePolicyNormalizesTunHealthTimeoutToFrontendRange(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}

	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                    "tun health timeout normalized",
		EntryServerID:           1,
		ExitServerID:            2,
		Mode:                    model.VPNModeTunSplit,
		RuleMode:                model.VPNRuleModeGlobal,
		TunName:                 "nezha-vpn",
		ExpiresSeconds:          3600,
		NotificationGroupID:     9,
		TunHealthURL:            "https://connectivity.example.com/generate_204",
		TunHealthTimeoutSeconds: 0,
	})
	if err != nil {
		t.Fatalf("save policy with zero tun health timeout: %v", err)
	}
	if policy.TunHealthTimeoutSeconds != 10 {
		t.Fatalf("zero tun health timeout must normalize to 10, got %d", policy.TunHealthTimeoutSeconds)
	}

	policy, err = h.vpn.UpdatePolicy(actor, policy.ID, model.AgentVPNPolicyForm{
		Name:                    "tun health timeout normalized updated",
		EntryServerID:           1,
		ExitServerID:            2,
		Mode:                    model.VPNModeTunSplit,
		RuleMode:                model.VPNRuleModeGlobal,
		TunName:                 "nezha-vpn",
		ExpiresSeconds:          3600,
		NotificationGroupID:     9,
		TunHealthURL:            "https://connectivity.example.com/generate_204",
		TunHealthTimeoutSeconds: 99,
	})
	if err != nil {
		t.Fatalf("update policy with oversized tun health timeout: %v", err)
	}
	if policy.TunHealthTimeoutSeconds != 60 {
		t.Fatalf("oversized tun health timeout must clamp to 60, got %d", policy.TunHealthTimeoutSeconds)
	}
}

func TestVPNStartSessionPassesEgressProbeOnlyToEntryAgent(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "egress probe",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
		EgressProbeURL:      " https://ifconfig.example/ip ",
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}
	if policy.EgressProbeURL != "https://ifconfig.example/ip" {
		t.Fatalf("policy egress probe URL must be normalized, got %q", policy.EgressProbeURL)
	}
	session, err := h.vpn.StartSession(actor, policy.ID)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if _, ok := exitReq.Extra["egress_probe_url"]; ok {
		t.Fatalf("exit agent must not receive entry egress probe config, extra=%#v", exitReq.Extra)
	}
	readVPNTask(t, h.entryStream)
	exitStartReq := dispatchExitStartAfterPreparedForTest(t, h, session, policy)
	if _, ok := exitStartReq.Extra["egress_probe_url"]; ok {
		t.Fatalf("exit start must not receive entry egress probe config, extra=%#v", exitStartReq.Extra)
	}

	if _, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	}); err != nil {
		t.Fatalf("handle exit running: %v", err)
	}
	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.Extra["egress_probe_url"] != "https://ifconfig.example/ip" {
		t.Fatalf("entry start must include egress probe URL, extra=%#v", entryReq.Extra)
	}
	if entryReq.Extra["egress_expected_ips"] != "198.51.100.20,2001:db8::20" {
		t.Fatalf("entry start must include exit agent expected egress IPs, extra=%#v", entryReq.Extra)
	}
}

func TestVPNStartSessionPassesTunDNSServerToEntryTunAgent(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "tun dns",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeTunSplit,
		RuleMode:            model.VPNRuleModeDomain,
		Domains:             []string{"example.com"},
		TunName:             "nezha-vpn",
		DNSServer:           "https://9.9.9.9/dns-query",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}
	session, err := h.vpn.StartSession(actor, policy.ID)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.DNSServer != "" {
		t.Fatalf("exit agent must not receive entry TUN DNS server, got %q", exitReq.DNSServer)
	}
	readVPNTask(t, h.entryStream)
	exitStartReq := dispatchExitStartAfterPreparedForTest(t, h, session, policy)
	if exitStartReq.DNSServer != "" {
		t.Fatalf("exit start must not receive entry TUN DNS server, got %q", exitStartReq.DNSServer)
	}

	if _, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	}); err != nil {
		t.Fatalf("handle exit running: %v", err)
	}
	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.DNSServer != "https://9.9.9.9/dns-query" {
		t.Fatalf("entry TUN start must include DNS server, got %q", entryReq.DNSServer)
	}
}

func TestVPNStartSessionPassesDynamicDashboardBypassToEntryTunAgent(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "tun global bypass",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeTunGlobal,
		RuleMode:            model.VPNRuleModeGlobal,
		TunName:             "nezha-vpn",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}
	session, err := h.vpn.StartSession(actor, policy.ID)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	readVPNTask(t, h.exitStream)
	readVPNTask(t, h.entryStream)
	exitStartReq := dispatchExitStartAfterPreparedForTest(t, h, session, policy)
	assertVPNBypassContains(t, exitStartReq.DashboardBypass, "dashboard.example.com", "198.51.100.20", "2001:db8::20")
	assertVPNBypassNotContains(t, exitStartReq.DashboardBypass, "127.0.0.0/8", "::1/128", "169.254.0.0/16", "169.254.169.254/32", "fe80::/10")

	if _, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	}); err != nil {
		t.Fatalf("handle exit running: %v", err)
	}
	_, entryReq := readVPNTask(t, h.entryStream)
	assertVPNBypassContains(t, entryReq.DashboardBypass, "dashboard.example.com", "198.51.100.20", "2001:db8::20")
	assertVPNBypassNotContains(t, entryReq.DashboardBypass, "127.0.0.0/8", "::1/128", "169.254.0.0/16", "169.254.169.254/32", "fe80::/10")
}

func TestVPNControlResultRejectsReporterNotBoundToSession(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session, err := h.vpn.StartSession(actor, policy.ID)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	readVPNTask(t, h.exitStream)
	readVPNTask(t, h.entryStream)

	_, err = h.vpn.HandleControlResult(3, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionPrepare,
		Role:      model.VPNRoleExit,
		State:     model.VPNStatePrepared,
	})
	if err == nil {
		t.Fatal("foreign reporter must not be allowed to advance the VPN session")
	}
	assertNoTask(t, h.entryStream)

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.ExitState != model.VPNStateStarting || stored.EntryState != model.VPNStateStarting {
		t.Fatalf("foreign report changed session state: entry=%q exit=%q", stored.EntryState, stored.ExitState)
	}
}

func TestVPNControlResultCachesAgentSidecarLogs(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)

	if _, err := h.vpn.HandleControlResult(policy.EntryServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionLogs,
		Role:      model.VPNRoleEntry,
		State:     model.VPNStateRunning,
		Logs:      []string{"entry log 1", "entry log 2"},
	}); err != nil {
		t.Fatalf("handle agent logs: %v", err)
	}

	logs := h.vpn.SessionLogs(session.SessionID)
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "agent report") ||
		!strings.Contains(joined, "entry log 1") ||
		!strings.Contains(joined, "entry log 2") {
		t.Fatalf("expected cached agent logs, got %#v", logs)
	}
}

func TestVPNRelayLifecycleEventsAreCachedAsSessionLogs(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)

	h.vpn.HandleRelayEvent(session.SessionID, "entry_connected", "")
	h.vpn.HandleRelayEvent(session.SessionID, "relay_started", "")
	h.vpn.HandleRelayEvent(session.SessionID, "relay_closed", "io: read/write on closed pipe")

	logs := strings.Join(h.vpn.SessionLogs(session.SessionID), "\n")
	if !strings.Contains(logs, "[dashboard] entry_connected") ||
		!strings.Contains(logs, "[dashboard] relay_started") ||
		!strings.Contains(logs, "[dashboard] relay_closed: io: read/write on closed pipe") {
		t.Fatalf("relay lifecycle events must be cached as session logs, got %q", logs)
	}
}

func TestVPNStartSessionRegistersRelayEndpointsAndStopClosesRelay(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)

	session := startAndRunTestVPNSession(t, h, actor, policy)

	if len(*h.relayCreates) != 1 {
		t.Fatalf("expected one relay registration, got %d", len(*h.relayCreates))
	}
	relay := (*h.relayCreates)[0]
	if relay.sessionID != session.SessionID {
		t.Fatalf("relay session mismatch: want %q got %q", session.SessionID, relay.sessionID)
	}
	if relay.entryStreamID != session.EntryStreamID || relay.entryServerID != policy.EntryServerID {
		t.Fatalf("relay entry mismatch: stream want %q got %q, server want %d got %d", session.EntryStreamID, relay.entryStreamID, policy.EntryServerID, relay.entryServerID)
	}
	if relay.exitStreamID != session.ExitStreamID || relay.exitServerID != policy.ExitServerID {
		t.Fatalf("relay exit mismatch: stream want %q got %q, server want %d got %d", session.ExitStreamID, relay.exitStreamID, policy.ExitServerID, relay.exitServerID)
	}

	if _, err := h.vpn.StopSession(actor, session.SessionID); err != nil {
		t.Fatalf("stop session: %v", err)
	}
	if len(*h.relayCloses) != 1 || (*h.relayCloses)[0] != session.SessionID {
		t.Fatalf("expected relay close for %q, got %#v", session.SessionID, *h.relayCloses)
	}
}

func TestVPNSessionActionsRejectForeignSessionWithSharedServers(t *testing.T) {
	cases := []struct {
		name string
		run  func(*VPNClass, VPNActor, string) (*model.AgentVPNSession, error)
	}{
		{
			name: "stop",
			run: func(vpn *VPNClass, actor VPNActor, sessionID string) (*model.AgentVPNSession, error) {
				return vpn.StopSession(actor, sessionID)
			},
		},
		{
			name: "restart",
			run: func(vpn *VPNClass, actor VPNActor, sessionID string) (*model.AgentVPNSession, error) {
				return vpn.RestartSession(actor, sessionID)
			},
		},
		{
			name: "status",
			run: func(vpn *VPNClass, actor VPNActor, sessionID string) (*model.AgentVPNSession, error) {
				return vpn.RefreshSessionStatus(actor, sessionID)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newVPNHarness(t)
			actor := VPNActor{UserID: 100, Role: model.RoleMember}
			policy := createTestVPNPolicy(t, h, actor)
			session := startAndRunTestVPNSession(t, h, actor, policy)
			if err := DB.Model(&model.AgentVPNPolicy{}).Where("id = ?", policy.ID).Update("user_id", uint64(200)).Error; err != nil {
				t.Fatal(err)
			}
			if err := DB.Model(&model.AgentVPNSession{}).Where("id = ?", session.ID).Update("user_id", uint64(200)).Error; err != nil {
				t.Fatal(err)
			}
			*h.relayCloses = nil

			_, err := tc.run(h.vpn, actor, session.SessionID)

			if err == nil {
				t.Fatalf("%s must reject a session owned by another user even when both servers are owned by the actor", tc.name)
			}
			if !strings.Contains(err.Error(), "permission denied") {
				t.Fatalf("error = %q, want permission denied", err.Error())
			}
			assertNoTask(t, h.entryStream)
			assertNoTask(t, h.exitStream)
			if len(*h.relayCloses) != 0 {
				t.Fatalf("%s must not close relay for a foreign session, got %#v", tc.name, *h.relayCloses)
			}
		})
	}
}

func TestVPNFailedControlResultClosesRelay(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	*h.notifications = nil

	failed, err := h.vpn.HandleControlResult(policy.EntryServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleEntry,
		State:     model.VPNStateFailed,
		LastError: "sidecar exited",
		Logs: []string{
			"[cleanup] tun_restore=failed: route restore failed",
			"[tun-health] request failed rollback=sidecar-stopped,relay-closed",
		},
	})
	if err != nil {
		t.Fatalf("handle entry failed: %v", err)
	}
	if failed.State != model.VPNStateFailed {
		t.Fatalf("expected failed session, got %q", failed.State)
	}
	if len(*h.relayCloses) != 1 || (*h.relayCloses)[0] != session.SessionID {
		t.Fatalf("expected relay close for failed session %q, got %#v", session.SessionID, *h.relayCloses)
	}
	if _, err := h.vpn.tokenForSession(failed); err == nil {
		t.Fatal("failed control result must delete the session token")
	}
	if len(*h.notifications) != 1 {
		t.Fatalf("expected one abnormal-stop notification, got %#v", *h.notifications)
	}
	notification := (*h.notifications)[0]
	if notification.groupID != policy.NotificationGroupID {
		t.Fatalf("failure notification group mismatch: want %d got %d", policy.NotificationGroupID, notification.groupID)
	}
	if !strings.Contains(notification.message, "[Agent VPN] 异常停止") ||
		!strings.Contains(notification.message, "入口节点: entry-cn") ||
		!strings.Contains(notification.message, "出口节点: exit-jp") {
		t.Fatalf("failure notification content is incomplete: %q", notification.message)
	}
	for _, want := range []string{
		"策略: GitHub Split",
		"状态: failed",
		"本地代理: SOCKS 127.0.0.1:1080",
		"上传/下载: 0 B / 0 B",
		"连接数: 0",
		"错误原因: sidecar exited",
		"时间:",
	} {
		if !strings.Contains(notification.message, want) {
			t.Fatalf("failure notification must include %q, got %q", want, notification.message)
		}
	}
	if !strings.Contains(notification.message, "tun_restore=failed: route restore failed") ||
		!strings.Contains(notification.message, "rollback=sidecar-stopped,relay-closed") {
		t.Fatalf("failure notification must include agent cleanup logs: %q", notification.message)
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionStatus, session.SessionID, false).Last(&audit).Error; err != nil {
		t.Fatalf("failed control result must write failure audit: %v", err)
	}
	if !strings.Contains(audit.Message, "sidecar exited") {
		t.Fatalf("failed control result audit must include error reason, got %q", audit.Message)
	}
	if audit.Detail["role"] != model.VPNRoleEntry || audit.Detail["result_action"] != model.VPNActionStart || audit.Detail["source"] != "agent_failed_result" {
		t.Fatalf("failed control result audit must include role and action, got detail=%#v", audit.Detail)
	}
	if !strings.Contains(audit.Detail["agent_cleanup_logs"], "tun_restore=failed: route restore failed") ||
		!strings.Contains(audit.Detail["agent_cleanup_logs"], "rollback=sidecar-stopped,relay-closed") {
		t.Fatalf("failed control result audit must include agent cleanup logs, detail=%#v", audit.Detail)
	}
	if audit.Detail["agent_cleanup_failed"] != "tun_restore" ||
		audit.Detail["agent_cleanup_state_kept"] != "false" {
		t.Fatalf("failed control result audit must include structured cleanup status, detail=%#v", audit.Detail)
	}
}

func TestVPNFailedControlResultReportsCleanupDispatchFailure(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	failingExit := newFailingTaskStream(errors.New("exit stream closed"))
	exit, ok := ServerShared.Get(policy.ExitServerID)
	if !ok {
		t.Fatal("exit server missing from harness")
	}
	exit.SetTaskStream(failingExit)
	*h.notifications = nil

	failed, err := h.vpn.HandleControlResult(policy.EntryServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleEntry,
		State:     model.VPNStateFailed,
		LastError: "sidecar exited",
	})
	if err != nil {
		t.Fatalf("handle entry failed: %v", err)
	}
	if failed.State != model.VPNStateFailed {
		t.Fatalf("expected failed session, got %q", failed.State)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "异常停止") {
		t.Fatalf("failed control result must notify despite cleanup dispatch failure, got %#v", *h.notifications)
	}
	if !strings.Contains((*h.notifications)[0].message, "清理下发失败") || !strings.Contains((*h.notifications)[0].message, "exit stream closed") {
		t.Fatalf("failed control result notification must include cleanup dispatch failure, got %#v", *h.notifications)
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionStatus, session.SessionID, false).Last(&audit).Error; err != nil {
		t.Fatalf("failed control result must write failure audit: %v", err)
	}
	if !strings.Contains(audit.Detail["cleanup_errors"], "exit stream closed") {
		t.Fatalf("failed control result audit must include cleanup dispatch failure, detail=%#v", audit.Detail)
	}
}

func TestVPNStartupFailedControlResultReportsCleanupDispatchFailure(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session, err := h.vpn.StartSession(actor, policy.ID)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	prepareAndDispatchExitStartForTest(t, h, session, policy)
	if _, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	}); err != nil {
		t.Fatalf("handle exit running: %v", err)
	}
	readVPNTask(t, h.entryStream)
	failingExit := newFailingTaskStream(errors.New("exit stream closed"))
	exit, ok := ServerShared.Get(policy.ExitServerID)
	if !ok {
		t.Fatal("exit server missing from harness")
	}
	exit.SetTaskStream(failingExit)
	*h.notifications = nil

	failed, err := h.vpn.HandleControlResult(policy.EntryServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleEntry,
		State:     model.VPNStateFailed,
		LastError: "entry sidecar failed",
		Logs: []string{
			"[cleanup] system_proxy_restore=failed: proxy restore failed",
			"[cleanup] state=kept-for-restore-retry path=/tmp/nezha-vpn/state.json",
		},
	})
	if err != nil {
		t.Fatalf("handle entry startup failed: %v", err)
	}
	if failed.State != model.VPNStateFailed {
		t.Fatalf("startup failed control result must fail session, got %q", failed.State)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "启动失败") {
		t.Fatalf("startup failed control result must send start failure notification, got %#v", *h.notifications)
	}
	startFailureNotification := (*h.notifications)[0].message
	for _, want := range []string{
		"策略: GitHub Split",
		"入口节点: entry-cn",
		"出口节点: exit-jp",
		"状态: failed",
		"本地代理: SOCKS 127.0.0.1:1080",
		"上传/下载: 0 B / 0 B",
		"连接数: 0",
		"错误原因: entry sidecar failed; cleanup dispatch failed: exit: exit stream closed",
		"时间:",
	} {
		if !strings.Contains(startFailureNotification, want) {
			t.Fatalf("startup failure notification must include %q, got %q", want, startFailureNotification)
		}
	}
	if !strings.Contains((*h.notifications)[0].message, "cleanup dispatch failed") ||
		!strings.Contains((*h.notifications)[0].message, "exit stream closed") {
		t.Fatalf("startup failure notification must include cleanup dispatch failure, got %#v", *h.notifications)
	}
	if !strings.Contains((*h.notifications)[0].message, "system_proxy_restore=failed: proxy restore failed") ||
		!strings.Contains((*h.notifications)[0].message, "state=kept-for-restore-retry") {
		t.Fatalf("startup failure notification must include agent cleanup logs, got %#v", *h.notifications)
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionStartSession, session.SessionID, false).Last(&audit).Error; err != nil {
		t.Fatalf("startup failed control result must write failure audit: %v", err)
	}
	if audit.Detail["cleanup_dispatched"] != "true" {
		t.Fatalf("startup failed control result audit must record cleanup dispatch, detail=%#v", audit.Detail)
	}
	if !strings.Contains(audit.Detail["cleanup_errors"], "exit stream closed") {
		t.Fatalf("startup failed control result audit must include cleanup dispatch failure, detail=%#v", audit.Detail)
	}
	if !strings.Contains(audit.Detail["agent_cleanup_logs"], "system_proxy_restore=failed: proxy restore failed") ||
		!strings.Contains(audit.Detail["agent_cleanup_logs"], "state=kept-for-restore-retry") {
		t.Fatalf("startup failed control result audit must include agent cleanup logs, detail=%#v", audit.Detail)
	}
	if audit.Detail["agent_cleanup_failed"] != "system_proxy_restore" ||
		audit.Detail["agent_cleanup_state_kept"] != "true" {
		t.Fatalf("startup failed control result audit must include structured cleanup status, detail=%#v", audit.Detail)
	}
}

func TestVPNStoppedControlResultFinalizesRuntimeAndAudits(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	*h.notifications = nil
	*h.relayCloses = nil

	stopped, err := h.vpn.HandleControlResult(policy.EntryServerID, model.VPNControlResult{
		SessionID:     session.SessionID,
		Action:        model.VPNActionStop,
		Role:          model.VPNRoleEntry,
		State:         model.VPNStateStopped,
		StoppedAtUnix: time.Now().Unix(),
		Logs: []string{
			"[cleanup] system_proxy_restore=ok",
			"[cleanup] tun_restore=ok",
		},
	})
	if err != nil {
		t.Fatalf("handle stopped control result: %v", err)
	}
	if stopped.State != model.VPNStateStopped || stopped.EntryState != model.VPNStateStopped || stopped.ExitState != model.VPNStateStopped {
		t.Fatalf("stopped control result must stop whole session, got state=%q entry=%q exit=%q", stopped.State, stopped.EntryState, stopped.ExitState)
	}
	if stopped.StoppedAt == nil {
		t.Fatal("stopped control result must persist stopped_at")
	}
	if len(*h.relayCloses) != 1 || (*h.relayCloses)[0] != session.SessionID {
		t.Fatalf("stopped control result must close relay for %q, got %#v", session.SessionID, *h.relayCloses)
	}
	if _, err := h.vpn.tokenForSession(stopped); err == nil {
		t.Fatal("stopped control result must delete the session token")
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "[Agent VPN] 已停止") {
		t.Fatalf("stopped control result must notify stop, got %#v", *h.notifications)
	}
	for _, want := range []string{
		"策略: GitHub Split",
		"状态: stopped",
		"本地代理: SOCKS 127.0.0.1:1080",
		"上传/下载: 0 B / 0 B",
		"时间:",
	} {
		if !strings.Contains((*h.notifications)[0].message, want) {
			t.Fatalf("stopped control result notification must include %q, got %q", want, (*h.notifications)[0].message)
		}
	}
	if !strings.Contains((*h.notifications)[0].message, "system_proxy_restore=ok") ||
		!strings.Contains((*h.notifications)[0].message, "tun_restore=ok") {
		t.Fatalf("stopped control result notification must include agent cleanup logs, got %#v", *h.notifications)
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ?", model.VPNAuditActionStopSession, session.SessionID).Last(&audit).Error; err != nil {
		t.Fatalf("stopped control result must write stop audit: %v", err)
	}
	if !audit.Success || audit.Message != "session stopped by agent" {
		t.Fatalf("stopped control result audit mismatch: success=%v message=%q", audit.Success, audit.Message)
	}
	if !strings.Contains(audit.Detail["agent_cleanup_logs"], "system_proxy_restore=ok") ||
		!strings.Contains(audit.Detail["agent_cleanup_logs"], "tun_restore=ok") {
		t.Fatalf("stopped control result audit must include agent cleanup logs, detail=%#v", audit.Detail)
	}
	if audit.Detail["agent_cleanup_ok"] != "system_proxy_restore,tun_restore" ||
		audit.Detail["agent_cleanup_failed"] != "" ||
		audit.Detail["agent_cleanup_state_kept"] != "false" {
		t.Fatalf("stopped control result audit must include structured cleanup status, detail=%#v", audit.Detail)
	}
}

func TestVPNStoppedSessionIgnoresLateControlResultButKeepsLogs(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	if _, err := h.vpn.StopSession(actor, session.SessionID); err != nil {
		t.Fatalf("stop session: %v", err)
	}
	relayCloses := len(*h.relayCloses)
	notifications := len(*h.notifications)

	got, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStatus,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
		Logs:      []string{"late exit status log"},
	})
	if err != nil {
		t.Fatalf("late stopped control result must be ignored without error: %v", err)
	}
	if got.State != model.VPNStateStopped || got.EntryState != model.VPNStateStopped || got.ExitState != model.VPNStateStopped {
		t.Fatalf("late result must not change stopped session, got state=%q entry=%q exit=%q", got.State, got.EntryState, got.ExitState)
	}
	if len(*h.relayCloses) != relayCloses {
		t.Fatalf("late stopped result must not close relay again, before=%d after=%d", relayCloses, len(*h.relayCloses))
	}
	if len(*h.notifications) != notifications {
		t.Fatalf("late stopped result must not notify again, before=%d after=%d", notifications, len(*h.notifications))
	}
	if logs := strings.Join(h.vpn.SessionLogs(session.SessionID), "\n"); !strings.Contains(logs, "late exit status log") {
		t.Fatalf("late stopped result logs must still be cached, got %q", logs)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateStopped || stored.EntryState != model.VPNStateStopped || stored.ExitState != model.VPNStateStopped {
		t.Fatalf("late result persisted terminal state change: state=%q entry=%q exit=%q", stored.State, stored.EntryState, stored.ExitState)
	}

	got, err = h.vpn.HandleControlResult(policy.EntryServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStop,
		Role:      model.VPNRoleEntry,
		State:     model.VPNStateStopped,
		Logs: []string{
			"[cleanup] system_proxy_restore=ok",
			"[cleanup] tun_restore=failed: route restore failed",
			"[cleanup] state=kept-for-restore-retry path=/tmp/nezha-vpn/state.json",
		},
	})
	if err != nil {
		t.Fatalf("late stopped cleanup result must be accepted: %v", err)
	}
	if got.State != model.VPNStateStopped || got.EntryState != model.VPNStateStopped || got.ExitState != model.VPNStateStopped {
		t.Fatalf("late cleanup result must not change stopped session, got state=%q entry=%q exit=%q", got.State, got.EntryState, got.ExitState)
	}
	if len(*h.relayCloses) != relayCloses {
		t.Fatalf("late cleanup result must not close relay again, before=%d after=%d", relayCloses, len(*h.relayCloses))
	}
	if len(*h.notifications) != notifications+1 {
		t.Fatalf("late cleanup result must send one cleanup notification, before=%d after=%d notifications=%#v", notifications, len(*h.notifications), *h.notifications)
	}
	cleanupNotification := (*h.notifications)[len(*h.notifications)-1].message
	if !strings.Contains(cleanupNotification, "[Agent VPN] 停止清理结果") ||
		!strings.Contains(cleanupNotification, "system_proxy_restore=ok") ||
		!strings.Contains(cleanupNotification, "tun_restore=failed: route restore failed") ||
		!strings.Contains(cleanupNotification, "state=kept-for-restore-retry") {
		t.Fatalf("late cleanup notification must include cleanup logs, got %q", cleanupNotification)
	}
	if logs := strings.Join(h.vpn.SessionLogs(session.SessionID), "\n"); !strings.Contains(logs, "tun_restore=failed: route restore failed") {
		t.Fatalf("late cleanup logs must still be cached, got %q", logs)
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND message = ?", model.VPNAuditActionStopSession, session.SessionID, "late agent cleanup result").Last(&audit).Error; err != nil {
		t.Fatalf("late cleanup result must write stop audit: %v", err)
	}
	if !audit.Success || audit.Detail["role"] != model.VPNRoleEntry {
		t.Fatalf("late cleanup audit mismatch: success=%v detail=%#v", audit.Success, audit.Detail)
	}
	if !strings.Contains(audit.Detail["agent_cleanup_logs"], "system_proxy_restore=ok") ||
		!strings.Contains(audit.Detail["agent_cleanup_logs"], "tun_restore=failed: route restore failed") ||
		!strings.Contains(audit.Detail["agent_cleanup_logs"], "state=kept-for-restore-retry") {
		t.Fatalf("late cleanup audit must include cleanup logs, detail=%#v", audit.Detail)
	}
	if audit.Detail["agent_cleanup_ok"] != "system_proxy_restore" ||
		audit.Detail["agent_cleanup_failed"] != "tun_restore" ||
		audit.Detail["agent_cleanup_state_kept"] != "true" {
		t.Fatalf("late cleanup audit must include structured cleanup status, detail=%#v", audit.Detail)
	}
}

func TestVPNStatusResultAfterDashboardRecoveryDoesNotRequireToken(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	h.vpn = NewVPNClass()
	VPNShared = h.vpn
	*h.notifications = nil

	if err := DB.Model(&model.AgentVPNSession{}).Where("id = ?", session.ID).Updates(map[string]any{
		"state":       model.VPNStateUnknown,
		"entry_state": model.VPNStateUnknown,
		"exit_state":  model.VPNStateRunning,
		"last_error":  "dashboard restarted; waiting for agent status",
	}).Error; err != nil {
		t.Fatalf("seed recovered session: %v", err)
	}

	got, err := h.vpn.HandleControlResult(policy.EntryServerID, model.VPNControlResult{
		SessionID:   session.SessionID,
		Action:      model.VPNActionStatus,
		Role:        model.VPNRoleEntry,
		State:       model.VPNStateRunning,
		UploadBytes: 128,
		Logs:        []string{"status after dashboard recovery"},
	})
	if err != nil {
		t.Fatalf("status result after dashboard recovery must not require in-memory token: %v", err)
	}
	if got.State != model.VPNStateRunning || got.EntryState != model.VPNStateRunning || got.ExitState != model.VPNStateRunning {
		t.Fatalf("status result must restore running state, got state=%q entry=%q exit=%q", got.State, got.EntryState, got.ExitState)
	}
	if got.UploadBytes != 128 {
		t.Fatalf("status result traffic not updated: upload=%d", got.UploadBytes)
	}
	if logs := strings.Join(h.vpn.SessionLogs(session.SessionID), "\n"); !strings.Contains(logs, "status after dashboard recovery") {
		t.Fatalf("status result logs must be cached, got %q", logs)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateRunning || stored.EntryState != model.VPNStateRunning || stored.ExitState != model.VPNStateRunning {
		t.Fatalf("status result persisted wrong state: state=%q entry=%q exit=%q", stored.State, stored.EntryState, stored.ExitState)
	}
	if len(*h.notifications) != 0 {
		t.Fatalf("status result after dashboard recovery must not send start notification again, got %#v", *h.notifications)
	}
	var startAuditCount int64
	if err := DB.Model(&model.AgentVPNAuditLog{}).
		Where("action = ? AND session_id = ? AND message = ?", model.VPNAuditActionStartSession, session.SessionID, "session started").
		Count(&startAuditCount).Error; err != nil {
		t.Fatal(err)
	}
	if startAuditCount != 1 {
		t.Fatalf("status result after dashboard recovery must not write another start success audit, got %d", startAuditCount)
	}
}

func TestVPNFailedResultAfterPolicyDeletionStillUpdatesSessionAndCachesLogs(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	if err := DB.Delete(&model.AgentVPNPolicy{}, policy.ID).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	delete(h.vpn.sessionPolicies, session.SessionID)
	h.vpn.mu.Unlock()

	got, err := h.vpn.HandleControlResult(policy.EntryServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStatus,
		Role:      model.VPNRoleEntry,
		State:     model.VPNStateFailed,
		LastError: "entry sidecar failed after policy deletion",
		Logs:      []string{"entry failed after policy deletion"},
	})
	if err != nil {
		t.Fatalf("failed result after policy deletion must still be handled: %v", err)
	}
	if got.State != model.VPNStateFailed || got.EntryState != model.VPNStateFailed {
		t.Fatalf("failed result after policy deletion must update session state, got state=%q entry=%q", got.State, got.EntryState)
	}
	if !strings.Contains(got.LastError, "entry sidecar failed after policy deletion") {
		t.Fatalf("failed result after policy deletion must persist last error, got %q", got.LastError)
	}
	if logs := strings.Join(h.vpn.SessionLogs(session.SessionID), "\n"); !strings.Contains(logs, "entry failed after policy deletion") {
		t.Fatalf("failed result after policy deletion must still cache logs, got %q", logs)
	}
}

func TestVPNStatusResultAfterPolicyDeletionStillUpdatesSessionAndCachesLogs(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	if err := DB.Delete(&model.AgentVPNPolicy{}, policy.ID).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	delete(h.vpn.sessionPolicies, session.SessionID)
	h.vpn.mu.Unlock()

	if _, err := h.vpn.RefreshSessionStatus(actor, session.SessionID); err != nil {
		t.Fatalf("status query with deleted policy must still dispatch before result handling: %v", err)
	}
	readVPNTask(t, h.entryStream)
	readVPNTask(t, h.exitStream)

	got, err := h.vpn.HandleControlResult(policy.EntryServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStatus,
		Role:      model.VPNRoleEntry,
		State:     model.VPNStateRunning,
		Logs:      []string{"status after policy deletion"},
	})
	if err != nil {
		t.Fatalf("status result after policy deletion must still be handled: %v", err)
	}
	if got.EntryState != model.VPNStateRunning {
		t.Fatalf("status result after policy deletion must update entry state, got %q", got.EntryState)
	}
	if logs := strings.Join(h.vpn.SessionLogs(session.SessionID), "\n"); !strings.Contains(logs, "status after policy deletion") {
		t.Fatalf("status result after policy deletion must still cache logs, got %q", logs)
	}
}

func TestVPNStartSessionDeletesTokenWhenExitStartDispatchFails(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	failingExit := newFailingTaskStream(errors.New("exit stream closed"))
	exit, ok := ServerShared.Get(policy.ExitServerID)
	if !ok {
		t.Fatal("exit server missing from harness")
	}

	session, err := h.vpn.StartSession(actor, policy.ID)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	readVPNTask(t, h.exitStream)
	readVPNTask(t, h.entryStream)
	if _, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionPrepare,
		Role:      model.VPNRoleExit,
		State:     model.VPNStatePrepared,
	}); err != nil {
		t.Fatalf("handle exit prepared: %v", err)
	}
	exit.SetTaskStream(failingExit)
	failed, err := h.vpn.HandleControlResult(policy.EntryServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionPrepare,
		Role:      model.VPNRoleEntry,
		State:     model.VPNStatePrepared,
	})
	if err == nil {
		t.Fatal("exit start dispatch failure must be returned")
	}
	if failed.State != model.VPNStateFailed || failed.ExitState != model.VPNStateFailed {
		t.Fatalf("failed exit dispatch must mark session failed, got state=%q exit=%q", failed.State, failed.ExitState)
	}
	_, exitReq := readVPNTask(t, &failingExit.capturedTaskStream)
	if exitReq.Action != model.VPNActionStart || exitReq.Role != model.VPNRoleExit {
		t.Fatalf("start should still attempt exit start dispatch, got %+v", exitReq)
	}
	if _, err := h.vpn.tokenForSession(failed); err == nil {
		t.Fatal("failed exit start dispatch must delete the session token")
	}
	if len(*h.relayCloses) != 1 || (*h.relayCloses)[0] != session.SessionID {
		t.Fatalf("failed exit start dispatch must close relay for %q, got %#v", session.SessionID, *h.relayCloses)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "启动失败") || !strings.Contains((*h.notifications)[0].message, "exit stream closed") {
		t.Fatalf("failed exit start dispatch must send failure notification, got %#v", *h.notifications)
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionStartSession, session.SessionID, false).Last(&audit).Error; err != nil {
		t.Fatalf("failed exit start dispatch must write failure audit: %v", err)
	}
	if audit.Detail["stage"] != "exit_start_dispatch" || audit.Detail["cleanup_dispatched"] != "true" {
		t.Fatalf("failed exit start dispatch audit detail mismatch: %#v", audit.Detail)
	}
}

func TestVPNEntryStartDispatchFailureCleansRuntimeAndStopsExit(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session, err := h.vpn.StartSession(actor, policy.ID)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	prepareAndDispatchExitStartForTest(t, h, session, policy)
	failingEntry := newFailingTaskStream(errors.New("entry stream closed"))
	entry, ok := ServerShared.Get(policy.EntryServerID)
	if !ok {
		t.Fatal("entry server missing from harness")
	}
	entry.SetTaskStream(failingEntry)
	*h.notifications = nil

	failed, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	})
	if err == nil {
		t.Fatal("entry start dispatch failure must be returned")
	}
	if failed.State != model.VPNStateFailed || failed.EntryState != model.VPNStateFailed {
		t.Fatalf("entry start dispatch failure must fail session, got state=%q entry=%q", failed.State, failed.EntryState)
	}
	_, entryReq := readVPNTask(t, &failingEntry.capturedTaskStream)
	if entryReq.Action != model.VPNActionStart || entryReq.Role != model.VPNRoleEntry {
		t.Fatalf("should still attempt entry start dispatch, got %+v", entryReq)
	}
	_, exitStopReq := readVPNTask(t, h.exitStream)
	if exitStopReq.Action != model.VPNActionStop || exitStopReq.Role != model.VPNRoleExit {
		t.Fatalf("entry start failure must stop already-running exit agent, got %+v", exitStopReq)
	}
	if _, err := h.vpn.tokenForSession(failed); err == nil {
		t.Fatal("entry start dispatch failure must delete the session token")
	}
	if len(*h.relayCloses) == 0 || (*h.relayCloses)[len(*h.relayCloses)-1] != session.SessionID {
		t.Fatalf("entry start dispatch failure must close relay for %q, got %#v", session.SessionID, *h.relayCloses)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "启动失败") {
		t.Fatalf("entry start dispatch failure must notify start failure, got %#v", *h.notifications)
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionStartSession, session.SessionID, false).Last(&audit).Error; err != nil {
		t.Fatalf("entry start dispatch failure must write failure audit: %v", err)
	}
	if !strings.Contains(audit.Message, "entry stream closed") {
		t.Fatalf("entry start dispatch failure audit must include reason, got %q", audit.Message)
	}
	if audit.Detail["stage"] != "entry_start_dispatch" || audit.Detail["cleanup_dispatched"] != "true" {
		t.Fatalf("entry start dispatch failure audit detail mismatch: %#v", audit.Detail)
	}
}

func TestVPNEntryStartDispatchFailureReportsCleanupDispatchFailure(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session, err := h.vpn.StartSession(actor, policy.ID)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	prepareAndDispatchExitStartForTest(t, h, session, policy)
	failingEntry := newFailingTaskStream(errors.New("entry stream closed"))
	entry, ok := ServerShared.Get(policy.EntryServerID)
	if !ok {
		t.Fatal("entry server missing from harness")
	}
	entry.SetTaskStream(failingEntry)
	failingExit := newFailingTaskStream(errors.New("exit cleanup stream closed"))
	exit, ok := ServerShared.Get(policy.ExitServerID)
	if !ok {
		t.Fatal("exit server missing from harness")
	}
	exit.SetTaskStream(failingExit)
	*h.notifications = nil

	failed, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	})
	if err == nil {
		t.Fatal("entry start dispatch failure must be returned")
	}
	if failed.State != model.VPNStateFailed || failed.EntryState != model.VPNStateFailed {
		t.Fatalf("entry start dispatch failure must fail session, got state=%q entry=%q", failed.State, failed.EntryState)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "启动失败") {
		t.Fatalf("entry start dispatch failure must notify start failure, got %#v", *h.notifications)
	}
	if !strings.Contains((*h.notifications)[0].message, "cleanup dispatch failed") ||
		!strings.Contains((*h.notifications)[0].message, "exit cleanup stream closed") {
		t.Fatalf("entry start dispatch failure notification must include cleanup dispatch failure, got %#v", *h.notifications)
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionStartSession, session.SessionID, false).Last(&audit).Error; err != nil {
		t.Fatalf("entry start dispatch failure must write failure audit: %v", err)
	}
	if audit.Detail["stage"] != "entry_start_dispatch" || audit.Detail["cleanup_dispatched"] != "true" {
		t.Fatalf("entry start dispatch failure audit detail mismatch: %#v", audit.Detail)
	}
	if !strings.Contains(audit.Detail["cleanup_errors"], "exit cleanup stream closed") {
		t.Fatalf("entry start dispatch failure audit must include cleanup dispatch failure, detail=%#v", audit.Detail)
	}
}

func TestVPNExitRunningStillDispatchesEntryStartWhenPolicyDeleted(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session, err := h.vpn.StartSession(actor, policy.ID)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	prepareAndDispatchExitStartForTest(t, h, session, policy)
	if err := DB.Delete(&model.AgentVPNPolicy{}, policy.ID).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	delete(h.vpn.sessionPolicies, session.SessionID)
	h.vpn.mu.Unlock()

	got, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	})
	if err != nil {
		t.Fatalf("exit running after policy deletion must still dispatch entry start: %v", err)
	}
	if got.ExitState != model.VPNStateRunning || got.EntryState != model.VPNStateStarting {
		t.Fatalf("exit running after policy deletion must keep lifecycle moving, got entry=%q exit=%q", got.EntryState, got.ExitState)
	}
	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.Action != model.VPNActionStart || entryReq.Role != model.VPNRoleEntry {
		t.Fatalf("exit running after policy deletion must still dispatch entry start, got %+v", entryReq)
	}
}

func TestVPNEntryRunningStillCompletesSessionWhenPolicyDeleted(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session, err := h.vpn.StartSession(actor, policy.ID)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	prepareAndDispatchExitStartForTest(t, h, session, policy)
	got, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	})
	if err != nil {
		t.Fatalf("handle exit running: %v", err)
	}
	if got.EntryState != model.VPNStateStarting {
		t.Fatalf("entry must be starting after exit running, got %q", got.EntryState)
	}
	readVPNTask(t, h.entryStream)
	if err := DB.Delete(&model.AgentVPNPolicy{}, policy.ID).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	delete(h.vpn.sessionPolicies, session.SessionID)
	h.vpn.mu.Unlock()
	*h.notifications = nil

	got, err = h.vpn.HandleControlResult(policy.EntryServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleEntry,
		State:     model.VPNStateRunning,
	})
	if err != nil {
		t.Fatalf("entry running after policy deletion must still complete session: %v", err)
	}
	if got.State != model.VPNStateRunning || got.EntryState != model.VPNStateRunning || got.ExitState != model.VPNStateRunning {
		t.Fatalf("entry running after policy deletion must complete session, got state=%q entry=%q exit=%q", got.State, got.EntryState, got.ExitState)
	}
}

func TestVPNExitRunningThenEntryOfflineReportsCleanupDispatchFailure(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session, err := h.vpn.StartSession(actor, policy.ID)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	prepareAndDispatchExitStartForTest(t, h, session, policy)
	h.mustServer(policy.EntryServerID).SetTaskStream(nil)
	failingExit := newFailingTaskStream(errors.New("exit cleanup stream closed"))
	exit, ok := ServerShared.Get(policy.ExitServerID)
	if !ok {
		t.Fatal("exit server missing from harness")
	}
	exit.SetTaskStream(failingExit)
	*h.notifications = nil

	failed, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	})
	if err == nil {
		t.Fatal("entry offline after exit running must be returned")
	}
	if failed.State != model.VPNStateFailed || failed.EntryState != model.VPNStateFailed {
		t.Fatalf("entry offline after exit running must fail session, got state=%q entry=%q", failed.State, failed.EntryState)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "启动失败") {
		t.Fatalf("entry offline after exit running must send start failure notification, got %#v", *h.notifications)
	}
	if !strings.Contains((*h.notifications)[0].message, "cleanup dispatch failed") ||
		!strings.Contains((*h.notifications)[0].message, "exit cleanup stream closed") {
		t.Fatalf("entry offline notification must include cleanup dispatch failure, got %#v", *h.notifications)
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionStartSession, session.SessionID, false).Last(&audit).Error; err != nil {
		t.Fatalf("entry offline after exit running must write failure audit: %v", err)
	}
	if audit.Detail["stage"] != "entry_offline_after_exit_running" || audit.Detail["cleanup_dispatched"] != "true" {
		t.Fatalf("entry offline audit detail mismatch: %#v", audit.Detail)
	}
	if !strings.Contains(audit.Detail["cleanup_errors"], "exit cleanup stream closed") {
		t.Fatalf("entry offline audit must include cleanup dispatch failure, detail=%#v", audit.Detail)
	}
}

func TestVPNExitRunningThenMissingTokenReportsCleanupDispatchFailure(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session, err := h.vpn.StartSession(actor, policy.ID)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	prepareAndDispatchExitStartForTest(t, h, session, policy)
	h.vpn.mu.Lock()
	delete(h.vpn.sessionTokens, session.SessionID)
	h.vpn.mu.Unlock()
	failingExit := newFailingTaskStream(errors.New("exit cleanup stream closed"))
	exit, ok := ServerShared.Get(policy.ExitServerID)
	if !ok {
		t.Fatal("exit server missing from harness")
	}
	exit.SetTaskStream(failingExit)
	*h.notifications = nil

	failed, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	})
	if err == nil {
		t.Fatal("missing token after exit running must be returned")
	}
	if failed.State != model.VPNStateFailed || failed.EntryState != model.VPNStateFailed {
		t.Fatalf("missing token after exit running must fail session, got state=%q entry=%q", failed.State, failed.EntryState)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "启动失败") {
		t.Fatalf("missing token after exit running must send start failure notification, got %#v", *h.notifications)
	}
	if !strings.Contains((*h.notifications)[0].message, "session token is no longer available") ||
		!strings.Contains((*h.notifications)[0].message, "cleanup dispatch failed") ||
		!strings.Contains((*h.notifications)[0].message, "exit cleanup stream closed") {
		t.Fatalf("missing token notification must include token and cleanup dispatch failure, got %#v", *h.notifications)
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionStartSession, session.SessionID, false).Last(&audit).Error; err != nil {
		t.Fatalf("missing token after exit running must write failure audit: %v", err)
	}
	if audit.Detail["stage"] != "entry_token_missing_after_exit_running" || audit.Detail["cleanup_dispatched"] != "true" {
		t.Fatalf("missing token audit detail mismatch: %#v", audit.Detail)
	}
	if !strings.Contains(audit.Detail["cleanup_errors"], "exit cleanup stream closed") {
		t.Fatalf("missing token audit must include cleanup dispatch failure, detail=%#v", audit.Detail)
	}
}

func TestVPNRelayTrafficUpdatesSessionCounters(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)

	shouldClose, reason := h.vpn.HandleRelayTraffic(session.SessionID, 123, 45, 0)
	if shouldClose {
		t.Fatalf("traffic below limits must not close relay: %s", reason)
	}
	h.vpn.FlushRelayTraffic(session.SessionID)

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.UploadBytes != 123 || stored.DownloadBytes != 45 {
		t.Fatalf("relay traffic must be persisted, got upload=%d download=%d", stored.UploadBytes, stored.DownloadBytes)
	}
	if stored.State != model.VPNStateRunning {
		t.Fatalf("traffic update must not change running state, got %q", stored.State)
	}
}

func TestVPNRelayActiveConnectionsUpdatesSessionCounter(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)

	shouldClose, reason := h.vpn.HandleRelayTraffic(session.SessionID, 123, 45, 2)
	if shouldClose {
		t.Fatalf("traffic below limits must not close relay: %s", reason)
	}
	h.vpn.FlushRelayTraffic(session.SessionID)

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.UploadBytes != 123 || stored.DownloadBytes != 45 || stored.ActiveConnections != 2 {
		t.Fatalf("relay counters must be persisted, got upload=%d download=%d active=%d", stored.UploadBytes, stored.DownloadBytes, stored.ActiveConnections)
	}

	shouldClose, reason = h.vpn.HandleRelayTraffic(session.SessionID, 123, 45, 0)
	if shouldClose {
		t.Fatalf("connection close below limits must not close relay: %s", reason)
	}
	h.vpn.FlushRelayTraffic(session.SessionID)
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.ActiveConnections != 0 {
		t.Fatalf("relay connection close must persist zero active connections, got %d", stored.ActiveConnections)
	}
}

func TestVPNRelayActiveConnectionsPersistImmediatelyDespiteTrafficThrottle(t *testing.T) {
	h := newVPNHarness(t)
	h.vpn.relayTrafficFlushInterval = time.Hour
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)

	shouldClose, reason := h.vpn.HandleRelayTraffic(session.SessionID, 17, 0, 1)
	if shouldClose {
		t.Fatalf("connection counter update must not close relay: %s", reason)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.ActiveConnections != 1 {
		t.Fatalf("active connection changes must persist immediately, got %d", stored.ActiveConnections)
	}
	if stored.UploadBytes != 17 || stored.DownloadBytes != 0 {
		t.Fatalf("immediate active connection flush must persist current traffic too, got upload=%d download=%d", stored.UploadBytes, stored.DownloadBytes)
	}
}

func TestVPNRelayTrafficBelowLimitIsThrottledBeforePersisting(t *testing.T) {
	h := newVPNHarness(t)
	h.vpn.relayTrafficFlushInterval = time.Hour
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)

	shouldClose, reason := h.vpn.HandleRelayTraffic(session.SessionID, 123, 45, 0)
	if shouldClose {
		t.Fatalf("traffic below limits must not close relay: %s", reason)
	}
	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.UploadBytes != 0 || stored.DownloadBytes != 0 {
		t.Fatalf("traffic below limits should be throttled before DB persistence, got upload=%d download=%d", stored.UploadBytes, stored.DownloadBytes)
	}

	h.vpn.FlushRelayTraffic(session.SessionID)
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.UploadBytes != 123 || stored.DownloadBytes != 45 {
		t.Fatalf("manual relay traffic flush must persist latest counters, got upload=%d download=%d", stored.UploadBytes, stored.DownloadBytes)
	}
}

func TestVPNRelayTrafficLimitStopsSessionAndNotifies(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "limited vpn",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		MaxUploadBytes:      10,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("save limited policy: %v", err)
	}
	session := startAndRunTestVPNSession(t, h, actor, policy)
	*h.notifications = nil

	shouldClose, reason := h.vpn.HandleRelayTraffic(session.SessionID, 11, 0, 0)
	if !shouldClose {
		t.Fatal("upload above policy limit must close relay")
	}
	if !strings.Contains(reason, "upload traffic limit exceeded") {
		t.Fatalf("limit close reason is incomplete: %q", reason)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateStopped || stored.EntryState != model.VPNStateStopped || stored.ExitState != model.VPNStateStopped {
		t.Fatalf("traffic limit must stop the session, got state=%q entry=%q exit=%q", stored.State, stored.EntryState, stored.ExitState)
	}
	if stored.StoppedAt == nil {
		t.Fatal("traffic limit stop must persist stopped_at")
	}
	if stored.UploadBytes != 11 || stored.DownloadBytes != 0 {
		t.Fatalf("traffic limit must persist final counters, got upload=%d download=%d", stored.UploadBytes, stored.DownloadBytes)
	}
	if !strings.Contains(stored.LastError, "upload traffic limit exceeded") {
		t.Fatalf("traffic limit must persist last_error, got %q", stored.LastError)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "已因流量超限停止") {
		t.Fatalf("traffic limit must send stop notification, got %#v", *h.notifications)
	}
	trafficNotification := (*h.notifications)[0].message
	for _, want := range []string{
		"策略: limited vpn",
		"入口节点: entry-cn",
		"出口节点: exit-jp",
		"状态: stopped",
		"本地代理: SOCKS 127.0.0.1:1080",
		"上传/下载: 11 B / 0 B",
		"连接数: 0",
		"错误原因: upload traffic limit exceeded: 11 > 10",
		"限制: 上传 10 B",
		"实际: 上传 11 B / 下载 0 B",
		"时间:",
	} {
		if !strings.Contains(trafficNotification, want) {
			t.Fatalf("traffic limit notification must include %q, got %q", want, trafficNotification)
		}
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ?", model.VPNAuditActionStopSession, session.SessionID).Last(&audit).Error; err != nil {
		t.Fatalf("traffic limit must write stop audit: %v", err)
	}
	if !audit.Success || !strings.Contains(audit.Message, "traffic limit") {
		t.Fatalf("traffic limit audit mismatch: success=%v message=%q", audit.Success, audit.Message)
	}
	if audit.Detail["reason"] != reason || audit.Detail["upload_bytes"] != "11" || audit.Detail["download_bytes"] != "0" {
		t.Fatalf("traffic limit audit detail mismatch: %#v", audit.Detail)
	}
}

func TestVPNRelayTrafficLimitStillStopsSessionWhenPolicyDeleted(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "limited vpn deleted policy",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		MaxUploadBytes:      10,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("save limited policy: %v", err)
	}
	session := startAndRunTestVPNSession(t, h, actor, policy)
	if err := DB.Delete(&model.AgentVPNPolicy{}, policy.ID).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	delete(h.vpn.sessionPolicies, session.SessionID)
	h.vpn.mu.Unlock()
	*h.notifications = nil

	shouldClose, reason := h.vpn.HandleRelayTraffic(session.SessionID, 11, 0, 0)
	if !shouldClose {
		t.Fatal("traffic limit must still close relay after policy deletion")
	}
	if !strings.Contains(reason, "upload traffic limit exceeded") {
		t.Fatalf("limit close reason is incomplete: %q", reason)
	}
	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateStopped {
		t.Fatalf("traffic limit after policy deletion must still stop session, got %q", stored.State)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "已因流量超限停止") {
		t.Fatalf("traffic limit after policy deletion must still notify, got %#v", *h.notifications)
	}
}

func TestVPNRelayConnectionLimitStillStopsSessionWhenPolicyDeleted(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "connection limited deleted policy",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		MaxConnections:      1,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("save connection limited policy: %v", err)
	}
	session := startAndRunTestVPNSession(t, h, actor, policy)
	if err := DB.Delete(&model.AgentVPNPolicy{}, policy.ID).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	delete(h.vpn.sessionPolicies, session.SessionID)
	h.vpn.mu.Unlock()
	*h.notifications = nil

	shouldClose, reason := h.vpn.HandleRelayTraffic(session.SessionID, 0, 0, 2)
	if !shouldClose {
		t.Fatal("connection limit must still close relay after policy deletion")
	}
	if !strings.Contains(reason, "connection limit exceeded") {
		t.Fatalf("limit close reason is incomplete: %q", reason)
	}
	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateStopped {
		t.Fatalf("connection limit after policy deletion must still stop session, got %q", stored.State)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "已因连接数超限停止") {
		t.Fatalf("connection limit after policy deletion must still notify, got %#v", *h.notifications)
	}
}

func TestVPNRelayConnectionLimitStopsSessionAndNotifies(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "connection limited vpn",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		MaxConnections:      1,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("save connection limited policy: %v", err)
	}
	session := startAndRunTestVPNSession(t, h, actor, policy)
	*h.notifications = nil

	shouldClose, reason := h.vpn.HandleRelayTraffic(session.SessionID, 0, 0, 2)
	if !shouldClose {
		t.Fatal("active connections above policy limit must close relay")
	}
	if !strings.Contains(reason, "connection limit exceeded") {
		t.Fatalf("limit close reason is incomplete: %q", reason)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateStopped || stored.EntryState != model.VPNStateStopped || stored.ExitState != model.VPNStateStopped {
		t.Fatalf("connection limit must stop the session, got state=%q entry=%q exit=%q", stored.State, stored.EntryState, stored.ExitState)
	}
	if stored.ActiveConnections != 2 {
		t.Fatalf("connection limit must persist final active connection count, got %d", stored.ActiveConnections)
	}
	if !strings.Contains(stored.LastError, "connection limit exceeded") {
		t.Fatalf("connection limit must persist last_error, got %q", stored.LastError)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "已因连接数超限停止") {
		t.Fatalf("connection limit must send stop notification, got %#v", *h.notifications)
	}
	connectionNotification := (*h.notifications)[0].message
	for _, want := range []string{
		"策略: connection limited vpn",
		"入口节点: entry-cn",
		"出口节点: exit-jp",
		"状态: stopped",
		"本地代理: SOCKS 127.0.0.1:1080",
		"上传/下载: 0 B / 0 B",
		"连接数: 2",
		"错误原因: connection limit exceeded: 2 > 1",
		"限制: 连接数 1",
		"实际: 连接数 2",
		"时间:",
	} {
		if !strings.Contains(connectionNotification, want) {
			t.Fatalf("connection limit notification must include %q, got %q", want, connectionNotification)
		}
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ?", model.VPNAuditActionStopSession, session.SessionID).Last(&audit).Error; err != nil {
		t.Fatalf("connection limit must write stop audit: %v", err)
	}
	if audit.Detail["reason"] != reason || audit.Detail["active_connections"] != "2" || audit.Detail["max_connections"] != "1" {
		t.Fatalf("connection limit audit detail mismatch: %#v", audit.Detail)
	}
}

func TestVPNRelayTrafficLimitDispatchesStopToBothAgentsForCleanup(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "limited vpn cleanup",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		MaxUploadBytes:      10,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("save limited policy: %v", err)
	}
	session := startAndRunTestVPNSession(t, h, actor, policy)

	shouldClose, reason := h.vpn.HandleRelayTraffic(session.SessionID, 11, 0, 0)
	if !shouldClose {
		t.Fatalf("upload above policy limit must close relay: %s", reason)
	}
	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.Action != model.VPNActionStop || entryReq.Role != model.VPNRoleEntry {
		t.Fatalf("traffic limit must dispatch entry cleanup stop, got action=%q role=%q", entryReq.Action, entryReq.Role)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.Action != model.VPNActionStop || exitReq.Role != model.VPNRoleExit {
		t.Fatalf("traffic limit must dispatch exit cleanup stop, got action=%q role=%q", exitReq.Action, exitReq.Role)
	}
}

func TestVPNRelayTrafficLimitReportsCleanupDispatchFailure(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "limited vpn cleanup failure",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		MaxUploadBytes:      10,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("save limited policy: %v", err)
	}
	session := startAndRunTestVPNSession(t, h, actor, policy)
	failingEntry := newFailingTaskStream(errors.New("entry stream closed"))
	entry, ok := ServerShared.Get(policy.EntryServerID)
	if !ok {
		t.Fatal("entry server missing from harness")
	}
	entry.SetTaskStream(failingEntry)
	*h.notifications = nil

	shouldClose, reason := h.vpn.HandleRelayTraffic(session.SessionID, 11, 0, 0)
	if !shouldClose {
		t.Fatalf("upload above policy limit must close relay: %s", reason)
	}

	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "已因流量超限停止") {
		t.Fatalf("traffic limit must notify despite cleanup dispatch failure, got %#v", *h.notifications)
	}
	if !strings.Contains((*h.notifications)[0].message, "清理下发失败") || !strings.Contains((*h.notifications)[0].message, "entry stream closed") {
		t.Fatalf("traffic limit notification must include cleanup dispatch failure, got %#v", *h.notifications)
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ?", model.VPNAuditActionStopSession, session.SessionID).Last(&audit).Error; err != nil {
		t.Fatalf("traffic limit must write stop audit: %v", err)
	}
	if !strings.Contains(audit.Detail["cleanup_errors"], "entry stream closed") {
		t.Fatalf("traffic limit audit must include cleanup dispatch failure, detail=%#v", audit.Detail)
	}
}

func TestVPNRelayTrafficLimitDeletesTokenAndClosesRelay(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "limited vpn finalizer",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		MaxUploadBytes:      10,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("save limited policy: %v", err)
	}
	session := startAndRunTestVPNSession(t, h, actor, policy)

	shouldClose, reason := h.vpn.HandleRelayTraffic(session.SessionID, 11, 0, 0)
	if !shouldClose {
		t.Fatalf("upload above policy limit must close relay: %s", reason)
	}
	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := h.vpn.tokenForSession(&stored); err == nil {
		t.Fatal("traffic-limit stop must delete the session token")
	}
	if len(*h.relayCloses) == 0 || (*h.relayCloses)[len(*h.relayCloses)-1] != session.SessionID {
		t.Fatalf("traffic-limit stop must close relay, got %#v", *h.relayCloses)
	}
}

func TestVPNRelayClosedMarksRunningSessionFailed(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	*h.notifications = nil

	h.vpn.HandleRelayClosed(session.SessionID, 55, 66, errors.New("relay disconnected"))

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateFailed {
		t.Fatalf("relay disconnect must fail running session, got %q", stored.State)
	}
	if stored.UploadBytes != 55 || stored.DownloadBytes != 66 {
		t.Fatalf("relay disconnect must persist final counters, got upload=%d download=%d", stored.UploadBytes, stored.DownloadBytes)
	}
	if !strings.Contains(stored.LastError, "relay disconnected") {
		t.Fatalf("relay disconnect must persist error reason, got %q", stored.LastError)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "异常停止") {
		t.Fatalf("relay disconnect must send abnormal-stop notification, got %#v", *h.notifications)
	}
	notification := (*h.notifications)[0].message
	for _, want := range []string{
		"策略: GitHub Split",
		"入口节点: entry-cn",
		"出口节点: exit-jp",
		"状态: failed",
		"本地代理: SOCKS 127.0.0.1:1080",
		"上传/下载: 55 B / 66 B",
		"连接数: 0",
		"错误原因: relay disconnected",
		"时间:",
	} {
		if !strings.Contains(notification, want) {
			t.Fatalf("relay disconnect notification must include %q, got %q", want, notification)
		}
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionStatus, session.SessionID, false).Last(&audit).Error; err != nil {
		t.Fatalf("relay disconnect must write failure audit: %v", err)
	}
	if !strings.Contains(audit.Message, "relay disconnected") {
		t.Fatalf("relay disconnect audit must include reason, got %q", audit.Message)
	}
	if audit.Detail["source"] != "relay_closed" || audit.Detail["upload_bytes"] != "55" || audit.Detail["download_bytes"] != "66" {
		t.Fatalf("relay disconnect audit detail mismatch: %#v", audit.Detail)
	}
}

func TestVPNRelayClosedDispatchesStopToBothAgentsForCleanup(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)

	h.vpn.HandleRelayClosed(session.SessionID, 55, 66, errors.New("relay disconnected"))

	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.Action != model.VPNActionStop || entryReq.Role != model.VPNRoleEntry {
		t.Fatalf("relay disconnect must dispatch entry cleanup stop, got action=%q role=%q", entryReq.Action, entryReq.Role)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.Action != model.VPNActionStop || exitReq.Role != model.VPNRoleExit {
		t.Fatalf("relay disconnect must dispatch exit cleanup stop, got action=%q role=%q", exitReq.Action, exitReq.Role)
	}
}

func TestVPNRelayClosedReportsCleanupDispatchFailure(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	failingEntry := newFailingTaskStream(errors.New("entry stream closed"))
	entry, ok := ServerShared.Get(policy.EntryServerID)
	if !ok {
		t.Fatal("entry server missing from harness")
	}
	entry.SetTaskStream(failingEntry)
	*h.notifications = nil

	h.vpn.HandleRelayClosed(session.SessionID, 55, 66, errors.New("relay disconnected"))

	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "异常停止") {
		t.Fatalf("relay disconnect must notify despite cleanup dispatch failure, got %#v", *h.notifications)
	}
	if !strings.Contains((*h.notifications)[0].message, "清理下发失败") || !strings.Contains((*h.notifications)[0].message, "entry stream closed") {
		t.Fatalf("relay disconnect notification must include cleanup dispatch failure, got %#v", *h.notifications)
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionStatus, session.SessionID, false).Last(&audit).Error; err != nil {
		t.Fatalf("relay disconnect must write failure audit: %v", err)
	}
	if !strings.Contains(audit.Detail["cleanup_errors"], "entry stream closed") {
		t.Fatalf("relay disconnect audit must include cleanup dispatch failure, detail=%#v", audit.Detail)
	}
}

func TestVPNRelayClosedDeletesTokenAndClosesRelay(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)

	h.vpn.HandleRelayClosed(session.SessionID, 55, 66, errors.New("relay disconnected"))

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateFailed {
		t.Fatalf("relay disconnect must fail running session, got %q", stored.State)
	}
	if _, err := h.vpn.tokenForSession(&stored); err == nil {
		t.Fatal("relay disconnect must delete the session token")
	}
	if len(*h.relayCloses) == 0 || (*h.relayCloses)[len(*h.relayCloses)-1] != session.SessionID {
		t.Fatalf("relay disconnect must close relay, got %#v", *h.relayCloses)
	}
}

func TestVPNRelayClosedStillFailsSessionWhenPolicyDeleted(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	if err := DB.Delete(&model.AgentVPNPolicy{}, policy.ID).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	delete(h.vpn.sessionPolicies, session.SessionID)
	h.vpn.mu.Unlock()
	*h.notifications = nil

	h.vpn.HandleRelayClosed(session.SessionID, 55, 66, errors.New("relay disconnected after policy deletion"))

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateFailed {
		t.Fatalf("relay disconnect after policy deletion must still fail running session, got %q", stored.State)
	}
	if !strings.Contains(stored.LastError, "relay disconnected after policy deletion") {
		t.Fatalf("relay disconnect after policy deletion must persist reason, got %q", stored.LastError)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "异常停止") {
		t.Fatalf("relay disconnect after policy deletion must still notify abnormal stop, got %#v", *h.notifications)
	}
	if (*h.notifications)[0].groupID != policy.NotificationGroupID {
		t.Fatalf("relay disconnect after policy deletion notification group = %d, want %d", (*h.notifications)[0].groupID, policy.NotificationGroupID)
	}
	for _, want := range []string{
		"策略: GitHub Split",
		"模式: system_proxy",
		"本地代理: SOCKS 127.0.0.1:1080",
	} {
		if !strings.Contains((*h.notifications)[0].message, want) {
			t.Fatalf("relay disconnect after policy deletion notification must include %q, got %q", want, (*h.notifications)[0].message)
		}
	}
}

func TestVPNRelayClosedKeepsTunNameWhenPolicyDeleted(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "tun deleted policy",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeTunSplit,
		RuleMode:            model.VPNRuleModeGlobal,
		TunName:             "corp-tun0",
		DNSServer:           "https://1.1.1.1/dns-query",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("save tun policy: %v", err)
	}
	session := startAndRunTestVPNSession(t, h, actor, policy)
	if err := DB.Delete(&model.AgentVPNPolicy{}, policy.ID).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	delete(h.vpn.sessionPolicies, session.SessionID)
	h.vpn.mu.Unlock()
	*h.notifications = nil

	h.vpn.HandleRelayClosed(session.SessionID, 1, 2, errors.New("relay disconnected after tun policy deletion"))

	if len(*h.notifications) != 1 {
		t.Fatalf("relay disconnect after tun policy deletion must send one notification, got %#v", *h.notifications)
	}
	if !strings.Contains((*h.notifications)[0].message, "本地代理: TUN corp-tun0") {
		t.Fatalf("relay disconnect after tun policy deletion must keep original tun name, got %q", (*h.notifications)[0].message)
	}
}

func TestVPNFallbackPolicyRestoresTunDNSAndProbeFieldsFromAudit(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                    "tun metadata policy",
		EntryServerID:           1,
		ExitServerID:            2,
		Mode:                    model.VPNModeTunSplit,
		RuleMode:                model.VPNRuleModeGlobal,
		Domains:                 []string{"github.com", "api.github.com"},
		CIDRs:                   []string{"198.51.100.0/24"},
		DirectCIDRs:             []string{"203.0.113.0/24"},
		ListenHTTP:              "127.0.0.1:8088",
		ListenSOCKS:             "127.0.0.1:1080",
		TunName:                 "corp-tun1",
		DNSServer:               "https://dns.example/dns-query",
		ExpiresSeconds:          3600,
		MaxUploadBytes:          1024,
		MaxDownloadBytes:        2048,
		MaxConnections:          32,
		IdleTimeoutSeconds:      60,
		NotificationGroupID:     9,
		AutoRestart:             true,
		SetSystemProxy:          true,
		TunHealthURL:            "https://health.example/generate_204",
		TunHealthTimeoutSeconds: 12,
		EgressProbeURL:          "https://ifconfig.example/ip",
		CoreVersion:             "1.12.0",
		CoreDownloadURL:         "https://download.example.com/sing-box",
		CoreSHA256:              "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("save tun metadata policy: %v", err)
	}
	session := startAndRunTestVPNSession(t, h, actor, policy)
	if err := DB.Delete(&model.AgentVPNPolicy{}, policy.ID).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	delete(h.vpn.sessionPolicies, session.SessionID)
	h.vpn.mu.Unlock()

	fallback := h.vpn.fallbackVPNPolicyForLostSession(session)
	if fallback == nil {
		t.Fatal("fallback policy must still be reconstructed")
	}
	if fallback.TunName != "corp-tun1" {
		t.Fatalf("fallback tun name = %q, want corp-tun1", fallback.TunName)
	}
	if fallback.ListenHTTP != "127.0.0.1:8088" || fallback.ListenSOCKS != "127.0.0.1:1080" {
		t.Fatalf("fallback listens mismatch: http=%q socks=%q", fallback.ListenHTTP, fallback.ListenSOCKS)
	}
	if fallback.DNSServer != "https://dns.example/dns-query" {
		t.Fatalf("fallback dns server = %q, want https://dns.example/dns-query", fallback.DNSServer)
	}
	if fallback.TunHealthURL != "https://health.example/generate_204" {
		t.Fatalf("fallback tun health url = %q, want https://health.example/generate_204", fallback.TunHealthURL)
	}
	if fallback.TunHealthTimeoutSeconds != 12 {
		t.Fatalf("fallback tun health timeout = %d, want 12", fallback.TunHealthTimeoutSeconds)
	}
	if len(fallback.Domains) != 2 || fallback.Domains[0] != "github.com" || fallback.Domains[1] != "api.github.com" {
		t.Fatalf("fallback domains = %#v, want github.com/api.github.com", fallback.Domains)
	}
	if len(fallback.CIDRs) != 1 || fallback.CIDRs[0] != "198.51.100.0/24" {
		t.Fatalf("fallback cidrs = %#v, want 198.51.100.0/24", fallback.CIDRs)
	}
	if len(fallback.DirectCIDRs) != 1 || fallback.DirectCIDRs[0] != "203.0.113.0/24" {
		t.Fatalf("fallback direct cidrs = %#v, want 203.0.113.0/24", fallback.DirectCIDRs)
	}
	if fallback.ExpiresSeconds != 3600 {
		t.Fatalf("fallback expires = %d, want 3600", fallback.ExpiresSeconds)
	}
	if fallback.MaxUploadBytes != 1024 || fallback.MaxDownloadBytes != 2048 || fallback.MaxConnections != 32 || fallback.IdleTimeoutSeconds != 60 {
		t.Fatalf("fallback limits mismatch: upload=%d download=%d conns=%d idle=%d", fallback.MaxUploadBytes, fallback.MaxDownloadBytes, fallback.MaxConnections, fallback.IdleTimeoutSeconds)
	}
	if fallback.NotificationGroupID != 9 {
		t.Fatalf("fallback notification group = %d, want 9", fallback.NotificationGroupID)
	}
	if !fallback.AutoRestart {
		t.Fatal("fallback auto_restart must be restored")
	}
	if !fallback.SetSystemProxy {
		t.Fatal("fallback set_system_proxy must be restored")
	}
	if fallback.EgressProbeURL != "https://ifconfig.example/ip" {
		t.Fatalf("fallback egress probe url = %q, want https://ifconfig.example/ip", fallback.EgressProbeURL)
	}
	if fallback.CoreVersion != "1.12.0" || fallback.CoreDownloadURL != "https://download.example.com/sing-box" || fallback.CoreSHA256 != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("fallback core fields mismatch: version=%q url=%q sha=%q", fallback.CoreVersion, fallback.CoreDownloadURL, fallback.CoreSHA256)
	}
}

func TestVPNFallbackPolicyPrefersLatestPolicyAuditSnapshot(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "policy audit snapshot",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeTunSplit,
		RuleMode:            model.VPNRuleModeGlobal,
		TunName:             "old-tun",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}
	session := startAndRunTestVPNSession(t, h, actor, policy)
	updated, err := h.vpn.UpdatePolicy(actor, policy.ID, model.AgentVPNPolicyForm{
		Name:                "policy audit snapshot updated",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeTunSplit,
		RuleMode:            model.VPNRuleModeGlobal,
		TunName:             "new-tun",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}
	if updated.TunName != "new-tun" {
		t.Fatalf("updated tun name = %q, want new-tun", updated.TunName)
	}
	if err := DB.Delete(&model.AgentVPNPolicy{}, policy.ID).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	delete(h.vpn.sessionPolicies, session.SessionID)
	h.vpn.mu.Unlock()

	fallback := h.vpn.fallbackVPNPolicyForLostSession(session)
	if fallback == nil {
		t.Fatal("fallback policy must still be reconstructed")
	}
	if fallback.Name != "policy audit snapshot updated" {
		t.Fatalf("fallback policy name = %q, want updated snapshot", fallback.Name)
	}
	if fallback.TunName != "new-tun" {
		t.Fatalf("fallback tun name = %q, want latest updated tun name", fallback.TunName)
	}
}

func TestVPNUpdatePolicyRefreshesCachedSessionPolicy(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "cache refresh policy",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeTunSplit,
		RuleMode:            model.VPNRuleModeGlobal,
		TunName:             "old-cache-tun",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}
	session := startAndRunTestVPNSession(t, h, actor, policy)

	updated, err := h.vpn.UpdatePolicy(actor, policy.ID, model.AgentVPNPolicyForm{
		Name:                "cache refresh policy updated",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeTunSplit,
		RuleMode:            model.VPNRuleModeGlobal,
		TunName:             "new-cache-tun",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}
	if updated.TunName != "new-cache-tun" {
		t.Fatalf("updated tun name = %q, want new-cache-tun", updated.TunName)
	}

	cached, err := h.vpn.policyForSession(session)
	if err != nil {
		t.Fatalf("policyForSession after update: %v", err)
	}
	if cached.TunName != "new-cache-tun" {
		t.Fatalf("session policy cache was not refreshed, got tun name %q", cached.TunName)
	}
}

func TestVPNRunningSessionUsesUpdatedPolicyOnNextRestart(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "restart update policy",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeTunSplit,
		RuleMode:            model.VPNRuleModeGlobal,
		TunName:             "before-restart-tun",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}
	session := startAndRunTestVPNSession(t, h, actor, policy)

	updated, err := h.vpn.UpdatePolicy(actor, policy.ID, model.AgentVPNPolicyForm{
		Name:                "restart update policy",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeTunSplit,
		RuleMode:            model.VPNRuleModeGlobal,
		TunName:             "after-restart-tun",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}
	if updated.TunName != "after-restart-tun" {
		t.Fatalf("updated tun name = %q, want after-restart-tun", updated.TunName)
	}

	restarted, err := h.vpn.RestartSession(actor, session.SessionID)
	if err != nil {
		t.Fatalf("restart session: %v", err)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.Action != model.VPNActionRestart {
		t.Fatalf("expected exit restart, got %+v", exitReq)
	}
	if _, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: restarted.SessionID,
		Action:    model.VPNActionRestart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	}); err != nil {
		t.Fatalf("handle exit restart running: %v", err)
	}
	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.TunName != "after-restart-tun" {
		t.Fatalf("entry restart must use updated tun name, got %q", entryReq.TunName)
	}
}

func TestVPNStopSessionSendsEntryThenExitAndMarksStopped(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	*h.notifications = nil

	stopped, err := h.vpn.StopSession(actor, session.SessionID)
	if err != nil {
		t.Fatalf("stop session: %v", err)
	}
	if stopped.State != model.VPNStateStopped {
		t.Fatalf("expected stopped session, got %q", stopped.State)
	}
	if stopped.StoppedAt == nil {
		t.Fatal("stopped session must persist stopped_at")
	}

	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.Action != model.VPNActionStop || entryReq.Role != model.VPNRoleEntry {
		t.Fatalf("expected entry stop first, got action=%q role=%q", entryReq.Action, entryReq.Role)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.Action != model.VPNActionStop || exitReq.Role != model.VPNRoleExit {
		t.Fatalf("expected exit stop second, got action=%q role=%q", exitReq.Action, exitReq.Role)
	}
	if len(*h.notifications) != 1 {
		t.Fatalf("manual stop must send one stop notification, got %#v", *h.notifications)
	}
	notification := (*h.notifications)[0]
	if notification.groupID != policy.NotificationGroupID {
		t.Fatalf("manual stop notification group mismatch: want %d got %d", policy.NotificationGroupID, notification.groupID)
	}
	for _, want := range []string{
		"[Agent VPN] 已停止",
		"策略: GitHub Split",
		"入口节点: entry-cn",
		"出口节点: exit-jp",
		"状态: stopped",
		"本地代理: SOCKS 127.0.0.1:1080",
		"上传/下载: 0 B / 0 B",
		"连接数: 0",
		"时间:",
	} {
		if !strings.Contains(notification.message, want) {
			t.Fatalf("manual stop notification must include %q, got %q", want, notification.message)
		}
	}
}

func TestVPNStopSessionStillStopsWhenPolicyDeleted(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	if err := DB.Delete(&model.AgentVPNPolicy{}, policy.ID).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	delete(h.vpn.sessionPolicies, session.SessionID)
	h.vpn.mu.Unlock()
	*h.notifications = nil

	stopped, err := h.vpn.StopSession(actor, session.SessionID)
	if err != nil {
		t.Fatalf("stop session with deleted policy must still succeed: %v", err)
	}
	if stopped.State != model.VPNStateStopped {
		t.Fatalf("expected stopped session, got %q", stopped.State)
	}
	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.Action != model.VPNActionStop || entryReq.Role != model.VPNRoleEntry {
		t.Fatalf("deleted policy stop must still dispatch entry stop, got action=%q role=%q", entryReq.Action, entryReq.Role)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.Action != model.VPNActionStop || exitReq.Role != model.VPNRoleExit {
		t.Fatalf("deleted policy stop must still dispatch exit stop, got action=%q role=%q", exitReq.Action, exitReq.Role)
	}
	if len(*h.notifications) != 1 {
		t.Fatalf("deleted policy stop must still send one stop notification, got %#v", *h.notifications)
	}
	if (*h.notifications)[0].groupID != policy.NotificationGroupID {
		t.Fatalf("deleted policy stop notification group = %d, want %d", (*h.notifications)[0].groupID, policy.NotificationGroupID)
	}
	for _, want := range []string{
		"策略: GitHub Split",
		"模式: system_proxy",
		"本地代理: SOCKS 127.0.0.1:1080",
	} {
		if !strings.Contains((*h.notifications)[0].message, want) {
			t.Fatalf("deleted policy stop notification must include %q, got %q", want, (*h.notifications)[0].message)
		}
	}
}

func TestVPNStopSessionMarksStoppedWhenEntryStopDispatchFails(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	failingEntry := newFailingTaskStream(errors.New("entry stream closed"))
	entry, ok := ServerShared.Get(policy.EntryServerID)
	if !ok {
		t.Fatal("entry server missing from harness")
	}
	entry.SetTaskStream(failingEntry)
	*h.notifications = nil

	stopped, err := h.vpn.StopSession(actor, session.SessionID)
	if err != nil {
		t.Fatalf("manual stop must not be blocked by entry cleanup dispatch failure: %v", err)
	}
	if stopped.State != model.VPNStateStopped || stopped.EntryState != model.VPNStateStopped || stopped.ExitState != model.VPNStateStopped {
		t.Fatalf("manual stop must mark session stopped despite entry dispatch failure, got state=%q entry=%q exit=%q", stopped.State, stopped.EntryState, stopped.ExitState)
	}
	if stopped.StoppedAt == nil {
		t.Fatal("manual stop must persist stopped_at despite entry dispatch failure")
	}
	if !strings.Contains(stopped.LastError, "entry stream closed") {
		t.Fatalf("manual stop must keep cleanup failure in last_error, got %q", stopped.LastError)
	}
	_, failedEntryReq := readVPNTask(t, &failingEntry.capturedTaskStream)
	if failedEntryReq.Action != model.VPNActionStop || failedEntryReq.Role != model.VPNRoleEntry {
		t.Fatalf("manual stop should still attempt entry cleanup stop, got %+v", failedEntryReq)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.Action != model.VPNActionStop || exitReq.Role != model.VPNRoleExit {
		t.Fatalf("manual stop should still dispatch exit cleanup stop after entry failure, got %+v", exitReq)
	}
	if len(*h.relayCloses) == 0 || (*h.relayCloses)[len(*h.relayCloses)-1] != session.SessionID {
		t.Fatalf("manual stop must close relay despite entry dispatch failure, got %#v", *h.relayCloses)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "已停止") {
		t.Fatalf("manual stop must notify despite entry dispatch failure, got %#v", *h.notifications)
	}
	if !strings.Contains((*h.notifications)[0].message, "清理下发失败") || !strings.Contains((*h.notifications)[0].message, "entry stream closed") {
		t.Fatalf("manual stop notification must include cleanup dispatch failure, got %#v", *h.notifications)
	}
	if _, err := h.vpn.tokenForSession(stopped); err == nil {
		t.Fatal("manual stop must delete session token after best-effort cleanup")
	}
}

func TestVPNRestartSessionReusesExistingSessionAndDispatchesExitRestart(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	oldEntryStreamID := session.EntryStreamID
	oldExitStreamID := session.ExitStreamID
	oldTokenHash := session.TokenHash
	*h.relayCreates = nil
	*h.relayCloses = nil

	restarted, err := h.vpn.RestartSession(actor, session.SessionID)
	if err != nil {
		t.Fatalf("restart session: %v", err)
	}

	if restarted.SessionID != session.SessionID {
		t.Fatalf("manual restart must reuse existing session id, got %q want %q", restarted.SessionID, session.SessionID)
	}
	if restarted.ID != session.ID {
		t.Fatalf("manual restart must update existing row, got id %d want %d", restarted.ID, session.ID)
	}
	if restarted.State != model.VPNStateStarting || restarted.EntryState != model.VPNStatePending || restarted.ExitState != model.VPNStateStarting {
		t.Fatalf("manual restart must stage existing session, got state=%q entry=%q exit=%q", restarted.State, restarted.EntryState, restarted.ExitState)
	}
	if restarted.EntryStreamID == oldEntryStreamID || restarted.ExitStreamID == oldExitStreamID {
		t.Fatalf("manual restart must allocate fresh relay streams, entry=%q old=%q exit=%q old=%q", restarted.EntryStreamID, oldEntryStreamID, restarted.ExitStreamID, oldExitStreamID)
	}
	if restarted.TokenHash == oldTokenHash {
		t.Fatal("manual restart must rotate the per-session token")
	}
	if restarted.StoppedAt != nil {
		t.Fatalf("manual restart must clear stopped_at, got %v", restarted.StoppedAt)
	}
	if len(*h.relayCloses) != 1 || (*h.relayCloses)[0] != session.SessionID {
		t.Fatalf("manual restart must close old relay for %q, got %#v", session.SessionID, *h.relayCloses)
	}
	if len(*h.relayCreates) != 1 || (*h.relayCreates)[0].sessionID != session.SessionID {
		t.Fatalf("manual restart must recreate relay for existing session, got %#v", *h.relayCreates)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.Action != model.VPNActionRestart || exitReq.Role != model.VPNRoleExit || exitReq.SessionID != session.SessionID {
		t.Fatalf("manual restart must dispatch restart to exit first, got %+v", exitReq)
	}
	if exitReq.RelayStreamID != restarted.ExitStreamID {
		t.Fatalf("manual restart exit request must use fresh exit stream %q, got %q", restarted.ExitStreamID, exitReq.RelayStreamID)
	}
	if exitReq.Token == "" {
		t.Fatal("manual restart request must include the rotated token")
	}
	assertNoTask(t, h.entryStream)

	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionRestart, session.SessionID, true).Last(&audit).Error; err != nil {
		t.Fatalf("manual restart must write restart audit: %v", err)
	}
	if audit.Message != "exit restart dispatched" {
		t.Fatalf("manual restart audit message = %q, want exit restart dispatched", audit.Message)
	}
}

func TestVPNRestartSessionStillDispatchesWhenPolicyDeleted(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	oldSessionID := session.SessionID
	if err := DB.Delete(&model.AgentVPNPolicy{}, policy.ID).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	delete(h.vpn.sessionPolicies, session.SessionID)
	h.vpn.mu.Unlock()
	*h.relayCreates = nil
	*h.relayCloses = nil

	restarted, err := h.vpn.RestartSession(actor, session.SessionID)
	if err != nil {
		t.Fatalf("restart session with deleted policy must still dispatch: %v", err)
	}
	if restarted == nil || restarted.SessionID != oldSessionID {
		t.Fatalf("restart session with deleted policy must return same session, got %#v", restarted)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.Action != model.VPNActionRestart || exitReq.Role != model.VPNRoleExit {
		t.Fatalf("restart session with deleted policy must still dispatch exit restart, got %+v", exitReq)
	}
}

func TestVPNRestartSessionDispatchesEntryRestartAfterExitRunning(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)

	restarted, err := h.vpn.RestartSession(actor, session.SessionID)
	if err != nil {
		t.Fatalf("restart session: %v", err)
	}
	readVPNTask(t, h.exitStream)

	if _, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: restarted.SessionID,
		Action:    model.VPNActionRestart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	}); err != nil {
		t.Fatalf("handle exit restart running: %v", err)
	}

	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.Action != model.VPNActionRestart || entryReq.Role != model.VPNRoleEntry || entryReq.SessionID != session.SessionID {
		t.Fatalf("manual restart must dispatch restart to entry after exit running, got %+v", entryReq)
	}
	if entryReq.RelayStreamID != restarted.EntryStreamID {
		t.Fatalf("manual restart entry request must use fresh entry stream %q, got %q", restarted.EntryStreamID, entryReq.RelayStreamID)
	}
	if entryReq.Token == "" {
		t.Fatal("manual restart entry request must include the rotated token")
	}
}

func TestVPNRestartSessionCompletionAuditsAndNotifiesRestart(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	*h.notifications = nil

	restarted, err := h.vpn.RestartSession(actor, session.SessionID)
	if err != nil {
		t.Fatalf("restart session: %v", err)
	}
	readVPNTask(t, h.exitStream)
	if _, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: restarted.SessionID,
		Action:    model.VPNActionRestart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	}); err != nil {
		t.Fatalf("handle exit restart running: %v", err)
	}
	readVPNTask(t, h.entryStream)
	if _, err := h.vpn.HandleControlResult(policy.EntryServerID, model.VPNControlResult{
		SessionID: restarted.SessionID,
		Action:    model.VPNActionRestart,
		Role:      model.VPNRoleEntry,
		State:     model.VPNStateRunning,
	}); err != nil {
		t.Fatalf("handle entry restart running: %v", err)
	}

	var restartAudit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ? AND message = ?", model.VPNAuditActionRestart, session.SessionID, true, "session restarted").Last(&restartAudit).Error; err != nil {
		t.Fatalf("manual restart completion must write restart success audit: %v", err)
	}
	var startAuditCount int64
	if err := DB.Model(&model.AgentVPNAuditLog{}).Where("action = ? AND session_id = ? AND message = ?", model.VPNAuditActionStartSession, session.SessionID, "session started").Count(&startAuditCount).Error; err != nil {
		t.Fatalf("count start audit: %v", err)
	}
	if startAuditCount != 1 {
		t.Fatalf("manual restart completion must not write another start_session success audit, count=%d", startAuditCount)
	}
	if len(*h.notifications) != 1 {
		t.Fatalf("manual restart completion must send one restart notification, got %#v", *h.notifications)
	}
	notification := (*h.notifications)[0]
	if notification.groupID != policy.NotificationGroupID {
		t.Fatalf("restart notification group mismatch: want %d got %d", policy.NotificationGroupID, notification.groupID)
	}
	if !strings.Contains(notification.message, "[Agent VPN] 已重启") ||
		!strings.Contains(notification.message, "入口节点: entry-cn") ||
		!strings.Contains(notification.message, "出口节点: exit-jp") ||
		!strings.Contains(notification.message, "Session: "+session.SessionID) {
		t.Fatalf("restart notification content is incomplete: %q", notification.message)
	}
}

func TestVPNRestartSessionEntryDispatchFailureAuditsAndNotifiesRestartFailure(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	failingEntry := newFailingTaskStream(errors.New("entry restart stream closed"))
	entry, ok := ServerShared.Get(policy.EntryServerID)
	if !ok {
		t.Fatal("entry server missing from harness")
	}
	entry.SetTaskStream(failingEntry)
	*h.notifications = nil

	restarted, err := h.vpn.RestartSession(actor, session.SessionID)
	if err != nil {
		t.Fatalf("restart session: %v", err)
	}
	readVPNTask(t, h.exitStream)
	_, err = h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: restarted.SessionID,
		Action:    model.VPNActionRestart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	})
	if err == nil {
		t.Fatal("entry restart dispatch failure must return an error")
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateFailed || stored.EntryState != model.VPNStateFailed {
		t.Fatalf("entry restart dispatch failure must mark session failed, got state=%q entry=%q", stored.State, stored.EntryState)
	}
	var restartAudit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionRestart, session.SessionID, false).Last(&restartAudit).Error; err != nil {
		t.Fatalf("entry restart dispatch failure must write restart failure audit: %v", err)
	}
	if restartAudit.Detail["stage"] != "entry_restart_dispatch" || restartAudit.Detail["cleanup_dispatched"] != "true" {
		t.Fatalf("restart failure audit detail mismatch: %#v", restartAudit.Detail)
	}
	var startAuditCount int64
	if err := DB.Model(&model.AgentVPNAuditLog{}).Where("action = ? AND session_id = ? AND success = ? AND message LIKE ?", model.VPNAuditActionStartSession, session.SessionID, false, "%entry restart stream closed%").Count(&startAuditCount).Error; err != nil {
		t.Fatalf("count start failure audit: %v", err)
	}
	if startAuditCount != 0 {
		t.Fatalf("entry restart dispatch failure must not be recorded as start failure, count=%d", startAuditCount)
	}
	if len(*h.notifications) != 1 {
		t.Fatalf("entry restart dispatch failure must send one restart failure notification, got %#v", *h.notifications)
	}
	if !strings.Contains((*h.notifications)[0].message, "[Agent VPN] 重启失败") ||
		!strings.Contains((*h.notifications)[0].message, "entry restart stream closed") ||
		!strings.Contains((*h.notifications)[0].message, "Session: "+session.SessionID) {
		t.Fatalf("restart failure notification content mismatch: %q", (*h.notifications)[0].message)
	}
	restartFailureNotification := (*h.notifications)[0].message
	for _, want := range []string{
		"策略: GitHub Split",
		"入口节点: entry-cn",
		"出口节点: exit-jp",
		"状态: failed",
		"本地代理: SOCKS 127.0.0.1:1080",
		"上传/下载: 0 B / 0 B",
		"连接数: 0",
		"错误原因: entry restart stream closed; cleanup dispatch failed: entry: entry restart stream closed",
		"时间:",
	} {
		if !strings.Contains(restartFailureNotification, want) {
			t.Fatalf("restart failure notification must include %q, got %q", want, restartFailureNotification)
		}
	}
}

func TestVPNRestartSessionExitDispatchFailureAuditsAndNotifiesRestartFailure(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	failingExit := newFailingTaskStream(errors.New("exit restart stream closed"))
	exit, ok := ServerShared.Get(policy.ExitServerID)
	if !ok {
		t.Fatal("exit server missing from harness")
	}
	exit.SetTaskStream(failingExit)
	*h.notifications = nil

	restarted, err := h.vpn.RestartSession(actor, session.SessionID)
	if err == nil {
		t.Fatal("exit restart dispatch failure must return an error")
	}
	if restarted == nil || restarted.SessionID != session.SessionID {
		t.Fatalf("exit restart dispatch failure must return the failed session snapshot, got %#v", restarted)
	}
	_, exitReq := readVPNTask(t, &failingExit.capturedTaskStream)
	if exitReq.Action != model.VPNActionRestart || exitReq.Role != model.VPNRoleExit || exitReq.SessionID != session.SessionID {
		t.Fatalf("manual restart should still attempt exit restart dispatch, got %+v", exitReq)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateFailed || stored.ExitState != model.VPNStateFailed {
		t.Fatalf("exit restart dispatch failure must mark session failed, got state=%q exit=%q", stored.State, stored.ExitState)
	}
	if _, err := h.vpn.tokenForSession(&stored); err == nil {
		t.Fatal("exit restart dispatch failure must delete the rotated session token")
	}
	if len(*h.relayCloses) == 0 || (*h.relayCloses)[len(*h.relayCloses)-1] != session.SessionID {
		t.Fatalf("exit restart dispatch failure must close relay, got %#v", *h.relayCloses)
	}

	var restartAudit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionRestart, session.SessionID, false).Last(&restartAudit).Error; err != nil {
		t.Fatalf("exit restart dispatch failure must write restart failure audit: %v", err)
	}
	if restartAudit.Detail["stage"] != "exit_restart_dispatch" || restartAudit.Detail["cleanup_dispatched"] != "false" {
		t.Fatalf("exit restart dispatch failure audit detail mismatch: %#v", restartAudit.Detail)
	}
	var startAuditCount int64
	if err := DB.Model(&model.AgentVPNAuditLog{}).Where("action = ? AND session_id = ? AND success = ? AND message LIKE ?", model.VPNAuditActionStartSession, session.SessionID, false, "%exit restart stream closed%").Count(&startAuditCount).Error; err != nil {
		t.Fatalf("count start failure audit: %v", err)
	}
	if startAuditCount != 0 {
		t.Fatalf("exit restart dispatch failure must not be recorded as start failure, count=%d", startAuditCount)
	}
	if len(*h.notifications) != 1 {
		t.Fatalf("exit restart dispatch failure must send one restart failure notification, got %#v", *h.notifications)
	}
	if !strings.Contains((*h.notifications)[0].message, "[Agent VPN] 重启失败") ||
		!strings.Contains((*h.notifications)[0].message, "exit restart stream closed") ||
		!strings.Contains((*h.notifications)[0].message, "Session: "+session.SessionID) {
		t.Fatalf("exit restart dispatch failure notification content mismatch: %q", (*h.notifications)[0].message)
	}
}

func TestVPNRestartSessionAgentFailedAuditsAndNotifiesRestartFailure(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	*h.notifications = nil

	restarted, err := h.vpn.RestartSession(actor, session.SessionID)
	if err != nil {
		t.Fatalf("restart session: %v", err)
	}
	readVPNTask(t, h.exitStream)
	if _, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: restarted.SessionID,
		Action:    model.VPNActionRestart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	}); err != nil {
		t.Fatalf("handle exit restart running: %v", err)
	}
	readVPNTask(t, h.entryStream)
	if _, err := h.vpn.HandleControlResult(policy.EntryServerID, model.VPNControlResult{
		SessionID: restarted.SessionID,
		Action:    model.VPNActionRestart,
		Role:      model.VPNRoleEntry,
		State:     model.VPNStateFailed,
		LastError: "entry restart sidecar failed",
	}); err != nil {
		t.Fatalf("handle entry restart failed: %v", err)
	}

	var restartAudit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionRestart, session.SessionID, false).Last(&restartAudit).Error; err != nil {
		t.Fatalf("agent restart failure must write restart failure audit: %v", err)
	}
	if restartAudit.Detail["result_action"] != model.VPNActionRestart || restartAudit.Detail["role"] != model.VPNRoleEntry {
		t.Fatalf("restart failure audit detail mismatch: %#v", restartAudit.Detail)
	}
	var startAuditCount int64
	if err := DB.Model(&model.AgentVPNAuditLog{}).Where("action = ? AND session_id = ? AND success = ? AND message LIKE ?", model.VPNAuditActionStartSession, session.SessionID, false, "%entry restart sidecar failed%").Count(&startAuditCount).Error; err != nil {
		t.Fatalf("count start failure audit: %v", err)
	}
	if startAuditCount != 0 {
		t.Fatalf("agent restart failure must not be recorded as start failure, count=%d", startAuditCount)
	}
	if len(*h.notifications) != 1 {
		t.Fatalf("agent restart failure must send one restart failure notification, got %#v", *h.notifications)
	}
	if !strings.Contains((*h.notifications)[0].message, "[Agent VPN] 重启失败") ||
		!strings.Contains((*h.notifications)[0].message, "entry restart sidecar failed") ||
		!strings.Contains((*h.notifications)[0].message, "Session: "+session.SessionID) {
		t.Fatalf("agent restart failure notification content mismatch: %q", (*h.notifications)[0].message)
	}
}

func TestVPNRestartSessionTokenGenerationFailureAuditsAndNotifiesRestartFailure(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	oldTokenHash := session.TokenHash
	oldEntryStreamID := session.EntryStreamID
	oldExitStreamID := session.ExitStreamID
	*h.notifications = nil
	*h.relayCreates = nil
	*h.relayCloses = nil
	VPNTokenGenerator = func() (string, error) {
		return "", errors.New("restart token entropy unavailable")
	}

	restarted, err := h.vpn.RestartSession(actor, session.SessionID)
	if err == nil {
		t.Fatal("restart token generation failure must reject manual restart")
	}
	if restarted == nil || restarted.SessionID != session.SessionID {
		t.Fatalf("restart token generation failure must return the original session snapshot, got %#v", restarted)
	}
	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.TokenHash != oldTokenHash || stored.EntryStreamID != oldEntryStreamID || stored.ExitStreamID != oldExitStreamID {
		t.Fatalf("restart token generation failure must not rotate token or streams, got token=%q entry=%q exit=%q", stored.TokenHash, stored.EntryStreamID, stored.ExitStreamID)
	}
	if len(*h.relayCreates) != 0 || len(*h.relayCloses) != 0 {
		t.Fatalf("restart token generation failure must not touch relay, creates=%#v closes=%#v", *h.relayCreates, *h.relayCloses)
	}
	assertNoTask(t, h.exitStream)
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionRestart, session.SessionID, false).Last(&audit).Error; err != nil {
		t.Fatalf("restart token generation failure must write restart failure audit: %v", err)
	}
	if audit.Detail["stage"] != "token_generation" || !strings.Contains(audit.Message, "restart token entropy unavailable") {
		t.Fatalf("restart token generation audit mismatch: message=%q detail=%#v", audit.Message, audit.Detail)
	}
	if len(*h.notifications) != 1 {
		t.Fatalf("restart token generation failure must send one notification, got %#v", *h.notifications)
	}
	if !strings.Contains((*h.notifications)[0].message, "[Agent VPN] 重启失败") ||
		!strings.Contains((*h.notifications)[0].message, "restart token entropy unavailable") {
		t.Fatalf("restart token generation notification mismatch: %q", (*h.notifications)[0].message)
	}
	restartNotification := (*h.notifications)[0].message
	for _, want := range []string{
		"策略: GitHub Split",
		"状态: running",
		"模式: system_proxy",
		"本地代理: SOCKS 127.0.0.1:1080",
		"上传/下载: 0 B / 0 B",
		"连接数: 0",
		"错误原因: restart token entropy unavailable",
		"时间:",
	} {
		if !strings.Contains(restartNotification, want) {
			t.Fatalf("restart token generation notification must include %q, got %q", want, restartNotification)
		}
	}
}

func TestVPNRestartSessionStreamIDGenerationFailureAuditsAndNotifiesRestartFailure(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	oldEntryStreamID := session.EntryStreamID
	oldExitStreamID := session.ExitStreamID
	*h.notifications = nil
	*h.relayCreates = nil
	*h.relayCloses = nil
	VPNIDGenerator = func(prefix string) (string, error) {
		if prefix == "vpn_entry_" {
			return "", errors.New("restart entry stream id unavailable")
		}
		return prefix + "ok", nil
	}

	restarted, err := h.vpn.RestartSession(actor, session.SessionID)
	if err == nil {
		t.Fatal("restart stream id generation failure must reject manual restart")
	}
	if restarted == nil || restarted.SessionID != session.SessionID {
		t.Fatalf("restart stream id generation failure must return original session snapshot, got %#v", restarted)
	}
	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.EntryStreamID != oldEntryStreamID || stored.ExitStreamID != oldExitStreamID {
		t.Fatalf("restart stream id generation failure must not replace relay streams, entry=%q old=%q exit=%q old=%q", stored.EntryStreamID, oldEntryStreamID, stored.ExitStreamID, oldExitStreamID)
	}
	if len(*h.relayCreates) != 0 || len(*h.relayCloses) != 0 {
		t.Fatalf("restart stream id generation failure must not touch relay, creates=%#v closes=%#v", *h.relayCreates, *h.relayCloses)
	}
	assertNoTask(t, h.exitStream)
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionRestart, session.SessionID, false).Last(&audit).Error; err != nil {
		t.Fatalf("restart stream id generation failure must write restart failure audit: %v", err)
	}
	if audit.Detail["stage"] != "entry_stream_id_generation" || !strings.Contains(audit.Message, "restart entry stream id unavailable") {
		t.Fatalf("restart stream id generation audit mismatch: message=%q detail=%#v", audit.Message, audit.Detail)
	}
	if len(*h.notifications) != 1 {
		t.Fatalf("restart stream id generation failure must send one notification, got %#v", *h.notifications)
	}
	if !strings.Contains((*h.notifications)[0].message, "[Agent VPN] 重启失败") ||
		!strings.Contains((*h.notifications)[0].message, "restart entry stream id unavailable") {
		t.Fatalf("restart stream id generation notification mismatch: %q", (*h.notifications)[0].message)
	}
}

func TestVPNRestartSessionOfflinePreflightAuditsAndNotifiesRestartFailure(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	oldTokenHash := session.TokenHash
	oldEntryStreamID := session.EntryStreamID
	oldExitStreamID := session.ExitStreamID
	h.mustServer(policy.EntryServerID).SetTaskStream(nil)
	*h.notifications = nil
	*h.relayCreates = nil
	*h.relayCloses = nil

	restarted, err := h.vpn.RestartSession(actor, session.SessionID)
	if err == nil {
		t.Fatal("offline entry must reject manual restart")
	}
	if restarted == nil || restarted.SessionID != session.SessionID {
		t.Fatalf("offline restart failure must return the original session snapshot, got %#v", restarted)
	}
	if !strings.Contains(err.Error(), "entry server 1 is offline") {
		t.Fatalf("error = %q, want offline entry reason", err.Error())
	}
	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.TokenHash != oldTokenHash || stored.EntryStreamID != oldEntryStreamID || stored.ExitStreamID != oldExitStreamID {
		t.Fatalf("offline restart failure must not rotate token or streams, got token=%q entry=%q exit=%q", stored.TokenHash, stored.EntryStreamID, stored.ExitStreamID)
	}
	if stored.State != model.VPNStateRunning {
		t.Fatalf("offline restart preflight failure must leave running session unchanged, got %q", stored.State)
	}
	if len(*h.relayCreates) != 0 || len(*h.relayCloses) != 0 {
		t.Fatalf("offline restart failure must not touch relay, creates=%#v closes=%#v", *h.relayCreates, *h.relayCloses)
	}
	assertNoTask(t, h.exitStream)
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionRestart, session.SessionID, false).Last(&audit).Error; err != nil {
		t.Fatalf("offline restart failure must write restart failure audit: %v", err)
	}
	if audit.Detail["stage"] != "entry_offline" || !strings.Contains(audit.Message, "entry server 1 is offline") {
		t.Fatalf("offline restart audit mismatch: message=%q detail=%#v", audit.Message, audit.Detail)
	}
	if len(*h.notifications) != 1 {
		t.Fatalf("offline restart failure must send one notification, got %#v", *h.notifications)
	}
	if !strings.Contains((*h.notifications)[0].message, "[Agent VPN] 重启失败") ||
		!strings.Contains((*h.notifications)[0].message, "entry server 1 is offline") {
		t.Fatalf("offline restart failure notification mismatch: %q", (*h.notifications)[0].message)
	}
}

func TestVPNRestartSessionCapabilityPreflightAuditsAndNotifiesRestartFailure(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	oldEntryStreamID := session.EntryStreamID
	oldExitStreamID := session.ExitStreamID
	h.mustServer(policy.EntryServerID).Host.VPNAllowSystemProxy = false
	*h.notifications = nil
	*h.relayCreates = nil
	*h.relayCloses = nil

	restarted, err := h.vpn.RestartSession(actor, session.SessionID)
	if err == nil {
		t.Fatal("capability preflight failure must reject manual restart")
	}
	if restarted == nil || restarted.SessionID != session.SessionID {
		t.Fatalf("capability restart failure must return original session snapshot, got %#v", restarted)
	}
	if !strings.Contains(err.Error(), "entry server 1 does not allow Agent VPN system_proxy mode") {
		t.Fatalf("error = %q, want capability reason", err.Error())
	}
	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.EntryStreamID != oldEntryStreamID || stored.ExitStreamID != oldExitStreamID {
		t.Fatalf("capability restart failure must not allocate streams, entry=%q exit=%q", stored.EntryStreamID, stored.ExitStreamID)
	}
	if len(*h.relayCreates) != 0 || len(*h.relayCloses) != 0 {
		t.Fatalf("capability restart failure must not touch relay, creates=%#v closes=%#v", *h.relayCreates, *h.relayCloses)
	}
	assertNoTask(t, h.entryStream)
	assertNoTask(t, h.exitStream)
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionRestart, session.SessionID, false).Last(&audit).Error; err != nil {
		t.Fatalf("capability restart failure must write restart failure audit: %v", err)
	}
	if audit.Detail["stage"] != "capability_validation" || !strings.Contains(audit.Message, "does not allow Agent VPN system_proxy mode") {
		t.Fatalf("capability restart audit mismatch: message=%q detail=%#v", audit.Message, audit.Detail)
	}
	if len(*h.notifications) != 1 {
		t.Fatalf("capability restart failure must send one notification, got %#v", *h.notifications)
	}
	if !strings.Contains((*h.notifications)[0].message, "[Agent VPN] 重启失败") ||
		!strings.Contains((*h.notifications)[0].message, "does not allow Agent VPN system_proxy mode") {
		t.Fatalf("capability restart failure notification mismatch: %q", (*h.notifications)[0].message)
	}
}

func TestVPNRestartSessionRejectsLegacyPolicyWithInvalidModeBeforeRuntime(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	oldTokenHash := session.TokenHash
	oldEntryStreamID := session.EntryStreamID
	oldExitStreamID := session.ExitStreamID
	if err := DB.Model(&model.AgentVPNPolicy{}).Where("id = ?", policy.ID).Updates(map[string]any{
		"mode": "wireguard",
	}).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	if cached := h.vpn.sessionPolicies[session.SessionID]; cached != nil {
		cached.Mode = "wireguard"
	}
	h.vpn.mu.Unlock()
	*h.notifications = nil
	*h.relayCreates = nil
	*h.relayCloses = nil

	restarted, err := h.vpn.RestartSession(actor, session.SessionID)
	if err == nil {
		t.Fatal("legacy invalid mode must reject manual restart before runtime")
	}
	if restarted == nil || restarted.SessionID != session.SessionID {
		t.Fatalf("legacy invalid mode restart failure must return original session snapshot, got %#v", restarted)
	}
	if !strings.Contains(err.Error(), `unsupported vpn mode "wireguard"`) {
		t.Fatalf("error = %q, want unsupported vpn mode", err.Error())
	}
	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.TokenHash != oldTokenHash || stored.EntryStreamID != oldEntryStreamID || stored.ExitStreamID != oldExitStreamID {
		t.Fatalf("legacy invalid mode restart must not rotate token or streams, got token=%q entry=%q exit=%q", stored.TokenHash, stored.EntryStreamID, stored.ExitStreamID)
	}
	if stored.State != model.VPNStateRunning {
		t.Fatalf("legacy invalid mode restart must leave running session unchanged, got %q", stored.State)
	}
	if len(*h.relayCreates) != 0 || len(*h.relayCloses) != 0 {
		t.Fatalf("legacy invalid mode restart must not touch relay, creates=%#v closes=%#v", *h.relayCreates, *h.relayCloses)
	}
	assertNoTask(t, h.entryStream)
	assertNoTask(t, h.exitStream)
}

func TestVPNRestartSessionRejectsLegacyPolicyWithInvalidRuleModeBeforeRuntime(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	oldTokenHash := session.TokenHash
	oldEntryStreamID := session.EntryStreamID
	oldExitStreamID := session.ExitStreamID
	if err := DB.Model(&model.AgentVPNPolicy{}).Where("id = ?", policy.ID).Updates(map[string]any{
		"rule_mode": "suffix",
	}).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	if cached := h.vpn.sessionPolicies[session.SessionID]; cached != nil {
		cached.RuleMode = "suffix"
	}
	h.vpn.mu.Unlock()
	*h.notifications = nil
	*h.relayCreates = nil
	*h.relayCloses = nil

	restarted, err := h.vpn.RestartSession(actor, session.SessionID)
	if err == nil {
		t.Fatal("legacy invalid rule mode must reject manual restart before runtime")
	}
	if restarted == nil || restarted.SessionID != session.SessionID {
		t.Fatalf("legacy invalid rule mode restart failure must return original session snapshot, got %#v", restarted)
	}
	if !strings.Contains(err.Error(), `unsupported vpn rule mode "suffix"`) {
		t.Fatalf("error = %q, want unsupported vpn rule mode", err.Error())
	}
	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.TokenHash != oldTokenHash || stored.EntryStreamID != oldEntryStreamID || stored.ExitStreamID != oldExitStreamID {
		t.Fatalf("legacy invalid rule mode restart must not rotate token or streams, got token=%q entry=%q exit=%q", stored.TokenHash, stored.EntryStreamID, stored.ExitStreamID)
	}
	if stored.State != model.VPNStateRunning {
		t.Fatalf("legacy invalid rule mode restart must leave running session unchanged, got %q", stored.State)
	}
	if len(*h.relayCreates) != 0 || len(*h.relayCloses) != 0 {
		t.Fatalf("legacy invalid rule mode restart must not touch relay, creates=%#v closes=%#v", *h.relayCreates, *h.relayCloses)
	}
	assertNoTask(t, h.entryStream)
	assertNoTask(t, h.exitStream)
}

func TestVPNRecoverActiveSessionsMarksUnknownAndQueriesOnlineAgents(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	h.vpn = NewVPNClass()
	VPNShared = h.vpn

	if err := h.vpn.RecoverActiveSessions(); err != nil {
		t.Fatalf("recover active sessions: %v", err)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateUnknown {
		t.Fatalf("dashboard recovery must mark active session unknown until agents answer, got %q", stored.State)
	}
	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.Action != model.VPNActionStatus || entryReq.Role != model.VPNRoleEntry || entryReq.SessionID != session.SessionID {
		t.Fatalf("expected entry status request for recovered session, got %+v", entryReq)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.Action != model.VPNActionStatus || exitReq.Role != model.VPNRoleExit || exitReq.SessionID != session.SessionID {
		t.Fatalf("expected exit status request for recovered session, got %+v", exitReq)
	}
}

func TestVPNRefreshSessionStatusRejectsLegacyPolicyWithInvalidModeBeforeDispatch(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	if err := DB.Model(&model.AgentVPNPolicy{}).Where("id = ?", policy.ID).Updates(map[string]any{
		"mode": "wireguard",
	}).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	if cached := h.vpn.sessionPolicies[session.SessionID]; cached != nil {
		cached.Mode = "wireguard"
	}
	h.vpn.mu.Unlock()

	refreshed, err := h.vpn.RefreshSessionStatus(actor, session.SessionID)
	if err == nil {
		t.Fatal("legacy invalid mode must reject status query before dispatch")
	}
	if refreshed == nil || refreshed.SessionID != session.SessionID {
		t.Fatalf("legacy invalid mode status failure must return current session snapshot, got %#v", refreshed)
	}
	if !strings.Contains(err.Error(), `unsupported vpn mode "wireguard"`) {
		t.Fatalf("error = %q, want unsupported vpn mode", err.Error())
	}
	assertNoTask(t, h.entryStream)
	assertNoTask(t, h.exitStream)
}

func TestVPNRefreshSessionStatusRejectsLegacyPolicyWithInvalidRuleModeBeforeDispatch(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	if err := DB.Model(&model.AgentVPNPolicy{}).Where("id = ?", policy.ID).Updates(map[string]any{
		"rule_mode": "suffix",
	}).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	if cached := h.vpn.sessionPolicies[session.SessionID]; cached != nil {
		cached.RuleMode = "suffix"
	}
	h.vpn.mu.Unlock()

	refreshed, err := h.vpn.RefreshSessionStatus(actor, session.SessionID)
	if err == nil {
		t.Fatal("legacy invalid rule mode must reject status query before dispatch")
	}
	if refreshed == nil || refreshed.SessionID != session.SessionID {
		t.Fatalf("legacy invalid rule mode status failure must return current session snapshot, got %#v", refreshed)
	}
	if !strings.Contains(err.Error(), `unsupported vpn rule mode "suffix"`) {
		t.Fatalf("error = %q, want unsupported vpn rule mode", err.Error())
	}
	assertNoTask(t, h.entryStream)
	assertNoTask(t, h.exitStream)
}

func TestVPNRefreshSessionStatusStillDispatchesWhenPolicyDeleted(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	if err := DB.Delete(&model.AgentVPNPolicy{}, policy.ID).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	delete(h.vpn.sessionPolicies, session.SessionID)
	h.vpn.mu.Unlock()

	refreshed, err := h.vpn.RefreshSessionStatus(actor, session.SessionID)
	if err != nil {
		t.Fatalf("status query with deleted policy must still dispatch: %v", err)
	}
	if refreshed == nil || refreshed.SessionID != session.SessionID {
		t.Fatalf("status query with deleted policy must return current session snapshot, got %#v", refreshed)
	}
	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.Action != model.VPNActionStatus || entryReq.Role != model.VPNRoleEntry {
		t.Fatalf("deleted policy status must still dispatch entry status, got %+v", entryReq)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.Action != model.VPNActionStatus || exitReq.Role != model.VPNRoleExit {
		t.Fatalf("deleted policy status must still dispatch exit status, got %+v", exitReq)
	}
}

func TestVPNRecoverActiveSessionsWaitsForBothAgentStatusesBeforeRunning(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	h.vpn = NewVPNClass()
	VPNShared = h.vpn
	*h.notifications = nil

	if err := h.vpn.RecoverActiveSessions(); err != nil {
		t.Fatalf("recover active sessions: %v", err)
	}

	recovered, err := h.vpn.HandleControlResult(policy.EntryServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStatus,
		Role:      model.VPNRoleEntry,
		State:     model.VPNStateRunning,
	})
	if err != nil {
		t.Fatalf("handle recovered entry status: %v", err)
	}
	if recovered.State == model.VPNStateRunning {
		t.Fatalf("recovered session must wait for both agent statuses before running, got state=%q entry=%q exit=%q", recovered.State, recovered.EntryState, recovered.ExitState)
	}
	if recovered.EntryState != model.VPNStateRunning || recovered.ExitState != model.VPNStateUnknown {
		t.Fatalf("recovered entry status must only update entry state, got entry=%q exit=%q", recovered.EntryState, recovered.ExitState)
	}
	if len(*h.notifications) != 0 {
		t.Fatalf("single recovered endpoint must not send start notification, got %#v", *h.notifications)
	}
}

func TestVPNRecoverActiveSessionsRequeriesUnknownSessions(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	h.vpn = NewVPNClass()
	VPNShared = h.vpn

	if err := DB.Model(&model.AgentVPNSession{}).Where("id = ?", session.ID).Updates(map[string]any{
		"state":       model.VPNStateUnknown,
		"entry_state": model.VPNStateRunning,
		"exit_state":  model.VPNStateUnknown,
		"last_error":  "dashboard restarted; waiting for agent status",
	}).Error; err != nil {
		t.Fatal(err)
	}

	if err := h.vpn.RecoverActiveSessions(); err != nil {
		t.Fatalf("recover unknown session: %v", err)
	}

	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.Action != model.VPNActionStatus || entryReq.Role != model.VPNRoleEntry || entryReq.SessionID != session.SessionID {
		t.Fatalf("expected entry status request for unknown recovered session, got %+v", entryReq)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.Action != model.VPNActionStatus || exitReq.Role != model.VPNRoleExit || exitReq.SessionID != session.SessionID {
		t.Fatalf("expected exit status request for unknown recovered session, got %+v", exitReq)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateUnknown || stored.EntryState != model.VPNStateUnknown || stored.ExitState != model.VPNStateUnknown {
		t.Fatalf("dashboard recovery must reset unknown session endpoint states before requery, got state=%q entry=%q exit=%q", stored.State, stored.EntryState, stored.ExitState)
	}
}

func TestVPNRecoverActiveSessionsNormalizesLegacyEmptyRelayMode(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	h.vpn = NewVPNClass()
	VPNShared = h.vpn

	if err := DB.Model(&model.AgentVPNSession{}).Where("id = ?", session.ID).Updates(map[string]any{
		"state":      model.VPNStateUnknown,
		"relay_mode": "",
	}).Error; err != nil {
		t.Fatal(err)
	}

	if err := h.vpn.RecoverActiveSessions(); err != nil {
		t.Fatalf("recover legacy empty relay mode session: %v", err)
	}

	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.RelayMode != model.VPNRelayModeDashboard {
		t.Fatalf("entry recovery request must normalize empty relay_mode to dashboard, got %+v", entryReq)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.RelayMode != model.VPNRelayModeDashboard {
		t.Fatalf("exit recovery request must normalize empty relay_mode to dashboard, got %+v", exitReq)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.RelayMode != model.VPNRelayModeDashboard {
		t.Fatalf("legacy recovered session relay_mode must be persisted as dashboard, got %q", stored.RelayMode)
	}
}

func TestVPNRecoverActiveSessionsMarksLostAndNotifiesWhenAgentOffline(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	h.vpn = NewVPNClass()
	VPNShared = h.vpn
	*h.notifications = nil

	exit, ok := ServerShared.Get(policy.ExitServerID)
	if !ok {
		t.Fatal("exit server missing from harness")
	}
	exit.SetTaskStream(nil)

	if err := h.vpn.RecoverActiveSessions(); err != nil {
		t.Fatalf("recover active sessions: %v", err)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateLost {
		t.Fatalf("offline agent during dashboard recovery must mark session lost, got %q", stored.State)
	}
	if stored.ExitState != model.VPNStateLost {
		t.Fatalf("offline exit agent must mark exit state lost, got %q", stored.ExitState)
	}
	if !strings.Contains(stored.LastError, "offline") {
		t.Fatalf("lost recovery must persist offline reason, got %q", stored.LastError)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "已失联") {
		t.Fatalf("lost recovery must send lost notification, got %#v", *h.notifications)
	}
}

func TestVPNRecoverActiveSessionsMarksLostWhenLegacyPolicyIsInvalid(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	h.vpn = NewVPNClass()
	VPNShared = h.vpn
	if err := DB.Model(&model.AgentVPNPolicy{}).Where("id = ?", policy.ID).Updates(map[string]any{
		"mode": "wireguard",
	}).Error; err != nil {
		t.Fatal(err)
	}
	*h.notifications = nil

	if err := h.vpn.RecoverActiveSessions(); err != nil {
		t.Fatalf("recover active sessions with invalid legacy policy: %v", err)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateLost {
		t.Fatalf("invalid legacy policy during recovery must mark session lost, got %q", stored.State)
	}
	if !strings.Contains(stored.LastError, `unsupported vpn mode "wireguard"`) {
		t.Fatalf("lost reason must include invalid policy error, got %q", stored.LastError)
	}
	if len(*h.notifications) != 1 {
		t.Fatalf("invalid legacy policy during recovery must send one lost notification, got %#v", *h.notifications)
	}
	var statusAuditCount int64
	if err := DB.Model(&model.AgentVPNAuditLog{}).
		Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionStatus, session.SessionID, false).
		Count(&statusAuditCount).Error; err != nil {
		t.Fatal(err)
	}
	if statusAuditCount != 1 {
		t.Fatalf("invalid legacy policy during recovery must write one lost status audit, got %d", statusAuditCount)
	}
	assertNoTask(t, h.entryStream)
	assertNoTask(t, h.exitStream)
}

func TestVPNRecoverActiveSessionsPolicyMissingWritesLostAuditAndNotification(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	h.vpn = NewVPNClass()
	VPNShared = h.vpn
	if err := DB.Delete(&model.AgentVPNPolicy{}, policy.ID).Error; err != nil {
		t.Fatal(err)
	}
	*h.notifications = nil

	if err := h.vpn.RecoverActiveSessions(); err != nil {
		t.Fatalf("recover active sessions with missing policy: %v", err)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateLost {
		t.Fatalf("missing policy during recovery must mark session lost, got %q", stored.State)
	}
	if !strings.Contains(stored.LastError, "policy not found during recovery") {
		t.Fatalf("lost reason must include missing policy error, got %q", stored.LastError)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "已失联") {
		t.Fatalf("missing policy during recovery must send lost notification, got %#v", *h.notifications)
	}
	if (*h.notifications)[0].groupID != policy.NotificationGroupID {
		t.Fatalf("missing policy during recovery notification group = %d, want %d", (*h.notifications)[0].groupID, policy.NotificationGroupID)
	}
	for _, want := range []string{
		"策略: GitHub Split",
		"模式: system_proxy",
		"本地代理: SOCKS 127.0.0.1:1080",
	} {
		if !strings.Contains((*h.notifications)[0].message, want) {
			t.Fatalf("missing policy during recovery notification must include %q, got %q", want, (*h.notifications)[0].message)
		}
	}
	var statusAuditCount int64
	if err := DB.Model(&model.AgentVPNAuditLog{}).
		Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionStatus, session.SessionID, false).
		Count(&statusAuditCount).Error; err != nil {
		t.Fatal(err)
	}
	if statusAuditCount != 1 {
		t.Fatalf("missing policy during recovery must write one lost status audit, got %d", statusAuditCount)
	}
}

func TestVPNMarkSessionLostDeduplicatesRepeatedReasonAndSource(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	*h.notifications = nil

	if err := h.vpn.markSessionLost(session, policy, model.VPNRoleEntry, "entry disconnected", "dashboard recovery"); err != nil {
		t.Fatalf("first markSessionLost: %v", err)
	}
	if err := h.vpn.markSessionLost(session, policy, model.VPNRoleEntry, "entry disconnected", "dashboard recovery"); err != nil {
		t.Fatalf("second markSessionLost: %v", err)
	}

	if len(*h.notifications) != 1 {
		t.Fatalf("repeated lost with same reason/source must send one notification, got %#v", *h.notifications)
	}
	var auditCount int64
	if err := DB.Model(&model.AgentVPNAuditLog{}).
		Where("action = ? AND session_id = ? AND success = ? AND message = ?", model.VPNAuditActionStatus, session.SessionID, false, "entry disconnected").
		Count(&auditCount).Error; err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("repeated lost with same reason/source must write one audit, got %d", auditCount)
	}
}

func TestVPNExpireSessionsStopsExpiredRunningSessionsAndNotifies(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	expiredAt := time.Now().Add(-time.Minute)
	if err := DB.Model(&model.AgentVPNSession{}).Where("id = ?", session.ID).Updates(map[string]any{
		"expires_at": expiredAt,
	}).Error; err != nil {
		t.Fatal(err)
	}
	*h.notifications = nil

	if err := h.vpn.ExpireSessions(time.Now()); err != nil {
		t.Fatalf("expire sessions: %v", err)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateStopped || stored.EntryState != model.VPNStateStopped || stored.ExitState != model.VPNStateStopped {
		t.Fatalf("expired session must be stopped, got state=%q entry=%q exit=%q", stored.State, stored.EntryState, stored.ExitState)
	}
	if stored.StoppedAt == nil {
		t.Fatal("expired session must persist stopped_at")
	}
	if !strings.Contains(stored.LastError, "expired") {
		t.Fatalf("expired session must persist reason, got %q", stored.LastError)
	}
	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.Action != model.VPNActionStop || entryReq.Role != model.VPNRoleEntry {
		t.Fatalf("expected entry stop for expired session, got %+v", entryReq)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.Action != model.VPNActionStop || exitReq.Role != model.VPNRoleExit {
		t.Fatalf("expected exit stop for expired session, got %+v", exitReq)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "已过期停止") {
		t.Fatalf("expired session must send notification, got %#v", *h.notifications)
	}
	expiredNotification := (*h.notifications)[0].message
	for _, want := range []string{
		"策略: GitHub Split",
		"入口节点: entry-cn",
		"出口节点: exit-jp",
		"状态: stopped",
		"本地代理: SOCKS 127.0.0.1:1080",
		"上传/下载: 0 B / 0 B",
		"连接数: 0",
		"错误原因: session expired",
		"时间:",
	} {
		if !strings.Contains(expiredNotification, want) {
			t.Fatalf("expired session notification must include %q, got %q", want, expiredNotification)
		}
	}

	_, err := h.vpn.HandleControlResult(policy.EntryServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStop,
		Role:      model.VPNRoleEntry,
		State:     model.VPNStateStopped,
		Logs: []string{
			"[cleanup] system_proxy_restore=ok",
			"[cleanup] tun_restore=ok",
		},
	})
	if err != nil {
		t.Fatalf("late expired cleanup result must be accepted: %v", err)
	}
	if len(*h.notifications) != 2 {
		t.Fatalf("expired late cleanup result must send cleanup notification, got %#v", *h.notifications)
	}
	cleanupNotification := (*h.notifications)[1].message
	if !strings.Contains(cleanupNotification, "停止清理结果") ||
		!strings.Contains(cleanupNotification, "system_proxy_restore=ok") ||
		!strings.Contains(cleanupNotification, "tun_restore=ok") {
		t.Fatalf("expired late cleanup notification must include cleanup logs, got %q", cleanupNotification)
	}
	var cleanupAudit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND message = ?", model.VPNAuditActionStopSession, session.SessionID, "late agent cleanup result").Last(&cleanupAudit).Error; err != nil {
		t.Fatalf("expired late cleanup result must write audit: %v", err)
	}
	if !strings.Contains(cleanupAudit.Detail["agent_cleanup_logs"], "system_proxy_restore=ok") ||
		!strings.Contains(cleanupAudit.Detail["agent_cleanup_logs"], "tun_restore=ok") {
		t.Fatalf("expired late cleanup audit must include cleanup logs, detail=%#v", cleanupAudit.Detail)
	}
}

func TestVPNExpireSessionsStillStopsWhenPolicyDeleted(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	expiredAt := time.Now().Add(-time.Minute)
	if err := DB.Model(&model.AgentVPNSession{}).Where("id = ?", session.ID).Updates(map[string]any{
		"expires_at": expiredAt,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := DB.Delete(&model.AgentVPNPolicy{}, policy.ID).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	delete(h.vpn.sessionPolicies, session.SessionID)
	h.vpn.mu.Unlock()
	*h.notifications = nil

	if err := h.vpn.ExpireSessions(time.Now()); err != nil {
		t.Fatalf("expire sessions with deleted policy must still succeed: %v", err)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateStopped {
		t.Fatalf("expired session with deleted policy must still stop, got %q", stored.State)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "已过期停止") {
		t.Fatalf("expired session with deleted policy must still notify, got %#v", *h.notifications)
	}
	if (*h.notifications)[0].groupID != policy.NotificationGroupID {
		t.Fatalf("expired session with deleted policy notification group = %d, want %d", (*h.notifications)[0].groupID, policy.NotificationGroupID)
	}
}

func TestVPNExpireSessionsStopsExpiredSessionWhenEntryStopDispatchFails(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	expiredAt := time.Now().Add(-time.Minute)
	if err := DB.Model(&model.AgentVPNSession{}).Where("id = ?", session.ID).Updates(map[string]any{
		"expires_at": expiredAt,
	}).Error; err != nil {
		t.Fatal(err)
	}
	failingEntry := newFailingTaskStream(errors.New("entry stream closed"))
	entry, ok := ServerShared.Get(policy.EntryServerID)
	if !ok {
		t.Fatal("entry server missing from harness")
	}
	entry.SetTaskStream(failingEntry)
	*h.notifications = nil

	if err := h.vpn.ExpireSessions(time.Now()); err != nil {
		t.Fatalf("expire sessions must not be blocked by cleanup dispatch failures: %v", err)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateStopped || stored.EntryState != model.VPNStateStopped || stored.ExitState != model.VPNStateStopped {
		t.Fatalf("expired session must be stopped despite entry dispatch failure, got state=%q entry=%q exit=%q", stored.State, stored.EntryState, stored.ExitState)
	}
	if stored.StoppedAt == nil {
		t.Fatal("expired session must persist stopped_at despite entry dispatch failure")
	}
	if !strings.Contains(stored.LastError, "expired") {
		t.Fatalf("expired session must keep expired reason, got %q", stored.LastError)
	}
	_, failedEntryReq := readVPNTask(t, &failingEntry.capturedTaskStream)
	if failedEntryReq.Action != model.VPNActionStop || failedEntryReq.Role != model.VPNRoleEntry {
		t.Fatalf("expiry should still attempt entry cleanup stop, got %+v", failedEntryReq)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.Action != model.VPNActionStop || exitReq.Role != model.VPNRoleExit {
		t.Fatalf("expiry should still dispatch exit cleanup stop after entry failure, got %+v", exitReq)
	}
	if len(*h.relayCloses) == 0 || (*h.relayCloses)[len(*h.relayCloses)-1] != session.SessionID {
		t.Fatalf("expired session must close relay despite entry dispatch failure, got %#v", *h.relayCloses)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "已过期停止") {
		t.Fatalf("expired session must notify despite entry dispatch failure, got %#v", *h.notifications)
	}
	if !strings.Contains((*h.notifications)[0].message, "清理下发失败") || !strings.Contains((*h.notifications)[0].message, "entry stream closed") {
		t.Fatalf("expired session notification must include cleanup dispatch failure, got %#v", *h.notifications)
	}
	if _, err := h.vpn.tokenForSession(&stored); err == nil {
		t.Fatal("expired session token must be deleted after best-effort cleanup")
	}
}

func TestVPNOnAgentReconnectQueriesBoundActiveSessions(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)

	if err := h.vpn.OnAgentReconnect(policy.EntryServerID); err != nil {
		t.Fatalf("agent reconnect: %v", err)
	}

	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.Action != model.VPNActionStatus || entryReq.Role != model.VPNRoleEntry || entryReq.SessionID != session.SessionID {
		t.Fatalf("entry reconnect must query status for bound session, got %+v", entryReq)
	}
	assertNoTask(t, h.exitStream)
}

func TestVPNOnAgentReconnectMarksLostWhenLegacyPolicyIsInvalid(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	if err := DB.Model(&model.AgentVPNPolicy{}).Where("id = ?", policy.ID).Updates(map[string]any{
		"rule_mode": "suffix",
	}).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	if cached := h.vpn.sessionPolicies[session.SessionID]; cached != nil {
		cached.RuleMode = "suffix"
	}
	h.vpn.mu.Unlock()
	*h.notifications = nil

	if err := h.vpn.OnAgentReconnect(policy.EntryServerID); err != nil {
		t.Fatalf("agent reconnect with invalid legacy policy: %v", err)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateLost {
		t.Fatalf("invalid legacy policy on reconnect must mark session lost, got %q", stored.State)
	}
	if !strings.Contains(stored.LastError, `unsupported vpn rule mode "suffix"`) {
		t.Fatalf("lost reason must include invalid policy error, got %q", stored.LastError)
	}
	assertNoTask(t, h.entryStream)
	assertNoTask(t, h.exitStream)
}

func TestVPNOnAgentReconnectPolicyMissingWritesLostAuditAndNotification(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	if err := DB.Delete(&model.AgentVPNPolicy{}, policy.ID).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	delete(h.vpn.sessionPolicies, session.SessionID)
	h.vpn.mu.Unlock()
	*h.notifications = nil

	if err := h.vpn.OnAgentReconnect(policy.EntryServerID); err != nil {
		t.Fatalf("agent reconnect with missing policy: %v", err)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateLost {
		t.Fatalf("missing policy on reconnect must mark session lost, got %q", stored.State)
	}
	if !strings.Contains(stored.LastError, "policy not found during reconnect") {
		t.Fatalf("lost reason must include missing policy error, got %q", stored.LastError)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "已失联") {
		t.Fatalf("missing policy on reconnect must send lost notification, got %#v", *h.notifications)
	}
	if (*h.notifications)[0].groupID != policy.NotificationGroupID {
		t.Fatalf("missing policy on reconnect notification group = %d, want %d", (*h.notifications)[0].groupID, policy.NotificationGroupID)
	}
	for _, want := range []string{
		"策略: GitHub Split",
		"模式: system_proxy",
		"本地代理: SOCKS 127.0.0.1:1080",
	} {
		if !strings.Contains((*h.notifications)[0].message, want) {
			t.Fatalf("missing policy on reconnect notification must include %q, got %q", want, (*h.notifications)[0].message)
		}
	}
	var statusAuditCount int64
	if err := DB.Model(&model.AgentVPNAuditLog{}).
		Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionStatus, session.SessionID, false).
		Count(&statusAuditCount).Error; err != nil {
		t.Fatal(err)
	}
	if statusAuditCount != 1 {
		t.Fatalf("missing policy on reconnect must write one lost status audit, got %d", statusAuditCount)
	}
}

func TestVPNOnAgentReconnectAutoRestartsLostSessionWhenPolicyAllows(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "auto restart vpn",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
		AutoRestart:         true,
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}
	session := &model.AgentVPNSession{
		Common:        model.Common{UserID: actor.UserID},
		PolicyID:      policy.ID,
		EntryServerID: policy.EntryServerID,
		ExitServerID:  policy.ExitServerID,
		SessionID:     "vpn_lost_session",
		TokenHash:     hashVPNToken("stale-token"),
		Mode:          policy.Mode,
		RelayMode:     model.VPNRelayModeDashboard,
		State:         model.VPNStateLost,
		EntryState:    model.VPNStateLost,
		ExitState:     model.VPNStateLost,
		EntryStreamID: "old-entry-stream",
		ExitStreamID:  "old-exit-stream",
		LastError:     "entry disconnected",
		StartedAt:     time.Now().Add(-time.Minute),
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	if err := DB.Create(session).Error; err != nil {
		t.Fatal(err)
	}

	if err := h.vpn.OnAgentReconnect(policy.EntryServerID); err != nil {
		t.Fatalf("agent reconnect: %v", err)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateStarting || stored.EntryState != model.VPNStatePending || stored.ExitState != model.VPNStateStarting {
		t.Fatalf("auto restart must stage the existing session, got state=%q entry=%q exit=%q", stored.State, stored.EntryState, stored.ExitState)
	}
	if stored.EntryStreamID == "old-entry-stream" || stored.ExitStreamID == "old-exit-stream" {
		t.Fatalf("auto restart must allocate fresh relay streams, got entry=%q exit=%q", stored.EntryStreamID, stored.ExitStreamID)
	}
	if stored.TokenHash == hashVPNToken("stale-token") {
		t.Fatal("auto restart must rotate the per-session token")
	}
	if stored.LastError != "" {
		t.Fatalf("auto restart must clear stale error, got %q", stored.LastError)
	}
	if len(*h.relayCreates) != 1 || (*h.relayCreates)[0].sessionID != session.SessionID {
		t.Fatalf("auto restart must recreate relay for existing session, got %#v", *h.relayCreates)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.Action != model.VPNActionStart || exitReq.Role != model.VPNRoleExit || exitReq.SessionID != session.SessionID {
		t.Fatalf("auto restart must dispatch start to exit first, got %+v", exitReq)
	}
	if exitReq.Token == "" {
		t.Fatal("auto restart start request must include a fresh token")
	}
	if exitReq.RelayStreamID != stored.ExitStreamID {
		t.Fatalf("auto restart request must use fresh exit relay stream %q, got %q", stored.ExitStreamID, exitReq.RelayStreamID)
	}
	assertNoTask(t, h.entryStream)
}

func TestVPNOnAgentReconnectAutoRestartExitDispatchFailureCleansRuntime(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "auto restart dispatch failure",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
		AutoRestart:         true,
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}
	session := &model.AgentVPNSession{
		Common:        model.Common{UserID: actor.UserID},
		PolicyID:      policy.ID,
		EntryServerID: policy.EntryServerID,
		ExitServerID:  policy.ExitServerID,
		SessionID:     "vpn_lost_restart_dispatch_failure",
		TokenHash:     hashVPNToken("stale-token"),
		Mode:          policy.Mode,
		RelayMode:     model.VPNRelayModeDashboard,
		State:         model.VPNStateLost,
		EntryState:    model.VPNStateLost,
		ExitState:     model.VPNStateLost,
		EntryStreamID: "old-entry-stream",
		ExitStreamID:  "old-exit-stream",
		LastError:     "entry disconnected",
		StartedAt:     time.Now().Add(-time.Minute),
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	if err := DB.Create(session).Error; err != nil {
		t.Fatal(err)
	}
	failingExit := newFailingTaskStream(errors.New("exit stream closed"))
	exit, ok := ServerShared.Get(policy.ExitServerID)
	if !ok {
		t.Fatal("exit server missing from harness")
	}
	exit.SetTaskStream(failingExit)
	*h.notifications = nil

	if err := h.vpn.OnAgentReconnect(policy.EntryServerID); err != nil {
		t.Fatalf("agent reconnect should mark lost instead of returning dispatch failure: %v", err)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateLost {
		t.Fatalf("auto restart dispatch failure must leave session lost, got %q", stored.State)
	}
	if _, err := h.vpn.tokenForSession(&stored); err == nil {
		t.Fatal("auto restart dispatch failure must delete the newly generated session token")
	}
	if len(*h.relayCloses) == 0 || (*h.relayCloses)[len(*h.relayCloses)-1] != session.SessionID {
		t.Fatalf("auto restart dispatch failure must close relay, got %#v", *h.relayCloses)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "已失联") {
		t.Fatalf("auto restart dispatch failure must send lost notification, got %#v", *h.notifications)
	}
	var restartAudit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionRestart, session.SessionID, false).Last(&restartAudit).Error; err != nil {
		t.Fatalf("auto restart dispatch failure must write restart failure audit: %v", err)
	}
	var statusAudit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionStatus, session.SessionID, false).Last(&statusAudit).Error; err != nil {
		t.Fatalf("auto restart dispatch failure must write lost status audit: %v", err)
	}
	if statusAudit.Detail["source"] != "auto restart" {
		t.Fatalf("lost status audit must include auto restart source, detail=%#v", statusAudit.Detail)
	}
}

func TestVPNOnAgentReconnectAutoRestartPreflightFailureDoesNotSendManualRestartFailure(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "auto restart token preflight failure",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
		AutoRestart:         true,
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}
	session := &model.AgentVPNSession{
		Common:        model.Common{UserID: actor.UserID},
		PolicyID:      policy.ID,
		EntryServerID: policy.EntryServerID,
		ExitServerID:  policy.ExitServerID,
		SessionID:     "vpn_lost_restart_preflight_failure",
		TokenHash:     hashVPNToken("stale-token"),
		Mode:          policy.Mode,
		RelayMode:     model.VPNRelayModeDashboard,
		State:         model.VPNStateLost,
		EntryState:    model.VPNStateLost,
		ExitState:     model.VPNStateLost,
		EntryStreamID: "old-entry-stream",
		ExitStreamID:  "old-exit-stream",
		LastError:     "entry disconnected",
		StartedAt:     time.Now().Add(-time.Minute),
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	if err := DB.Create(session).Error; err != nil {
		t.Fatal(err)
	}
	VPNTokenGenerator = func() (string, error) {
		return "", errors.New("auto restart token entropy unavailable")
	}
	*h.notifications = nil

	if err := h.vpn.OnAgentReconnect(policy.EntryServerID); err != nil {
		t.Fatalf("agent reconnect should mark lost instead of returning preflight failure: %v", err)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateLost {
		t.Fatalf("auto restart preflight failure must leave session lost, got %q", stored.State)
	}
	if stored.EntryStreamID != "old-entry-stream" || stored.ExitStreamID != "old-exit-stream" {
		t.Fatalf("auto restart preflight failure must not allocate fresh relay streams, got entry=%q exit=%q", stored.EntryStreamID, stored.ExitStreamID)
	}
	if len(*h.relayCreates) != 0 || len(*h.relayCloses) != 0 {
		t.Fatalf("auto restart preflight failure must not touch relay, creates=%#v closes=%#v", *h.relayCreates, *h.relayCloses)
	}
	if len(*h.notifications) != 1 {
		t.Fatalf("auto restart preflight failure must send only lost notification, got %#v", *h.notifications)
	}
	if !strings.Contains((*h.notifications)[0].message, "[Agent VPN] 已失联") ||
		strings.Contains((*h.notifications)[0].message, "[Agent VPN] 重启失败") ||
		!strings.Contains((*h.notifications)[0].message, "auto restart token entropy unavailable") {
		t.Fatalf("auto restart preflight notification should be lost-only, got %q", (*h.notifications)[0].message)
	}
	for _, want := range []string{
		"策略: auto restart token preflight failure",
		"状态: lost",
		"模式: system_proxy",
		"本地代理: SOCKS 127.0.0.1:1080",
		"错误原因: auto restart token entropy unavailable",
		"时间:",
	} {
		if !strings.Contains((*h.notifications)[0].message, want) {
			t.Fatalf("auto restart preflight lost notification must include %q, got %q", want, (*h.notifications)[0].message)
		}
	}
	var restartAudit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionRestart, session.SessionID, false).Last(&restartAudit).Error; err != nil {
		t.Fatalf("auto restart preflight failure must write restart failure audit: %v", err)
	}
	if restartAudit.Detail["stage"] != "token_generation" {
		t.Fatalf("auto restart preflight restart audit detail mismatch: %#v", restartAudit.Detail)
	}
	var statusAudit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionStatus, session.SessionID, false).Last(&statusAudit).Error; err != nil {
		t.Fatalf("auto restart preflight failure must write lost status audit: %v", err)
	}
	if statusAudit.Detail["source"] != "auto restart" {
		t.Fatalf("lost status audit must include auto restart source, detail=%#v", statusAudit.Detail)
	}
	assertNoTask(t, h.entryStream)
	assertNoTask(t, h.exitStream)
}

func TestVPNOnAgentReconnectAutoRestartLegacyInvalidPolicyDoesNotSendManualRestartFailure(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "auto restart invalid legacy policy",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
		AutoRestart:         true,
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}
	session := &model.AgentVPNSession{
		Common:        model.Common{UserID: actor.UserID},
		PolicyID:      policy.ID,
		EntryServerID: policy.EntryServerID,
		ExitServerID:  policy.ExitServerID,
		SessionID:     "vpn_lost_restart_invalid_policy",
		TokenHash:     hashVPNToken("stale-token"),
		Mode:          policy.Mode,
		RelayMode:     model.VPNRelayModeDashboard,
		State:         model.VPNStateLost,
		EntryState:    model.VPNStateLost,
		ExitState:     model.VPNStateLost,
		EntryStreamID: "old-entry-stream",
		ExitStreamID:  "old-exit-stream",
		LastError:     "entry disconnected",
		StartedAt:     time.Now().Add(-time.Minute),
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	if err := DB.Create(session).Error; err != nil {
		t.Fatal(err)
	}
	if err := DB.Model(&model.AgentVPNPolicy{}).Where("id = ?", policy.ID).Updates(map[string]any{
		"mode": "wireguard",
	}).Error; err != nil {
		t.Fatal(err)
	}
	h.vpn.mu.Lock()
	if cached := h.vpn.sessionPolicies[session.SessionID]; cached != nil {
		cached.Mode = "wireguard"
	}
	h.vpn.mu.Unlock()
	*h.notifications = nil

	if err := h.vpn.OnAgentReconnect(policy.EntryServerID); err != nil {
		t.Fatalf("agent reconnect should mark lost instead of returning invalid policy failure: %v", err)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateLost {
		t.Fatalf("auto restart invalid legacy policy must leave session lost, got %q", stored.State)
	}
	if !strings.Contains(stored.LastError, `unsupported vpn mode "wireguard"`) {
		t.Fatalf("lost state must persist invalid policy reason, got %q", stored.LastError)
	}
	if len(*h.notifications) != 1 {
		t.Fatalf("auto restart invalid policy must send one lost notification, got %#v", *h.notifications)
	}
	if !strings.Contains((*h.notifications)[0].message, "[Agent VPN] 已失联") ||
		strings.Contains((*h.notifications)[0].message, "[Agent VPN] 重启失败") ||
		!strings.Contains((*h.notifications)[0].message, `unsupported vpn mode "wireguard"`) {
		t.Fatalf("auto restart invalid policy must send lost-only notification, got %q", (*h.notifications)[0].message)
	}
	var restartAudit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionRestart, session.SessionID, false).Last(&restartAudit).Error; err != nil {
		t.Fatalf("auto restart invalid policy must write restart failure audit: %v", err)
	}
	if restartAudit.Detail["stage"] != "policy_validation" {
		t.Fatalf("auto restart invalid policy restart audit detail mismatch: %#v", restartAudit.Detail)
	}
	var statusAudit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionStatus, session.SessionID, false).Last(&statusAudit).Error; err != nil {
		t.Fatalf("auto restart invalid policy must write lost status audit: %v", err)
	}
	if statusAudit.Detail["source"] != "auto restart" {
		t.Fatalf("auto restart invalid policy lost audit detail mismatch: %#v", statusAudit.Detail)
	}
	assertNoTask(t, h.entryStream)
	assertNoTask(t, h.exitStream)
}

func TestVPNOnAgentReconnectDoesNotAutoRestartWhenAgentCapabilityDisabled(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "auto restart blocked by capability",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
		AutoRestart:         true,
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}
	session := &model.AgentVPNSession{
		Common:        model.Common{UserID: actor.UserID},
		PolicyID:      policy.ID,
		EntryServerID: policy.EntryServerID,
		ExitServerID:  policy.ExitServerID,
		SessionID:     "vpn_lost_without_capability",
		TokenHash:     hashVPNToken("stale-token"),
		Mode:          policy.Mode,
		RelayMode:     model.VPNRelayModeDashboard,
		State:         model.VPNStateLost,
		EntryState:    model.VPNStateLost,
		ExitState:     model.VPNStateLost,
		EntryStreamID: "old-entry-stream",
		ExitStreamID:  "old-exit-stream",
		LastError:     "entry disconnected",
		StartedAt:     time.Now().Add(-time.Minute),
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	if err := DB.Create(session).Error; err != nil {
		t.Fatal(err)
	}
	h.mustServer(policy.EntryServerID).Host.VPNAllowSystemProxy = false

	if err := h.vpn.OnAgentReconnect(policy.EntryServerID); err != nil {
		t.Fatalf("agent reconnect: %v", err)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateLost {
		t.Fatalf("unsupported capability must keep auto restart session lost, got %q", stored.State)
	}
	if !strings.Contains(stored.LastError, "does not allow Agent VPN system_proxy mode") {
		t.Fatalf("lost session must keep capability error, got %q", stored.LastError)
	}
	if stored.EntryStreamID != "old-entry-stream" || stored.ExitStreamID != "old-exit-stream" {
		t.Fatalf("blocked auto restart must not allocate fresh relay streams, got entry=%q exit=%q", stored.EntryStreamID, stored.ExitStreamID)
	}
	if len(*h.relayCreates) != 0 {
		t.Fatalf("blocked auto restart must not create relay endpoints, got %#v", *h.relayCreates)
	}
	if len(*h.notifications) != 1 {
		t.Fatalf("blocked auto restart must notify once, got %#v", *h.notifications)
	}
	notification := (*h.notifications)[0]
	if notification.groupID != policy.NotificationGroupID {
		t.Fatalf("blocked auto restart notification group = %d, want %d", notification.groupID, policy.NotificationGroupID)
	}
	if !strings.Contains(notification.message, "[Agent VPN] 已失联") ||
		!strings.Contains(notification.message, "does not allow Agent VPN system_proxy mode") ||
		!strings.Contains(notification.message, session.SessionID) {
		t.Fatalf("blocked auto restart notification missing context: %q", notification.message)
	}
	for _, want := range []string{
		"策略: auto restart blocked by capability",
		"入口节点: entry-cn",
		"出口节点: exit-jp",
		"状态: lost",
		"本地代理: SOCKS 127.0.0.1:1080",
		"上传/下载: 0 B / 0 B",
		"连接数: 0",
		"错误原因: entry server 1 does not allow Agent VPN system_proxy mode",
		"角色: entry",
		"时间:",
	} {
		if !strings.Contains(notification.message, want) {
			t.Fatalf("blocked auto restart notification must include %q, got %q", want, notification.message)
		}
	}

	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ?", model.VPNAuditActionStatus, session.SessionID).Last(&audit).Error; err != nil {
		t.Fatalf("blocked auto restart must write failed status audit: %v", err)
	}
	if audit.Success {
		t.Fatalf("blocked auto restart audit must be failure, got success")
	}
	if !strings.Contains(audit.Message, "does not allow Agent VPN system_proxy mode") {
		t.Fatalf("blocked auto restart audit missing reason: %q", audit.Message)
	}
	if !strings.Contains(audit.DetailRaw, "auto restart") {
		t.Fatalf("blocked auto restart audit detail must include source, got %q", audit.DetailRaw)
	}
	assertNoTask(t, h.entryStream)
	assertNoTask(t, h.exitStream)
}

func TestVPNOnAgentReconnectDoesNotAutoRestartExpiredSession(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "expired auto restart vpn",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
		AutoRestart:         true,
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}
	session := &model.AgentVPNSession{
		Common:        model.Common{UserID: actor.UserID},
		PolicyID:      policy.ID,
		EntryServerID: policy.EntryServerID,
		ExitServerID:  policy.ExitServerID,
		SessionID:     "vpn_expired_lost_session",
		TokenHash:     hashVPNToken("stale-token"),
		Mode:          policy.Mode,
		RelayMode:     model.VPNRelayModeDashboard,
		State:         model.VPNStateLost,
		EntryState:    model.VPNStateLost,
		ExitState:     model.VPNStateLost,
		EntryStreamID: "old-entry-stream",
		ExitStreamID:  "old-exit-stream",
		LastError:     "entry disconnected",
		StartedAt:     time.Now().Add(-2 * time.Hour),
		ExpiresAt:     time.Now().Add(-time.Minute),
	}
	if err := DB.Create(session).Error; err != nil {
		t.Fatal(err)
	}

	if err := h.vpn.OnAgentReconnect(policy.EntryServerID); err != nil {
		t.Fatalf("agent reconnect: %v", err)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateStopped || stored.EntryState != model.VPNStateStopped || stored.ExitState != model.VPNStateStopped {
		t.Fatalf("expired session must be stopped instead of auto restarted, got state=%q entry=%q exit=%q", stored.State, stored.EntryState, stored.ExitState)
	}
	if stored.EntryStreamID != "old-entry-stream" || stored.ExitStreamID != "old-exit-stream" {
		t.Fatalf("expired stop must not allocate fresh relay streams, got entry=%q exit=%q", stored.EntryStreamID, stored.ExitStreamID)
	}
	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.Action != model.VPNActionStop || entryReq.Role != model.VPNRoleEntry {
		t.Fatalf("expected entry stop for expired reconnect, got %+v", entryReq)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.Action != model.VPNActionStop || exitReq.Role != model.VPNRoleExit {
		t.Fatalf("expected exit stop for expired reconnect, got %+v", exitReq)
	}
	if len(*h.relayCreates) != 0 {
		t.Fatalf("expired session must not recreate relay, got %#v", *h.relayCreates)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "已过期停止") {
		t.Fatalf("expired reconnect must send stop notification, got %#v", *h.notifications)
	}
}

func TestVPNOnAgentReconnectExpiredSessionCleanupFailurePreservesStoppedStateAndWritesFailureAudit(t *testing.T) {
	h := newVPNHarness(t)
	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	expiredAt := time.Now().Add(-time.Minute)
	if err := DB.Model(&model.AgentVPNSession{}).Where("id = ?", session.ID).Updates(map[string]any{
		"expires_at": expiredAt,
	}).Error; err != nil {
		t.Fatal(err)
	}
	failingEntry := newFailingTaskStream(errors.New("entry expire stop failed"))
	entry, ok := ServerShared.Get(policy.EntryServerID)
	if !ok {
		t.Fatal("entry server missing from harness")
	}
	entry.SetTaskStream(failingEntry)
	*h.notifications = nil

	if err := h.vpn.OnAgentReconnect(policy.EntryServerID); err != nil {
		t.Fatalf("agent reconnect with expired session cleanup failure: %v", err)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateStopped {
		t.Fatalf("expired reconnect cleanup failure must keep session stopped, got %q", stored.State)
	}
	if !strings.Contains(stored.LastError, "entry expire stop failed") {
		t.Fatalf("stopped session must persist expire cleanup failure, got %q", stored.LastError)
	}
	if len(*h.notifications) != 1 || !strings.Contains((*h.notifications)[0].message, "已过期停止") {
		t.Fatalf("expired reconnect cleanup failure must send stop notification, got %#v", *h.notifications)
	}
	var stopAuditCount int64
	if err := DB.Model(&model.AgentVPNAuditLog{}).
		Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionStopSession, session.SessionID, true).
		Count(&stopAuditCount).Error; err != nil {
		t.Fatal(err)
	}
	if stopAuditCount != 1 {
		t.Fatalf("expired reconnect cleanup failure must keep one stop audit, got %d", stopAuditCount)
	}
	var stopAudit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ?", model.VPNAuditActionStopSession, session.SessionID).Last(&stopAudit).Error; err != nil {
		t.Fatal(err)
	}
	if stopAudit.Detail["cleanup_errors"] == "" || !strings.Contains(stopAudit.Detail["cleanup_errors"], "entry expire stop failed") {
		t.Fatalf("expired reconnect cleanup failure must persist cleanup_errors in stop audit, detail=%#v", stopAudit.Detail)
	}
}

func TestStartVPNLifecycleJobsRecoversActiveSessionsAndSchedulesExpiry(t *testing.T) {
	h := newVPNHarness(t)
	originalCronShared := CronShared
	CronShared = &CronClass{Cron: cron.New(cron.WithSeconds())}
	t.Cleanup(func() { CronShared = originalCronShared })

	actor := VPNActor{UserID: 100, Role: model.RoleMember}
	policy := createTestVPNPolicy(t, h, actor)
	session := startAndRunTestVPNSession(t, h, actor, policy)
	h.vpn = NewVPNClass()
	VPNShared = h.vpn

	if err := StartVPNLifecycleJobs(); err != nil {
		t.Fatalf("start VPN lifecycle jobs: %v", err)
	}

	var stored model.AgentVPNSession
	if err := DB.First(&stored, session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.State != model.VPNStateUnknown {
		t.Fatalf("lifecycle startup must recover active sessions as unknown, got %q", stored.State)
	}
	_, entryReq := readVPNTask(t, h.entryStream)
	if entryReq.Action != model.VPNActionStatus || entryReq.Role != model.VPNRoleEntry {
		t.Fatalf("lifecycle startup must query entry status, got %+v", entryReq)
	}
	_, exitReq := readVPNTask(t, h.exitStream)
	if exitReq.Action != model.VPNActionStatus || exitReq.Role != model.VPNRoleExit {
		t.Fatalf("lifecycle startup must query exit status, got %+v", exitReq)
	}
	if entries := CronShared.Entries(); len(entries) != 1 {
		t.Fatalf("lifecycle startup must schedule one expiry job, got %d", len(entries))
	}
}

func createTestVPNPolicy(t *testing.T, h *vpnHarness, actor VPNActor) *model.AgentVPNPolicy {
	t.Helper()
	policy, err := h.vpn.SavePolicy(actor, model.AgentVPNPolicyForm{
		Name:                "GitHub Split",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeDomain,
		Domains:             []string{"github.com", "api.github.com"},
		DirectCIDRs:         []string{"127.0.0.0/8"},
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		MaxConnections:      128,
		NotificationGroupID: 9,
	})
	if err != nil {
		t.Fatalf("save policy: %v", err)
	}
	return policy
}

func assertVPNCoreSpec(t *testing.T, spec model.VPNCoreSpec) {
	t.Helper()
	if spec.Name != "sing-box" {
		t.Fatalf("core name = %q, want sing-box", spec.Name)
	}
	if spec.Version != "1.12.0" {
		t.Fatalf("core version = %q, want 1.12.0", spec.Version)
	}
	if spec.DownloadURL != "https://download.example.com/sing-box.exe" {
		t.Fatalf("core download URL = %q, want configured URL", spec.DownloadURL)
	}
	if spec.SHA256 != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("core sha256 = %q, want configured hash", spec.SHA256)
	}
}

func assertVPNBypassContains(t *testing.T, got []string, wants ...string) {
	t.Helper()
	seen := make(map[string]struct{}, len(got))
	for _, value := range got {
		seen[value] = struct{}{}
	}
	for _, want := range wants {
		if _, ok := seen[want]; !ok {
			t.Fatalf("dashboard bypass = %#v, want it to contain %q", got, want)
		}
	}
}

func assertVPNBypassNotContains(t *testing.T, got []string, unwanted ...string) {
	t.Helper()
	seen := make(map[string]struct{}, len(got))
	for _, value := range got {
		seen[value] = struct{}{}
	}
	for _, value := range unwanted {
		if _, ok := seen[value]; ok {
			t.Fatalf("dashboard bypass = %#v, must not contain sensitive default %q", got, value)
		}
	}
}

func startAndRunTestVPNSession(t *testing.T, h *vpnHarness, actor VPNActor, policy *model.AgentVPNPolicy) *model.AgentVPNSession {
	t.Helper()
	session, err := h.vpn.StartSession(actor, policy.ID)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	prepareAndDispatchExitStartForTest(t, h, session, policy)
	session, err = h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	})
	if err != nil {
		t.Fatalf("handle exit running: %v", err)
	}
	readVPNTask(t, h.entryStream)
	session, err = h.vpn.HandleControlResult(policy.EntryServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleEntry,
		State:     model.VPNStateRunning,
	})
	if err != nil {
		t.Fatalf("handle entry running: %v", err)
	}
	return session
}

func prepareAndDispatchExitStartForTest(t *testing.T, h *vpnHarness, session *model.AgentVPNSession, policy *model.AgentVPNPolicy) model.VPNControlRequest {
	t.Helper()
	_, exitPrepareReq := readVPNTask(t, h.exitStream)
	if exitPrepareReq.Action != model.VPNActionPrepare || exitPrepareReq.Role != model.VPNRoleExit {
		t.Fatalf("expected prepare exit request, got action=%q role=%q", exitPrepareReq.Action, exitPrepareReq.Role)
	}
	_, entryPrepareReq := readVPNTask(t, h.entryStream)
	if entryPrepareReq.Action != model.VPNActionPrepare || entryPrepareReq.Role != model.VPNRoleEntry {
		t.Fatalf("expected prepare entry request, got action=%q role=%q", entryPrepareReq.Action, entryPrepareReq.Role)
	}
	if len(*h.relayCreates) != 0 {
		t.Fatalf("relay must not be created before both agents prepare, got %#v", *h.relayCreates)
	}
	return dispatchExitStartAfterPreparedForTest(t, h, session, policy)
}

func dispatchExitStartAfterPreparedForTest(t *testing.T, h *vpnHarness, session *model.AgentVPNSession, policy *model.AgentVPNPolicy) model.VPNControlRequest {
	t.Helper()
	prepared, err := h.vpn.HandleControlResult(policy.ExitServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionPrepare,
		Role:      model.VPNRoleExit,
		State:     model.VPNStatePrepared,
		Logs:      []string{"[core] prepare=downloaded path=/tmp/sing-box temporary=true"},
	})
	if err != nil {
		t.Fatalf("handle exit prepared: %v", err)
	}
	if prepared.ExitState != model.VPNStatePrepared || prepared.EntryState != model.VPNStateStarting {
		t.Fatalf("exit prepared must wait for entry prepare, got entry=%q exit=%q", prepared.EntryState, prepared.ExitState)
	}
	assertNoTask(t, h.exitStream)
	prepared, err = h.vpn.HandleControlResult(policy.EntryServerID, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionPrepare,
		Role:      model.VPNRoleEntry,
		State:     model.VPNStatePrepared,
		Logs:      []string{"[core] prepare=reused path=/tmp/sing-box temporary=true"},
	})
	if err != nil {
		t.Fatalf("handle entry prepared: %v", err)
	}
	if prepared.ExitState != model.VPNStateStarting || prepared.EntryState != model.VPNStatePending {
		t.Fatalf("both prepared must dispatch exit start, got entry=%q exit=%q", prepared.EntryState, prepared.ExitState)
	}
	_, exitStartReq := readVPNTask(t, h.exitStream)
	if exitStartReq.Action != model.VPNActionStart || exitStartReq.Role != model.VPNRoleExit {
		t.Fatalf("expected start exit request, got action=%q role=%q", exitStartReq.Action, exitStartReq.Role)
	}
	return exitStartReq
}

func readVPNTask(t *testing.T, stream *capturedTaskStream) (*pb.Task, model.VPNControlRequest) {
	t.Helper()
	select {
	case task := <-stream.tasks:
		if task.GetType() != model.TaskTypeVPNControl {
			t.Fatalf("expected VPN control task type %d, got %d", model.TaskTypeVPNControl, task.GetType())
		}
		var req model.VPNControlRequest
		if err := json.Unmarshal([]byte(task.GetData()), &req); err != nil {
			t.Fatalf("decode VPN control request: %v\npayload: %s", err, task.GetData())
		}
		return task, req
	case <-time.After(time.Second):
		t.Fatal("expected VPN control task to be sent")
		return nil, model.VPNControlRequest{}
	}
}
