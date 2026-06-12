package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/i18n"
	pb "github.com/nezhahq/nezha/proto"
	"github.com/nezhahq/nezha/service/singleton"
)

func setupVPNControllerFixture(t *testing.T) *gin.Context {
	t.Helper()

	originalDB := singleton.DB
	originalServerShared := singleton.ServerShared
	originalVPNShared := singleton.VPNShared
	originalConf := singleton.Conf
	originalLocalizer := singleton.Localizer
	originalTokenGenerator := singleton.VPNTokenGenerator
	originalIDGenerator := singleton.VPNIDGenerator
	originalNotificationSender := singleton.VPNNotificationSender

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&model.Server{},
		&model.NotificationGroup{},
		&model.AgentVPNPolicy{},
		&model.AgentVPNSession{},
		&model.AgentVPNAuditLog{},
	))
	require.NoError(t, db.Create(&model.Server{
		Common: model.Common{ID: 1, UserID: 200},
		Name:   "entry",
		UUID:   "entry",
	}).Error)
	require.NoError(t, db.Create(&model.Server{
		Common: model.Common{ID: 2, UserID: 200},
		Name:   "exit",
		UUID:   "exit",
	}).Error)
	require.NoError(t, db.Create(&model.NotificationGroup{
		Common: model.Common{ID: 9, UserID: 200},
		Name:   "vpn-notify",
	}).Error)
	require.NoError(t, db.Create(&model.NotificationGroup{
		Common: model.Common{ID: 10, UserID: 300},
		Name:   "foreign-notify",
	}).Error)

	singleton.DB = db
	singleton.Conf = &singleton.ConfigClass{Config: &model.Config{}}
	singleton.Localizer = i18n.NewLocalizer("en_US", "nezha", "translations", i18n.Translations)
	singleton.ServerShared = singleton.NewServerClass()
	setControllerVPNServerCapability(t, 1)
	setControllerVPNServerCapability(t, 2)
	singleton.VPNShared = singleton.NewVPNClass()
	singleton.VPNTokenGenerator = func() (string, error) { return "controller-token", nil }
	ids := []string{"controller_session", "controller_entry_stream", "controller_exit_stream"}
	idIndex := 0
	singleton.VPNIDGenerator = func(prefix string) (string, error) {
		id := ids[idIndex%len(ids)]
		idIndex++
		return id, nil
	}
	singleton.VPNNotificationSender = func(uint64, string, string) {}

	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	setAuthUser(ctx, 200, model.RoleMember)

	t.Cleanup(func() {
		singleton.DB = originalDB
		singleton.ServerShared = originalServerShared
		singleton.VPNShared = originalVPNShared
		singleton.Conf = originalConf
		singleton.Localizer = originalLocalizer
		singleton.VPNTokenGenerator = originalTokenGenerator
		singleton.VPNIDGenerator = originalIDGenerator
		singleton.VPNNotificationSender = originalNotificationSender
	})

	return ctx
}

func setControllerVPNServerCapability(t *testing.T, serverID uint64) {
	t.Helper()
	server, ok := singleton.ServerShared.Get(serverID)
	require.True(t, ok)
	server.Host = &model.Host{
		VPNEnabled:          true,
		VPNAllowSystemProxy: true,
		VPNAllowTun:         true,
		VPNCoreVersion:      "1.12.0",
	}
}

func TestCreateVPNPolicyRejectsForeignNotificationGroup(t *testing.T) {
	ctx := setupVPNControllerFixture(t)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/vpn/policy", strings.NewReader(`{
		"name":"bad notify",
		"entry_server_id":1,
		"exit_server_id":2,
		"mode":"system_proxy",
		"rule_mode":"global",
		"listen_socks":"127.0.0.1:1080",
		"notification_group_id":10
	}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	_, err := createVPNPolicy(ctx)

	require.Error(t, err)
	require.Contains(t, err.Error(), "permission denied")
}

func TestUpdateVPNPolicyRejectsForeignNotificationGroup(t *testing.T) {
	ctx := setupVPNControllerFixture(t)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNPolicy{
		Common:              model.Common{ID: 77, UserID: 200},
		Name:                "owned policy",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	}).Error)

	ctx.Params = gin.Params{{Key: "id", Value: "77"}}
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/vpn/policy/77", strings.NewReader(`{
		"name":"bad notify update",
		"entry_server_id":1,
		"exit_server_id":2,
		"mode":"system_proxy",
		"rule_mode":"global",
		"listen_socks":"127.0.0.1:1080",
		"expires_seconds":3600,
		"notification_group_id":10
	}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	_, err := updateVPNPolicy(ctx)

	require.Error(t, err)
	require.Contains(t, err.Error(), "permission denied")
}

func TestVPNListEndpointsFilterForeignRowsForMember(t *testing.T) {
	ctx := setupVPNControllerFixture(t)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNPolicy{
		Common:              model.Common{ID: 77, UserID: 200},
		Name:                "owned policy",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	}).Error)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNPolicy{
		Common:              model.Common{ID: 88, UserID: 300},
		Name:                "foreign policy",
		EntryServerID:       3,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1081",
		ExpiresSeconds:      3600,
		NotificationGroupID: 10,
	}).Error)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNSession{
		Common:        model.Common{UserID: 200},
		PolicyID:      77,
		EntryServerID: 1,
		ExitServerID:  2,
		SessionID:     "owned_session",
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		State:         model.VPNStateRunning,
		StartedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
	}).Error)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNSession{
		Common:        model.Common{UserID: 300},
		PolicyID:      88,
		EntryServerID: 3,
		ExitServerID:  2,
		SessionID:     "foreign_session",
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		State:         model.VPNStateRunning,
		StartedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
	}).Error)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNAuditLog{
		Common:        model.Common{UserID: 200},
		SessionID:     "owned_session",
		UserID:        200,
		Action:        model.VPNAuditActionStartSession,
		EntryServerID: 1,
		ExitServerID:  2,
		Success:       true,
		Message:       "owned audit",
	}).Error)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNAuditLog{
		Common:        model.Common{UserID: 300},
		SessionID:     "foreign_session",
		UserID:        300,
		Action:        model.VPNAuditActionStartSession,
		EntryServerID: 3,
		ExitServerID:  2,
		Success:       true,
		Message:       "foreign audit",
	}).Error)

	ctx.Request = httptest.NewRequest(http.MethodGet, "/vpn/policy", nil)
	policies, err := listVPNPolicy(ctx)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.Equal(t, "owned policy", policies[0].Name)

	ctx.Request = httptest.NewRequest(http.MethodGet, "/vpn/session", nil)
	sessions, err := listVPNSession(ctx)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	require.Equal(t, "owned_session", sessions[0].SessionID)

	ctx.Request = httptest.NewRequest(http.MethodGet, "/vpn/audit", nil)
	audits, err := listVPNAudit(ctx)
	require.NoError(t, err)
	require.Len(t, audits, 1)
	require.Equal(t, "owned_session", audits[0].SessionID)
}

func TestVPNListSessionFiltersRowsWhenServerOwnershipChanged(t *testing.T) {
	ctx := setupVPNControllerFixture(t)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNSession{
		Common:        model.Common{UserID: 200},
		PolicyID:      77,
		EntryServerID: 1,
		ExitServerID:  2,
		SessionID:     "still_owned_session",
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		State:         model.VPNStateRunning,
		StartedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
	}).Error)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNSession{
		Common:        model.Common{UserID: 200},
		PolicyID:      88,
		EntryServerID: 1,
		ExitServerID:  2,
		SessionID:     "transferred_server_session",
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		State:         model.VPNStateRunning,
		StartedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
	}).Error)
	entry, ok := singleton.ServerShared.Get(1)
	require.True(t, ok)
	entry.SetUserID(300)

	ctx.Request = httptest.NewRequest(http.MethodGet, "/vpn/session", nil)
	sessions, err := listVPNSession(ctx)

	require.NoError(t, err)
	require.Empty(t, sessions, "member must not see VPN sessions whose entry or exit server is no longer permitted")
}

func TestVPNListPolicyFiltersRowsWhenServerOwnershipChanged(t *testing.T) {
	ctx := setupVPNControllerFixture(t)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNPolicy{
		Common:              model.Common{ID: 77, UserID: 200},
		Name:                "transferred server policy",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	}).Error)
	entry, ok := singleton.ServerShared.Get(1)
	require.True(t, ok)
	entry.SetUserID(300)

	ctx.Request = httptest.NewRequest(http.MethodGet, "/vpn/policy", nil)
	policies, err := listVPNPolicy(ctx)

	require.NoError(t, err)
	require.Empty(t, policies, "member must not see VPN policies whose entry or exit server is no longer permitted")
}

func TestVPNListAuditFiltersRowsWhenServerOwnershipChanged(t *testing.T) {
	ctx := setupVPNControllerFixture(t)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNAuditLog{
		Common:        model.Common{UserID: 200},
		SessionID:     "transferred_server_session",
		UserID:        200,
		Action:        model.VPNAuditActionStartSession,
		EntryServerID: 1,
		ExitServerID:  2,
		Success:       true,
		Message:       "session started",
	}).Error)
	entry, ok := singleton.ServerShared.Get(1)
	require.True(t, ok)
	entry.SetUserID(300)

	ctx.Request = httptest.NewRequest(http.MethodGet, "/vpn/audit", nil)
	audits, err := listVPNAudit(ctx)

	require.NoError(t, err)
	require.Empty(t, audits, "member must not see VPN audit rows whose entry or exit server is no longer permitted")
}

func TestCreateListAndStartVPNPolicyFromController(t *testing.T) {
	ctx := setupVPNControllerFixture(t)
	attachControllerVPNTaskStream(t, 1)
	attachControllerVPNTaskStream(t, 2)

	ctx.Request = httptest.NewRequest(http.MethodPost, "/vpn/policy", strings.NewReader(`{
		"name":"github split",
		"entry_server_id":1,
		"exit_server_id":2,
		"mode":"system_proxy",
		"rule_mode":"domain",
		"domains":["github.com"],
		"listen_socks":"127.0.0.1:1080",
		"expires_seconds":3600,
		"notification_group_id":9
	}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	policyID, err := createVPNPolicy(ctx)
	require.NoError(t, err)
	require.NotZero(t, policyID)

	ctx.Request = httptest.NewRequest(http.MethodGet, "/vpn/policy", nil)
	policies, err := listVPNPolicy(ctx)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.Equal(t, "github split", policies[0].Name)

	ctx.Request = httptest.NewRequest(http.MethodPost, "/vpn/session/start", strings.NewReader(`{"policy_id":`+strconv.FormatUint(policyID, 10)+`}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	session, err := startVPNSession(ctx)
	require.NoError(t, err)
	require.Equal(t, "controller_session", session.SessionID)
	require.Equal(t, model.VPNStateStarting, session.State)

	ctx.Request = httptest.NewRequest(http.MethodGet, "/vpn/session", nil)
	sessions, err := listVPNSession(ctx)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	require.Equal(t, session.SessionID, sessions[0].SessionID)
}

func TestCreateVPNPolicyPersistsTunHealthFieldsFromController(t *testing.T) {
	ctx := setupVPNControllerFixture(t)

	ctx.Request = httptest.NewRequest(http.MethodPost, "/vpn/policy", strings.NewReader(`{
		"name":"tun health",
		"entry_server_id":1,
		"exit_server_id":2,
		"mode":"tun_split",
		"rule_mode":"domain",
		"domains":["example.com"],
		"tun_name":"nezha-vpn",
		"expires_seconds":3600,
		"notification_group_id":9,
		"tun_health_url":"https://connectivity.example.com/generate_204",
		"tun_health_timeout_seconds":7
	}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	policyID, err := createVPNPolicy(ctx)
	require.NoError(t, err)
	require.NotZero(t, policyID)

	ctx.Request = httptest.NewRequest(http.MethodGet, "/vpn/policy", nil)
	policies, err := listVPNPolicy(ctx)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.Equal(t, "https://connectivity.example.com/generate_204", policies[0].TunHealthURL)
	require.Equal(t, uint32(7), policies[0].TunHealthTimeoutSeconds)
}

func TestDeleteVPNPolicyRejectsActiveSessionPolicy(t *testing.T) {
	ctx := setupVPNControllerFixture(t)

	require.NoError(t, singleton.DB.Create(&model.AgentVPNPolicy{
		Common:        model.Common{ID: 77, UserID: 200},
		Name:          "active policy",
		EntryServerID: 1,
		ExitServerID:  2,
		Mode:          model.VPNModeSystemProxy,
		RuleMode:      model.VPNRuleModeGlobal,
		ListenSOCKS:   "127.0.0.1:1080",
	}).Error)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNSession{
		Common:        model.Common{UserID: 200},
		PolicyID:      77,
		EntryServerID: 1,
		ExitServerID:  2,
		SessionID:     "active_session",
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		State:         model.VPNStateRunning,
		EntryState:    model.VPNStateRunning,
		ExitState:     model.VPNStateRunning,
		StartedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
	}).Error)

	ctx.Request = httptest.NewRequest(http.MethodPost, "/batch-delete/vpn/policy", strings.NewReader(`[77]`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	_, err := batchDeleteVPNPolicy(ctx)

	require.Error(t, err)
	require.Contains(t, err.Error(), "active session")
	var count int64
	require.NoError(t, singleton.DB.Model(&model.AgentVPNPolicy{}).Where("id = ?", 77).Count(&count).Error)
	require.Equal(t, int64(1), count)
}

func TestDeleteVPNPolicyWritesAuditWithPolicySnapshot(t *testing.T) {
	ctx := setupVPNControllerFixture(t)

	require.NoError(t, singleton.DB.Create(&model.AgentVPNPolicy{
		Common:              model.Common{ID: 77, UserID: 200},
		Name:                "delete policy",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeDomain,
		Domains:             []string{"example.com"},
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	}).Error)

	ctx.Request = httptest.NewRequest(http.MethodPost, "/batch-delete/vpn/policy", strings.NewReader(`[77]`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	_, err := batchDeleteVPNPolicy(ctx)

	require.NoError(t, err)
	var policyCount int64
	require.NoError(t, singleton.DB.Model(&model.AgentVPNPolicy{}).Where("id = ?", 77).Count(&policyCount).Error)
	require.Zero(t, policyCount)

	var audits []model.AgentVPNAuditLog
	require.NoError(t, singleton.DB.Order("id ASC").Find(&audits).Error)
	require.Len(t, audits, 1)
	require.Equal(t, model.VPNAuditActionDeletePolicy, audits[0].Action)
	require.True(t, audits[0].Success)
	require.Equal(t, uint64(200), audits[0].UserID)
	require.Equal(t, uint64(1), audits[0].EntryServerID)
	require.Equal(t, uint64(2), audits[0].ExitServerID)
	require.Equal(t, "policy deleted", audits[0].Message)
	require.Equal(t, "77", audits[0].Detail["policy_id"])
	require.Equal(t, "delete policy", audits[0].Detail["policy_name"])
	require.Equal(t, model.VPNRuleModeDomain, audits[0].Detail["rule_mode"])
	require.Equal(t, "example.com", audits[0].Detail["domains"])
}

func TestDeleteVPNPolicyRejectsPolicyWhenServerOwnershipChanged(t *testing.T) {
	ctx := setupVPNControllerFixture(t)

	require.NoError(t, singleton.DB.Create(&model.AgentVPNPolicy{
		Common:              model.Common{ID: 77, UserID: 200},
		Name:                "transferred server policy",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	}).Error)
	entry, ok := singleton.ServerShared.Get(1)
	require.True(t, ok)
	entry.SetUserID(300)

	ctx.Request = httptest.NewRequest(http.MethodPost, "/batch-delete/vpn/policy", strings.NewReader(`[77]`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	_, err := batchDeleteVPNPolicy(ctx)

	require.Error(t, err)
	require.Contains(t, err.Error(), "permission denied")
	var policyCount int64
	require.NoError(t, singleton.DB.Model(&model.AgentVPNPolicy{}).Where("id = ?", 77).Count(&policyCount).Error)
	require.Equal(t, int64(1), policyCount)
	var auditCount int64
	require.NoError(t, singleton.DB.Model(&model.AgentVPNAuditLog{}).Count(&auditCount).Error)
	require.Zero(t, auditCount)
}

func TestListVPNAuditAppliesQueryFilters(t *testing.T) {
	ctx := setupVPNControllerFixture(t)
	base := time.Date(2026, 6, 8, 13, 0, 0, 0, time.UTC)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNAuditLog{
		Common:        model.Common{UserID: 200, CreatedAt: base.Add(-time.Hour)},
		SessionID:     "controller_session_1",
		UserID:        200,
		Action:        model.VPNAuditActionStartSession,
		EntryServerID: 1,
		ExitServerID:  2,
		Success:       true,
		Message:       "session started",
	}).Error)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNAuditLog{
		Common:        model.Common{UserID: 200, CreatedAt: base.Add(30 * time.Minute)},
		SessionID:     "controller_session_2",
		UserID:        200,
		Action:        model.VPNAuditActionStopSession,
		EntryServerID: 2,
		ExitServerID:  1,
		Success:       false,
		Message:       "session failed",
	}).Error)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNAuditLog{
		Common:        model.Common{UserID: 300, CreatedAt: base.Add(45 * time.Minute)},
		SessionID:     "controller_session_3",
		UserID:        300,
		Action:        model.VPNAuditActionStopSession,
		EntryServerID: 2,
		ExitServerID:  1,
		Success:       false,
		Message:       "foreign session failed",
	}).Error)

	ctx.Request = httptest.NewRequest(http.MethodGet, "/vpn/audit?action=stop&result=failure&user=200&entry=2&exit=1&from=2026-06-08T13:15:00Z&to=2026-06-08T13:45:00Z", nil)
	audits, err := listVPNAudit(ctx)

	require.NoError(t, err)
	require.Len(t, audits, 1)
	require.Equal(t, "controller_session_2", audits[0].SessionID)
}

func TestStatusVPNSessionDispatchesAgentStatusRequests(t *testing.T) {
	ctx := setupVPNControllerFixture(t)
	entryStream := attachControllerVPNTaskStream(t, 1)
	exitStream := attachControllerVPNTaskStream(t, 2)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNPolicy{
		Common:         model.Common{ID: 77, UserID: 200},
		Name:           "status policy",
		EntryServerID:  1,
		ExitServerID:   2,
		Mode:           model.VPNModeSystemProxy,
		RuleMode:       model.VPNRuleModeGlobal,
		ListenSOCKS:    "127.0.0.1:1080",
		ExpiresSeconds: 3600,
	}).Error)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNSession{
		Common:        model.Common{UserID: 200},
		PolicyID:      77,
		EntryServerID: 1,
		ExitServerID:  2,
		SessionID:     "controller_session",
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		State:         model.VPNStateRunning,
		EntryState:    model.VPNStateRunning,
		ExitState:     model.VPNStateRunning,
		EntryStreamID: "controller_entry_stream",
		ExitStreamID:  "controller_exit_stream",
		StartedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
	}).Error)

	ctx.Params = gin.Params{{Key: "id", Value: "controller_session"}}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/vpn/session/controller_session/status", nil)
	session, err := statusVPNSession(ctx)

	require.NoError(t, err)
	require.Equal(t, "controller_session", session.SessionID)
	requireControllerVPNStatusTask(t, entryStream, model.VPNRoleEntry, "controller_session")
	requireControllerVPNStatusTask(t, exitStream, model.VPNRoleExit, "controller_session")
}

func TestStatusVPNSessionRejectsSessionWithoutPermission(t *testing.T) {
	ctx := setupVPNControllerFixture(t)
	entryStream := attachControllerVPNTaskStream(t, 1)
	exitStream := attachControllerVPNTaskStream(t, 2)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNPolicy{
		Common:         model.Common{ID: 88, UserID: 300},
		Name:           "foreign policy",
		EntryServerID:  1,
		ExitServerID:   2,
		Mode:           model.VPNModeSystemProxy,
		RuleMode:       model.VPNRuleModeGlobal,
		ListenSOCKS:    "127.0.0.1:1080",
		ExpiresSeconds: 3600,
	}).Error)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNSession{
		Common:        model.Common{UserID: 300},
		PolicyID:      88,
		EntryServerID: 1,
		ExitServerID:  2,
		SessionID:     "foreign_session",
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		State:         model.VPNStateRunning,
		EntryState:    model.VPNStateRunning,
		ExitState:     model.VPNStateRunning,
		StartedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
	}).Error)

	ctx.Params = gin.Params{{Key: "id", Value: "foreign_session"}}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/vpn/session/foreign_session/status", nil)
	_, err := statusVPNSession(ctx)

	require.Error(t, err)
	require.Contains(t, err.Error(), "permission denied")
	entryStream.mu.Lock()
	require.Empty(t, entryStream.tasks, "foreign status request must not be dispatched to entry agent")
	entryStream.mu.Unlock()
	exitStream.mu.Lock()
	require.Empty(t, exitStream.tasks, "foreign status request must not be dispatched to exit agent")
	exitStream.mu.Unlock()
}

func TestStatusVPNSessionRejectsLegacyPolicyWithInvalidModeBeforeDispatch(t *testing.T) {
	ctx := setupVPNControllerFixture(t)
	entryStream := attachControllerVPNTaskStream(t, 1)
	exitStream := attachControllerVPNTaskStream(t, 2)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNPolicy{
		Common:         model.Common{ID: 89, UserID: 200},
		Name:           "legacy invalid mode",
		EntryServerID:  1,
		ExitServerID:   2,
		Mode:           "wireguard",
		RuleMode:       model.VPNRuleModeGlobal,
		ListenSOCKS:    "127.0.0.1:1080",
		ExpiresSeconds: 3600,
	}).Error)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNSession{
		Common:        model.Common{UserID: 200},
		PolicyID:      89,
		EntryServerID: 1,
		ExitServerID:  2,
		SessionID:     "legacy_invalid_mode_session",
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		State:         model.VPNStateRunning,
		EntryState:    model.VPNStateRunning,
		ExitState:     model.VPNStateRunning,
		StartedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
	}).Error)

	ctx.Params = gin.Params{{Key: "id", Value: "legacy_invalid_mode_session"}}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/vpn/session/legacy_invalid_mode_session/status", nil)
	_, err := statusVPNSession(ctx)

	require.Error(t, err)
	require.Contains(t, err.Error(), `unsupported vpn mode "wireguard"`)
	entryStream.mu.Lock()
	require.Empty(t, entryStream.tasks, "invalid mode status request must not be dispatched to entry agent")
	entryStream.mu.Unlock()
	exitStream.mu.Lock()
	require.Empty(t, exitStream.tasks, "invalid mode status request must not be dispatched to exit agent")
	exitStream.mu.Unlock()
}

func TestVPNSessionStreamSendsCurrentSessionSnapshot(t *testing.T) {
	ctx := setupVPNControllerFixture(t)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNSession{
		Common:        model.Common{UserID: 200},
		PolicyID:      1,
		EntryServerID: 1,
		ExitServerID:  2,
		SessionID:     "controller_session",
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		State:         model.VPNStateRunning,
		EntryState:    model.VPNStateRunning,
		ExitState:     model.VPNStateRunning,
		UploadBytes:   123,
		DownloadBytes: 456,
		StartedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
	}).Error)

	InitUpgrader()
	r := gin.New()
	r.GET("/api/v1/ws/vpn/session/:id", func(c *gin.Context) {
		setAuthUser(c, 200, model.RoleMember)
		c.Params = append(c.Params, gin.Param{Key: "id", Value: "controller_session"})
		_, _ = vpnSessionStream(c)
	})
	server := httptest.NewServer(r)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/ws/vpn/session/controller_session"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	var frame struct {
		Session model.AgentVPNSession `json:"session"`
		Logs    []string              `json:"logs"`
	}
	require.NoError(t, conn.ReadJSON(&frame))
	require.Equal(t, "controller_session", frame.Session.SessionID)
	require.Equal(t, model.VPNStateRunning, frame.Session.State)
	require.Equal(t, uint64(123), frame.Session.UploadBytes)
	require.Equal(t, uint64(456), frame.Session.DownloadBytes)
	_ = ctx
}

func TestVPNSessionStreamRejectsSessionWithoutPermission(t *testing.T) {
	setupVPNControllerFixture(t)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNSession{
		Common:        model.Common{UserID: 300},
		PolicyID:      1,
		EntryServerID: 3,
		ExitServerID:  2,
		SessionID:     "foreign_session",
		State:         model.VPNStateRunning,
		StartedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
	}).Error)

	InitUpgrader()
	r := gin.New()
	r.GET("/api/v1/ws/vpn/session/:id", func(c *gin.Context) {
		setAuthUser(c, 200, model.RoleMember)
		c.Params = append(c.Params, gin.Param{Key: "id", Value: "foreign_session"})
		_, _ = vpnSessionStream(c)
	})
	server := httptest.NewServer(r)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/ws/vpn/session/foreign_session"
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if conn != nil {
		_ = conn.Close()
	}
	require.Error(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestVPNSessionStreamRejectsSessionWhenServerOwnershipChanged(t *testing.T) {
	setupVPNControllerFixture(t)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNSession{
		Common:        model.Common{UserID: 200},
		PolicyID:      1,
		EntryServerID: 1,
		ExitServerID:  2,
		SessionID:     "transferred_server_session",
		State:         model.VPNStateRunning,
		StartedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
	}).Error)
	entry, ok := singleton.ServerShared.Get(1)
	require.True(t, ok)
	entry.SetUserID(300)

	InitUpgrader()
	r := gin.New()
	r.GET("/api/v1/ws/vpn/session/:id", func(c *gin.Context) {
		setAuthUser(c, 200, model.RoleMember)
		c.Params = append(c.Params, gin.Param{Key: "id", Value: "transferred_server_session"})
		_, _ = vpnSessionStream(c)
	})
	server := httptest.NewServer(r)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/ws/vpn/session/transferred_server_session"
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if conn != nil {
		_ = conn.Close()
	}
	require.Error(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestVPNSessionStreamIncludesLogLinesFromAgentStatus(t *testing.T) {
	setupVPNControllerFixture(t)
	require.NoError(t, singleton.DB.Create(&model.AgentVPNSession{
		Common:        model.Common{UserID: 200},
		PolicyID:      1,
		EntryServerID: 1,
		ExitServerID:  2,
		SessionID:     "controller_session",
		State:         model.VPNStateFailed,
		LastError:     "sidecar crashed",
		StartedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
	}).Error)

	InitUpgrader()
	r := gin.New()
	r.GET("/api/v1/ws/vpn/session/:id", func(c *gin.Context) {
		setAuthUser(c, 200, model.RoleMember)
		c.Params = append(c.Params, gin.Param{Key: "id", Value: "controller_session"})
		_, _ = vpnSessionStream(c)
	})
	server := httptest.NewServer(r)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/ws/vpn/session/controller_session"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	var frame struct {
		Session model.AgentVPNSession `json:"session"`
		Logs    []string              `json:"logs"`
	}
	require.NoError(t, conn.ReadJSON(&frame))
	require.Equal(t, "controller_session", frame.Session.SessionID)
	require.Contains(t, frame.Logs, "sidecar crashed")
}

func TestVPNSessionStreamIncludesBufferedAgentSidecarLogs(t *testing.T) {
	setupVPNControllerFixture(t)
	attachControllerVPNTaskStream(t, 1)
	attachControllerVPNTaskStream(t, 2)
	policy, err := singleton.VPNShared.SavePolicy(singleton.VPNActor{UserID: 200, Role: model.RoleMember}, model.AgentVPNPolicyForm{
		Name:                "controller logs",
		EntryServerID:       1,
		ExitServerID:        2,
		Mode:                model.VPNModeSystemProxy,
		RuleMode:            model.VPNRuleModeGlobal,
		ListenSOCKS:         "127.0.0.1:1080",
		ExpiresSeconds:      3600,
		NotificationGroupID: 9,
	})
	require.NoError(t, err)
	session, err := singleton.VPNShared.StartSession(singleton.VPNActor{UserID: 200, Role: model.RoleMember}, policy.ID)
	require.NoError(t, err)
	_, err = singleton.VPNShared.HandleControlResult(1, model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionLogs,
		Role:      model.VPNRoleEntry,
		State:     model.VPNStateRunning,
		Logs:      []string{"entry accepted connection", "entry proxy connected"},
	})
	require.NoError(t, err)

	InitUpgrader()
	r := gin.New()
	r.GET("/api/v1/ws/vpn/session/:id", func(c *gin.Context) {
		setAuthUser(c, 200, model.RoleMember)
		c.Params = append(c.Params, gin.Param{Key: "id", Value: session.SessionID})
		_, _ = vpnSessionStream(c)
	})
	server := httptest.NewServer(r)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/ws/vpn/session/" + session.SessionID
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	var frame struct {
		Session model.AgentVPNSession `json:"session"`
		Logs    []string              `json:"logs"`
	}
	require.NoError(t, conn.ReadJSON(&frame))
	require.Equal(t, session.SessionID, frame.Session.SessionID)
	require.Contains(t, frame.Logs, "entry accepted connection")
	require.Contains(t, frame.Logs, "entry proxy connected")
	require.Contains(t, strings.Join(frame.Logs, "\n"), "[dashboard] agent report")
}

func attachControllerVPNTaskStream(t *testing.T, serverID uint64) *controllerVPNTaskStream {
	t.Helper()
	server, ok := singleton.ServerShared.Get(serverID)
	require.True(t, ok)
	stream := &controllerVPNTaskStream{}
	server.SetTaskStream(stream)
	return stream
}

type controllerVPNTaskStream struct {
	mu    sync.Mutex
	tasks []*pb.Task
}

func (s *controllerVPNTaskStream) Send(task *pb.Task) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tasks = append(s.tasks, task)
	return nil
}
func (s *controllerVPNTaskStream) Recv() (*pb.TaskResult, error) {
	return nil, context.Canceled
}
func (s *controllerVPNTaskStream) SetHeader(metadata.MD) error  { return nil }
func (s *controllerVPNTaskStream) SendHeader(metadata.MD) error { return nil }
func (s *controllerVPNTaskStream) SetTrailer(metadata.MD)       {}
func (s *controllerVPNTaskStream) Context() context.Context     { return context.Background() }
func (s *controllerVPNTaskStream) SendMsg(any) error            { return nil }
func (s *controllerVPNTaskStream) RecvMsg(any) error            { return context.Canceled }

func requireControllerVPNStatusTask(t *testing.T, stream *controllerVPNTaskStream, role string, sessionID string) {
	t.Helper()
	stream.mu.Lock()
	defer stream.mu.Unlock()
	require.Len(t, stream.tasks, 1)
	task := stream.tasks[0]
	require.Equal(t, uint64(model.TaskTypeVPNControl), task.GetType())
	var req model.VPNControlRequest
	require.NoError(t, json.Unmarshal([]byte(task.GetData()), &req))
	require.Equal(t, model.VPNActionStatus, req.Action)
	require.Equal(t, role, req.Role)
	require.Equal(t, sessionID, req.SessionID)
}
