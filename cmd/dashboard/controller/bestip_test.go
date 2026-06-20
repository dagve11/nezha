package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/bestip"
	"github.com/nezhahq/nezha/pkg/i18n"
	"github.com/nezhahq/nezha/service/singleton"
	"github.com/patrickmn/go-cache"
	"github.com/robfig/cron/v3"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupBestIPControllerFixture(t *testing.T) *gin.Context {
	t.Helper()

	originalDB := singleton.DB
	originalCache := singleton.Cache
	originalConf := singleton.Conf
	originalLocalizer := singleton.Localizer
	originalDDNSShared := singleton.DDNSShared
	originalCronShared := singleton.CronShared
	originalBestIPAutomationShared := singleton.BestIPAutomationShared
	originalRunner := bestIPFissionRunner
	originalStreamRunner := bestIPFissionStreamRunner
	originalAutomationRunner := singleton.BestIPAutomationFissionRunner
	originalNotificationSender := singleton.BestIPNotificationSender
	originalUpgrader := upgrader

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&model.DDNSProfile{},
		&model.NotificationGroup{},
		&model.BestIPAutomation{},
		&model.BestIPAutomationHistory{},
	))

	enableIPv4 := true
	enableIPv6 := false
	require.NoError(t, db.Create(&model.DDNSProfile{
		Common:       model.Common{ID: 7, UserID: 200},
		Name:         "dummy-ddns",
		Provider:     model.ProviderDummy,
		EnableIPv4:   &enableIPv4,
		EnableIPv6:   &enableIPv6,
		MaxRetries:   1,
		Domains:      []string{"cdn.example.com"},
		DomainsRaw:   `["cdn.example.com"]`,
		AccessID:     "",
		AccessSecret: "",
	}).Error)
	require.NoError(t, db.Create(&model.NotificationGroup{
		Common: model.Common{ID: 9, UserID: 200},
		Name:   "bestip-notify",
	}).Error)
	require.NoError(t, db.Create(&model.NotificationGroup{
		Common: model.Common{ID: 10, UserID: 300},
		Name:   "other-notify",
	}).Error)

	singleton.DB = db
	singleton.Cache = cache.New(time.Minute, time.Minute)
	singleton.Conf = &singleton.ConfigClass{Config: &model.Config{
		ConfigDashboard: model.ConfigDashboard{DNSServers: "1.1.1.1:53"},
	}}
	singleton.Localizer = i18n.NewLocalizer("en_US", "nezha", "translations", i18n.Translations)
	singleton.DDNSShared = singleton.NewDDNSClass()
	singleton.CronShared = &singleton.CronClass{Cron: cron.New(cron.WithSeconds())}
	singleton.BestIPAutomationShared = singleton.NewBestIPAutomationClass()

	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	setAuthUser(ctx, 200, model.RoleMember)

	t.Cleanup(func() {
		singleton.DB = originalDB
		singleton.Cache = originalCache
		singleton.Conf = originalConf
		singleton.Localizer = originalLocalizer
		singleton.DDNSShared = originalDDNSShared
		singleton.CronShared = originalCronShared
		singleton.BestIPAutomationShared = originalBestIPAutomationShared
		bestIPFissionRunner = originalRunner
		bestIPFissionStreamRunner = originalStreamRunner
		singleton.BestIPAutomationFissionRunner = originalAutomationRunner
		singleton.BestIPNotificationSender = originalNotificationSender
		upgrader = originalUpgrader
	})

	return ctx
}

func TestRunBestIPFissionUsesRequestConfig(t *testing.T) {
	ctx := setupBestIPControllerFixture(t)
	bestIPFissionRunner = func(_ context.Context, userID uint64, config bestip.FissionConfig) (*bestip.FissionRunResult, error) {
		require.Equal(t, uint64(200), userID)
		require.Equal(t, []string{"1.1.1.1"}, config.SeedIPs)
		require.Equal(t, 2, config.Rounds)
		return &bestip.FissionRunResult{
			IPs: []string{"1.1.1.1", "1.0.0.1"},
			Rounds: []bestip.FissionRoundResult{
				{Round: 1, NewIPs: []string{"1.0.0.1"}, NewDomains: []string{"one.example.com"}, TotalIPs: 2, TotalDomains: 1},
			},
		}, nil
	}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/bestip/fission", strings.NewReader(`{
		"seed_ips":["1.1.1.1"],
		"rounds":2,
		"concurrency":2,
		"timeout_ms":1000,
		"max_domains":10,
		"max_ips_per_round":10,
		"families":["ipv4"]
	}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	result, err := runBestIPFission(ctx)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"1.1.1.1", "1.0.0.1"}, result.IPs)
	require.Len(t, result.Rounds, 1)
}

func TestStreamBestIPFissionWritesProgressEvents(t *testing.T) {
	setupBestIPControllerFixture(t)
	InitUpgrader()

	bestIPFissionStreamRunner = func(_ context.Context, userID uint64, config bestip.FissionConfig, progress func(bestip.FissionProgressEvent)) (*bestip.FissionRunResult, error) {
		require.Equal(t, uint64(200), userID)
		require.Equal(t, []string{"1.1.1.1"}, config.SeedIPs)
		require.Equal(t, 1, config.Rounds)

		progress(bestip.FissionProgressEvent{
			Type: bestip.FissionProgressStart,
			IPs:  []string{"1.1.1.1"},
		})
		progress(bestip.FissionProgressEvent{
			Type:    bestip.FissionProgressIPLookupDone,
			Round:   1,
			IP:      "1.1.1.1",
			Domains: []string{"one.example.com"},
		})
		result := &bestip.FissionRunResult{
			IPs: []string{"1.1.1.1", "1.0.0.1"},
			Candidates: []bestip.CandidateResult{
				{Family: "ipv4", IP: "1.0.0.1", Score: 0.98},
			},
		}
		progress(bestip.FissionProgressEvent{
			Type:   bestip.FissionProgressDone,
			Result: result,
		})
		return result, nil
	}

	r := gin.New()
	r.Use(func(c *gin.Context) {
		setAuthUser(c, 200, model.RoleMember)
	})
	r.GET("/api/v1/ws/bestip/fission", commonHandler(streamBestIPFission))
	server := httptest.NewServer(r)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/ws/bestip/fission"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.WriteJSON(model.BestIPFissionForm{
		SeedIPs:        []string{"1.1.1.1"},
		Rounds:         1,
		Concurrency:    1,
		TimeoutMS:      1000,
		MaxDomains:     10,
		MaxIPsPerRound: 10,
		Families:       []string{"ipv4"},
	}))

	events := []bestip.FissionProgressEvent{}
	for {
		var event bestip.FissionProgressEvent
		require.NoError(t, conn.ReadJSON(&event))
		events = append(events, event)
		if event.Type == bestip.FissionProgressDone {
			break
		}
	}

	require.Len(t, events, 3)
	require.Equal(t, bestip.FissionProgressStart, events[0].Type)
	require.Equal(t, bestip.FissionProgressIPLookupDone, events[1].Type)
	require.Equal(t, "1.1.1.1", events[1].IP)
	require.Equal(t, []string{"one.example.com"}, events[1].Domains)
	require.Equal(t, bestip.FissionProgressDone, events[2].Type)
	require.Equal(t, []string{"1.1.1.1", "1.0.0.1"}, events[2].Result.IPs)
}

func TestWriteBestIPDNSReturnsSynchronousResult(t *testing.T) {
	ctx := setupBestIPControllerFixture(t)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/bestip/dns", strings.NewReader(`{
		"ddns_profiles":[7],
		"domains":["cdn.example.com"],
		"ipv4":"1.0.0.1"
	}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	results, err := writeBestIPDNS(ctx)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, uint64(7), results[0].ProfileID)
	require.True(t, results[0].Success, marshalBestIPDNSResults(t, results))
}

func TestWriteBestIPDNSAcceptsMultipleIPv4Records(t *testing.T) {
	ctx := setupBestIPControllerFixture(t)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/bestip/dns", strings.NewReader(`{
		"ddns_profiles":[7],
		"domains":["cdn.example.com"],
		"ipv4_records":["1.0.0.1","1.1.1.1"]
	}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	results, err := writeBestIPDNS(ctx)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.True(t, results[0].Success, marshalBestIPDNSResults(t, results))
}

func TestWriteBestIPDNSAllowsIPv4OnlyRecordsWithDualStackProfile(t *testing.T) {
	ctx := setupBestIPControllerFixture(t)
	enableIPv6 := true
	profile, ok := singleton.DDNSShared.Get(7)
	require.True(t, ok)
	profile.EnableIPv6 = &enableIPv6
	singleton.DDNSShared.Update(profile)

	ctx.Request = httptest.NewRequest(http.MethodPost, "/bestip/dns", strings.NewReader(`{
		"ddns_profiles":[7],
		"domains":["cdn.example.com"],
		"ipv4_records":["1.0.0.1"]
	}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	results, err := writeBestIPDNS(ctx)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.True(t, results[0].Success, marshalBestIPDNSResults(t, results))
}

func TestSaveGetRunAndRollbackBestIPAutomation(t *testing.T) {
	ctx := setupBestIPControllerFixture(t)
	singleton.BestIPAutomationFissionRunner = func(_ context.Context, _ bestip.FissionConfig) (*bestip.FissionRunResult, error) {
		return &bestip.FissionRunResult{
			IPs: []string{"1.1.1.1", "1.0.0.1"},
			Candidates: []bestip.CandidateResult{
				{Family: "ipv4", IP: "1.0.0.1", Score: 0.99, SuccessRate: 1, AvgLatencyMS: 10},
				{Family: "ipv4", IP: "1.1.1.1", Score: 0.50, SuccessRate: 1, AvgLatencyMS: 100},
			},
		}, nil
	}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/bestip/automation", strings.NewReader(`{
		"enabled":true,
		"scheduler":"0 */30 * * * *",
		"auto_write_dns":true,
		"push_successful":true,
		"push_failed":true,
		"fission_notification_group_id":9,
		"notification_group_id":9,
		"write_top_n":1,
		"ddns_profiles":[7],
		"domains":["cdn.example.com"],
		"fission":{
			"seed_ips":["1.1.1.1"],
			"rounds":1,
			"concurrency":1,
			"timeout_ms":1000,
			"max_domains":10,
			"max_ips_per_round":10,
			"families":["ipv4"]
		}
	}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	saved, err := saveBestIPAutomation(ctx)
	require.NoError(t, err)
	require.True(t, saved.Enabled)
	require.NotZero(t, saved.CronJobID)
	require.True(t, saved.PushSuccessful)
	require.True(t, saved.PushFailed)
	require.Equal(t, uint64(9), saved.FissionNotificationGroupID)
	require.Equal(t, uint64(9), saved.NotificationGroupID)

	saved.LastIPv4Records = []string{"9.9.9.9"}
	require.NoError(t, singleton.DB.Save(saved).Error)
	require.NoError(t, singleton.BestIPAutomationShared.Update(saved))

	ctx.Request = httptest.NewRequest(http.MethodGet, "/bestip/automation", nil)
	got, err := getBestIPAutomation(ctx)
	require.NoError(t, err)
	require.Equal(t, saved.ID, got.ID)
	require.Equal(t, []uint64{7}, got.DDNSProfiles)

	ctx.Request = httptest.NewRequest(http.MethodPost, "/bestip/automation/run", nil)
	runHistory, err := runBestIPAutomation(ctx)
	require.NoError(t, err)
	require.True(t, runHistory.Success, runHistory.Error)
	require.Equal(t, []string{"1.0.0.1"}, runHistory.IPv4Records)

	ctx.Request = httptest.NewRequest(http.MethodPost, "/bestip/automation/rollback", nil)
	rollbackHistory, err := rollbackBestIPAutomation(ctx)
	require.NoError(t, err)
	require.True(t, rollbackHistory.Success, rollbackHistory.Error)
	require.Equal(t, model.BestIPAutomationActionRollback, rollbackHistory.Action)
	require.Equal(t, []string{"9.9.9.9"}, rollbackHistory.IPv4Records)
}

func TestSaveBestIPAutomationRejectsForeignNotificationGroup(t *testing.T) {
	ctx := setupBestIPControllerFixture(t)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/bestip/automation", strings.NewReader(`{
		"enabled":false,
		"scheduler":"0 */30 * * * *",
		"auto_write_dns":true,
		"push_successful":true,
		"fission_notification_group_id":10,
		"notification_group_id":10,
		"write_top_n":1,
		"ddns_profiles":[7],
		"domains":["cdn.example.com"],
		"fission":{
			"seed_ips":["1.1.1.1"],
			"rounds":1,
			"concurrency":1,
			"timeout_ms":1000,
			"max_domains":10,
			"max_ips_per_round":10,
			"families":["ipv4"]
		}
	}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	_, err := saveBestIPAutomation(ctx)

	require.Error(t, err)
	require.Contains(t, err.Error(), "permission denied")
}

func TestNotifyBestIPResultSendsSelectedRecords(t *testing.T) {
	ctx := setupBestIPControllerFixture(t)
	sentNotifications := []string{}
	singleton.BestIPNotificationSender = func(groupID uint64, message string, muteLabel string) {
		require.Equal(t, uint64(9), groupID)
		require.Empty(t, muteLabel)
		sentNotifications = append(sentNotifications, message)
	}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/bestip/notify", strings.NewReader(`{
		"notification_group_id":9,
		"domains":["cdn.example.com"],
		"ipv4_records":["1.0.0.1"],
		"ipv6_records":["2606:4700::1"]
	}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	result, err := notifyBestIPResult(ctx)

	require.NoError(t, err)
	require.True(t, result.Success)
	require.Len(t, sentNotifications, 1)
	require.Contains(t, sentNotifications[0], "[Best IP] Selected records")
	require.Contains(t, sentNotifications[0], "IPv4: 1.0.0.1")
	require.Contains(t, sentNotifications[0], "IPv6: 2606:4700::1")
	require.Contains(t, sentNotifications[0], "Domains: cdn.example.com")
}

func marshalBestIPDNSResults(t *testing.T, results []model.BestIPDNSWriteResult) string {
	t.Helper()
	data, err := json.Marshal(results)
	require.NoError(t, err)
	return string(data)
}
