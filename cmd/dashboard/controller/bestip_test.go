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
	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/bestip"
	"github.com/nezhahq/nezha/pkg/i18n"
	"github.com/nezhahq/nezha/service/singleton"
	"github.com/patrickmn/go-cache"
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
	originalRunner := bestIPFissionRunner

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&model.DDNSProfile{}))

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

	singleton.DB = db
	singleton.Cache = cache.New(time.Minute, time.Minute)
	singleton.Conf = &singleton.ConfigClass{Config: &model.Config{
		ConfigDashboard: model.ConfigDashboard{DNSServers: "1.1.1.1:53"},
	}}
	singleton.Localizer = i18n.NewLocalizer("en_US", "nezha", "translations", i18n.Translations)
	singleton.DDNSShared = singleton.NewDDNSClass()

	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	setAuthUser(ctx, 200, model.RoleMember)

	t.Cleanup(func() {
		singleton.DB = originalDB
		singleton.Cache = originalCache
		singleton.Conf = originalConf
		singleton.Localizer = originalLocalizer
		singleton.DDNSShared = originalDDNSShared
		bestIPFissionRunner = originalRunner
	})

	return ctx
}

func TestRunBestIPFissionUsesRequestConfig(t *testing.T) {
	ctx := setupBestIPControllerFixture(t)
	bestIPFissionRunner = func(_ context.Context, config bestip.FissionConfig) (*bestip.FissionRunResult, error) {
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

func marshalBestIPDNSResults(t *testing.T, results []model.BestIPDNSWriteResult) string {
	t.Helper()
	data, err := json.Marshal(results)
	require.NoError(t, err)
	return string(data)
}
