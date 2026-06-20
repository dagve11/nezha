package singleton

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/bestip"
	"github.com/nezhahq/nezha/pkg/i18n"
	"github.com/patrickmn/go-cache"
	"github.com/robfig/cron/v3"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupBestIPAutomationFixture(t *testing.T) *BestIPAutomationClass {
	t.Helper()

	originalDB := DB
	originalCache := Cache
	originalConf := Conf
	originalLocalizer := Localizer
	originalDDNSShared := DDNSShared
	originalDDNSCredentialShared := DDNSCredentialShared
	originalCronShared := CronShared
	originalRunner := BestIPAutomationFissionRunner
	originalNotificationSender := BestIPNotificationSender

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&model.DDNSProfile{},
		&model.DDNSCredential{},
		&model.NotificationGroup{},
		&model.BestIPAutomation{},
		&model.BestIPAutomationHistory{},
	))

	enableIPv4 := true
	enableIPv6 := true
	require.NoError(t, db.Create(&model.DDNSProfile{
		Common:     model.Common{ID: 7, UserID: 200},
		Name:       "dummy-ddns",
		Provider:   model.ProviderDummy,
		EnableIPv4: &enableIPv4,
		EnableIPv6: &enableIPv6,
		MaxRetries: 1,
		Domains:    []string{"cdn.example.com"},
		DomainsRaw: `["cdn.example.com"]`,
	}).Error)
	require.NoError(t, db.Create(&model.DDNSCredential{
		Common:   model.Common{ID: 8, UserID: 200},
		Name:     "dummy-credential",
		Provider: model.ProviderDummy,
	}).Error)
	require.NoError(t, db.Create(&model.NotificationGroup{
		Common: model.Common{ID: 9, UserID: 200},
		Name:   "bestip-notify",
	}).Error)

	DB = db
	Cache = cache.New(time.Minute, time.Minute)
	Conf = &ConfigClass{Config: &model.Config{
		ConfigDashboard: model.ConfigDashboard{DNSServers: "1.1.1.1:53"},
	}}
	Localizer = i18n.NewLocalizer("en_US", "nezha", "translations", i18n.Translations)
	DDNSShared = NewDDNSClass()
	DDNSCredentialShared = NewDDNSCredentialClass()
	CronShared = &CronClass{Cron: cron.New(cron.WithSeconds())}

	t.Cleanup(func() {
		DB = originalDB
		Cache = originalCache
		Conf = originalConf
		Localizer = originalLocalizer
		DDNSShared = originalDDNSShared
		DDNSCredentialShared = originalDDNSCredentialShared
		CronShared = originalCronShared
		BestIPAutomationFissionRunner = originalRunner
		BestIPNotificationSender = originalNotificationSender
	})

	return NewBestIPAutomationClass()
}

func TestWriteBestIPDNSUsesDDNSCredentialsWithOverrideDomains(t *testing.T) {
	setupBestIPAutomationFixture(t)

	results, err := WriteBestIPDNS(context.Background(), 200, model.BestIPDNSWriteForm{
		DDNSCredentials: []uint64{8},
		Domains:         []string{"best.example.com"},
		IPv4Records:     []string{"1.0.0.1"},
	})

	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Zero(t, results[0].ProfileID)
	require.Equal(t, uint64(8), results[0].CredentialID)
	require.Equal(t, model.ProviderDummy, results[0].Provider)
	require.Equal(t, []string{"best.example.com"}, results[0].Domains)
	require.True(t, results[0].Success)
}

func TestBestIPAutomationRunWritesTopCandidateStoresRollbackPointAndNotifies(t *testing.T) {
	automation := setupBestIPAutomationFixture(t)
	sentNotifications := []string{}
	BestIPNotificationSender = func(groupID uint64, message string, muteLabel string) {
		require.Equal(t, uint64(9), groupID)
		require.Empty(t, muteLabel)
		sentNotifications = append(sentNotifications, message)
	}
	BestIPAutomationFissionRunner = func(_ context.Context, _ bestip.FissionConfig) (*bestip.FissionRunResult, error) {
		return &bestip.FissionRunResult{
			IPs: []string{"1.1.1.1", "1.0.0.1"},
			Candidates: []bestip.CandidateResult{
				{Family: "ipv4", IP: "1.0.0.1", Score: 0.99, SuccessRate: 1, AvgLatencyMS: 10},
				{Family: "ipv4", IP: "1.1.1.1", Score: 0.50, SuccessRate: 1, AvgLatencyMS: 100},
			},
		}, nil
	}

	saved, err := automation.SaveForUser(200, model.BestIPAutomationForm{
		Enabled:             true,
		Scheduler:           "0 */30 * * * *",
		AutoWriteDNS:        true,
		PushSuccessful:      true,
		PushFailed:          true,
		NotificationGroupID: 9,
		WriteTopN:           1,
		DDNSProfiles:        []uint64{7},
		Domains:             []string{"cdn.example.com"},
		Fission: bestip.FissionConfig{
			SeedIPs:        []string{"1.1.1.1"},
			Rounds:         1,
			Concurrency:    1,
			TimeoutMS:      1000,
			MaxDomains:     10,
			MaxIPsPerRound: 10,
			Families:       []string{"ipv4"},
		},
	})
	require.NoError(t, err)

	saved.LastIPv4Records = []string{"9.9.9.9"}
	require.NoError(t, DB.Save(saved).Error)
	automation.Update(saved)

	history, err := automation.RunByID(context.Background(), saved.ID)
	require.NoError(t, err)
	require.True(t, history.Success, history.Error)
	require.Equal(t, []string{"1.0.0.1"}, history.IPv4Records)
	require.Equal(t, []string{"9.9.9.9"}, history.RollbackIPv4Records)

	updated, ok := automation.Get(saved.ID)
	require.True(t, ok)
	require.Equal(t, []string{"1.0.0.1"}, updated.LastIPv4Records)
	require.Equal(t, []string{"9.9.9.9"}, updated.RollbackIPv4Records)
	require.Len(t, updated.LastDNSResults, 1)
	require.Equal(t, uint64(7), updated.LastDNSResults[0].ProfileID)
	require.True(t, updated.LastDNSResults[0].Success)
	require.NotZero(t, updated.LastRunAt)
	require.True(t, updated.LastResult)
	require.Equal(t, uint64(9), updated.NotificationGroupID)
	require.True(t, updated.PushSuccessful)
	require.True(t, updated.PushFailed)
	require.Len(t, sentNotifications, 1)
	require.Contains(t, sentNotifications[0], "[Best IP] Automation completed")
	require.Contains(t, sentNotifications[0], "IPv4: 1.0.0.1")
	require.Contains(t, sentNotifications[0], "Domains: cdn.example.com")
}

func TestBestIPAutomationRunWithoutDNSWritebackNotifiesCandidateRecords(t *testing.T) {
	automation := setupBestIPAutomationFixture(t)
	Localizer = i18n.NewLocalizer("zh_CN", "nezha", "translations", i18n.Translations)
	sentNotifications := []string{}
	BestIPNotificationSender = func(groupID uint64, message string, muteLabel string) {
		require.Equal(t, uint64(9), groupID)
		require.Empty(t, muteLabel)
		sentNotifications = append(sentNotifications, message)
	}
	BestIPAutomationFissionRunner = func(_ context.Context, _ bestip.FissionConfig) (*bestip.FissionRunResult, error) {
		return &bestip.FissionRunResult{
			IPs: []string{"1.1.1.1", "1.0.0.1"},
			Candidates: []bestip.CandidateResult{
				{Family: "ipv4", IP: "1.0.0.1", Score: 0.99, SuccessRate: 1, AvgLatencyMS: 10},
				{Family: "ipv4", IP: "1.1.1.1", Score: 0.50, SuccessRate: 1, AvgLatencyMS: 100},
			},
		}, nil
	}

	saved, err := automation.SaveForUser(200, model.BestIPAutomationForm{
		Enabled:             false,
		Scheduler:           "0 */30 * * * *",
		AutoWriteDNS:        false,
		PushSuccessful:      true,
		NotificationGroupID: 9,
		WriteTopN:           1,
		DDNSProfiles:        []uint64{7},
		Domains:             []string{"cdn.example.com"},
		Fission: bestip.FissionConfig{
			SeedIPs:        []string{"1.1.1.1"},
			Rounds:         1,
			Concurrency:    1,
			TimeoutMS:      1000,
			MaxDomains:     10,
			MaxIPsPerRound: 10,
			Families:       []string{"ipv4"},
		},
	})
	require.NoError(t, err)

	history, err := automation.RunByID(context.Background(), saved.ID)
	require.NoError(t, err)
	require.True(t, history.Success, history.Error)
	require.Empty(t, history.IPv4Records)
	require.Len(t, sentNotifications, 1)
	require.Contains(t, sentNotifications[0], Localizer.T("[Best IP] Automation completed"))
	require.Contains(t, sentNotifications[0], "IPv4: 1.0.0.1")
	require.Contains(t, sentNotifications[0], Localizer.Tf("Candidates: %d", 2))
}

func TestSendBestIPNotificationListsTopTenCandidateRecords(t *testing.T) {
	setupBestIPAutomationFixture(t)
	sentNotifications := []string{}
	BestIPNotificationSender = func(groupID uint64, message string, muteLabel string) {
		require.Equal(t, uint64(9), groupID)
		require.Empty(t, muteLabel)
		sentNotifications = append(sentNotifications, message)
	}

	candidates := make([]bestip.CandidateResult, 0, 12)
	for i := 1; i <= 6; i++ {
		candidates = append(candidates, bestip.CandidateResult{
			Family:       "ipv4",
			IP:           "203.0.113." + strconv.Itoa(i),
			AvgLatencyMS: float64(10 + i),
			SuccessRate:  1,
			DownloadMBps: float64(20 - i),
			Score:        1 - float64(i)/100,
		})
		candidates = append(candidates, bestip.CandidateResult{
			Family:       "ipv6",
			IP:           "2001:db8::" + strconv.Itoa(i),
			AvgLatencyMS: float64(10 + i),
			SuccessRate:  1,
			DownloadMBps: float64(20 - i),
			Score:        1 - float64(i)/100,
		})
	}

	result, err := SendBestIPNotification(200, model.BestIPNotifyForm{
		NotificationGroupID: 9,
		Domains:             []string{"cdn.example.com"},
		Candidates:          candidates,
		WriteTopN:           10,
	})

	require.NoError(t, err)
	require.True(t, result.Success)
	require.Equal(t, []string{
		"203.0.113.1",
		"203.0.113.2",
		"203.0.113.3",
		"203.0.113.4",
		"203.0.113.5",
	}, result.IPv4)
	require.Equal(t, []string{
		"2001:db8::1",
		"2001:db8::2",
		"2001:db8::3",
		"2001:db8::4",
		"2001:db8::5",
	}, result.IPv6)
	require.Len(t, sentNotifications, 1)
	require.Contains(t, sentNotifications[0], "IPv4: 203.0.113.1, 203.0.113.2, 203.0.113.3, 203.0.113.4, 203.0.113.5")
	require.Contains(t, sentNotifications[0], "IPv6: 2001:db8::1, 2001:db8::2, 2001:db8::3, 2001:db8::4, 2001:db8::5")
	require.Contains(t, sentNotifications[0], "Candidates: 12")
	require.Contains(t, sentNotifications[0], "Selected records: 10")
	require.NotContains(t, sentNotifications[0], "203.0.113.6")
	require.NotContains(t, sentNotifications[0], "2001:db8::6")
}

func TestBestIPAutomationRollbackWritesStoredRollbackRecords(t *testing.T) {
	automation := setupBestIPAutomationFixture(t)
	saved, err := automation.SaveForUser(200, model.BestIPAutomationForm{
		Enabled:      false,
		Scheduler:    "0 */30 * * * *",
		AutoWriteDNS: true,
		WriteTopN:    1,
		DDNSProfiles: []uint64{7},
		Domains:      []string{"cdn.example.com"},
		Fission: bestip.FissionConfig{
			SeedIPs:        []string{"1.1.1.1"},
			Rounds:         1,
			Concurrency:    1,
			TimeoutMS:      1000,
			MaxDomains:     10,
			MaxIPsPerRound: 10,
			Families:       []string{"ipv4"},
		},
	})
	require.NoError(t, err)

	saved.LastIPv4Records = []string{"1.0.0.1"}
	saved.RollbackIPv4Records = []string{"9.9.9.9"}
	require.NoError(t, DB.Save(saved).Error)
	automation.Update(saved)

	history, err := automation.RollbackByID(context.Background(), saved.ID)
	require.NoError(t, err)
	require.True(t, history.Success, history.Error)
	require.Equal(t, model.BestIPAutomationActionRollback, history.Action)
	require.Equal(t, []string{"9.9.9.9"}, history.IPv4Records)
	require.Equal(t, []string{"1.0.0.1"}, history.RollbackIPv4Records)

	updated, ok := automation.Get(saved.ID)
	require.True(t, ok)
	require.Equal(t, []string{"9.9.9.9"}, updated.LastIPv4Records)
	require.Equal(t, []string{"1.0.0.1"}, updated.RollbackIPv4Records)
	require.Len(t, updated.LastDNSResults, 1)
	require.Equal(t, uint64(7), updated.LastDNSResults[0].ProfileID)
	require.True(t, updated.LastDNSResults[0].Success)
}

func TestBestIPAutomationRollbackSuccessSendsRollbackNotification(t *testing.T) {
	automation := setupBestIPAutomationFixture(t)
	sentNotifications := []string{}
	BestIPNotificationSender = func(groupID uint64, message string, muteLabel string) {
		require.Equal(t, uint64(9), groupID)
		require.Empty(t, muteLabel)
		sentNotifications = append(sentNotifications, message)
	}
	saved, err := automation.SaveForUser(200, model.BestIPAutomationForm{
		Enabled:             false,
		Scheduler:           "0 */30 * * * *",
		AutoWriteDNS:        true,
		PushSuccessful:      true,
		NotificationGroupID: 9,
		WriteTopN:           1,
		DDNSProfiles:        []uint64{7},
		Domains:             []string{"cdn.example.com"},
		Fission: bestip.FissionConfig{
			SeedIPs:        []string{"1.1.1.1"},
			Rounds:         1,
			Concurrency:    1,
			TimeoutMS:      1000,
			MaxDomains:     10,
			MaxIPsPerRound: 10,
			Families:       []string{"ipv4"},
		},
	})
	require.NoError(t, err)

	saved.LastIPv4Records = []string{"1.0.0.1"}
	saved.RollbackIPv4Records = []string{"9.9.9.9"}
	require.NoError(t, DB.Save(saved).Error)
	automation.Update(saved)

	history, err := automation.RollbackByID(context.Background(), saved.ID)
	require.NoError(t, err)
	require.True(t, history.Success, history.Error)
	require.Len(t, sentNotifications, 1)
	require.Contains(t, sentNotifications[0], "[Best IP] Rollback completed")
	require.Contains(t, sentNotifications[0], "IPv4: 9.9.9.9")
	require.Contains(t, sentNotifications[0], "DNS writeback: success")
}

func TestBestIPAutomationRollbackFailureSendsRollbackFailureNotification(t *testing.T) {
	automation := setupBestIPAutomationFixture(t)
	sentNotifications := []string{}
	BestIPNotificationSender = func(groupID uint64, message string, muteLabel string) {
		require.Equal(t, uint64(9), groupID)
		require.NotEmpty(t, muteLabel)
		sentNotifications = append(sentNotifications, message)
	}
	saved, err := automation.SaveForUser(200, model.BestIPAutomationForm{
		Enabled:             false,
		Scheduler:           "0 */30 * * * *",
		AutoWriteDNS:        true,
		PushFailed:          true,
		NotificationGroupID: 9,
		WriteTopN:           1,
		DDNSProfiles:        []uint64{7},
		Domains:             []string{"cdn.example.com"},
		Fission: bestip.FissionConfig{
			SeedIPs:        []string{"1.1.1.1"},
			Rounds:         1,
			Concurrency:    1,
			TimeoutMS:      1000,
			MaxDomains:     10,
			MaxIPsPerRound: 10,
			Families:       []string{"ipv4"},
		},
	})
	require.NoError(t, err)

	saved.LastIPv4Records = []string{"1.0.0.1"}
	saved.RollbackIPv4Records = []string{"not-an-ip"}
	require.NoError(t, DB.Save(saved).Error)
	automation.Update(saved)

	history, err := automation.RollbackByID(context.Background(), saved.ID)
	require.Error(t, err)
	require.False(t, history.Success)
	require.Len(t, sentNotifications, 1)
	require.Contains(t, sentNotifications[0], "[Best IP] Rollback failed")
	require.Contains(t, sentNotifications[0], "parse error")
}

func TestBestIPAutomationRunNotifiesFailureWhenEnabled(t *testing.T) {
	automation := setupBestIPAutomationFixture(t)
	sentNotifications := []string{}
	BestIPNotificationSender = func(groupID uint64, message string, muteLabel string) {
		require.Equal(t, uint64(9), groupID)
		require.NotEmpty(t, muteLabel)
		sentNotifications = append(sentNotifications, message)
	}
	BestIPAutomationFissionRunner = func(_ context.Context, _ bestip.FissionConfig) (*bestip.FissionRunResult, error) {
		return &bestip.FissionRunResult{Candidates: nil}, nil
	}

	saved, err := automation.SaveForUser(200, model.BestIPAutomationForm{
		Enabled:             false,
		Scheduler:           "0 */30 * * * *",
		AutoWriteDNS:        true,
		PushFailed:          true,
		NotificationGroupID: 9,
		WriteTopN:           1,
		DDNSProfiles:        []uint64{7},
		Domains:             []string{"cdn.example.com"},
		Fission: bestip.FissionConfig{
			SeedIPs:        []string{"1.1.1.1"},
			Rounds:         1,
			Concurrency:    1,
			TimeoutMS:      1000,
			MaxDomains:     10,
			MaxIPsPerRound: 10,
			Families:       []string{"ipv4"},
		},
	})
	require.NoError(t, err)

	history, err := automation.RunByID(context.Background(), saved.ID)
	require.Error(t, err)
	require.False(t, history.Success)
	require.Len(t, sentNotifications, 1)
	require.Contains(t, sentNotifications[0], "[Best IP] Automation failed")
	require.Contains(t, sentNotifications[0], "no candidate records available")
}
