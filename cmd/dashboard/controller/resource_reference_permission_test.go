package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/i18n"
	"github.com/nezhahq/nezha/service/singleton"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupResourceReferenceFixture(t *testing.T) func() *gin.Context {
	t.Helper()

	originalDB := singleton.DB
	originalLoc := singleton.Loc
	originalLocalizer := singleton.Localizer
	originalServerShared := singleton.ServerShared
	originalCronShared := singleton.CronShared
	originalDDNSShared := singleton.DDNSShared
	originalNotificationShared := singleton.NotificationShared

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&model.Server{},
		&model.Cron{},
		&model.DDNSProfile{},
		&model.Notification{},
		&model.NotificationGroup{},
		&model.NotificationGroupNotification{},
		&model.ServerGroup{},
		&model.ServerGroupServer{},
	))

	require.NoError(t, db.Create(&model.Server{Common: model.Common{ID: 1, UserID: 200}, Name: "owned", UUID: "owned"}).Error)
	require.NoError(t, db.Create(&model.Server{Common: model.Common{ID: 2, UserID: 300}, Name: "foreign", UUID: "foreign"}).Error)
	require.NoError(t, db.Create(&model.Cron{Common: model.Common{ID: 11, UserID: 200}, Name: "owned trigger", TaskType: model.CronTypeTriggerTask}).Error)
	require.NoError(t, db.Create(&model.Cron{Common: model.Common{ID: 12, UserID: 300}, Name: "foreign trigger", TaskType: model.CronTypeTriggerTask}).Error)
	require.NoError(t, db.Create(&model.DDNSProfile{Common: model.Common{ID: 21, UserID: 200}, Name: "owned ddns", Provider: model.ProviderDummy, Domains: []string{"owned.example.com"}}).Error)
	require.NoError(t, db.Create(&model.DDNSProfile{Common: model.Common{ID: 22, UserID: 300}, Name: "foreign ddns", Provider: model.ProviderDummy, Domains: []string{"foreign.example.com"}}).Error)
	require.NoError(t, db.Create(&model.Notification{Common: model.Common{ID: 31, UserID: 200}, Name: "owned notification"}).Error)
	require.NoError(t, db.Create(&model.Notification{Common: model.Common{ID: 32, UserID: 300}, Name: "foreign notification"}).Error)
	require.NoError(t, db.Create(&model.NotificationGroup{Common: model.Common{ID: 41, UserID: 200}, Name: "owned group"}).Error)
	require.NoError(t, db.Create(&model.NotificationGroup{Common: model.Common{ID: 42, UserID: 300}, Name: "foreign group"}).Error)

	singleton.DB = db
	singleton.Loc = time.UTC
	singleton.Localizer = i18n.NewLocalizer("en_US", "nezha", "translations", i18n.Translations)
	singleton.NotificationShared = singleton.NewNotificationClass()
	singleton.DDNSShared = singleton.NewDDNSClass()
	singleton.ServerShared = singleton.NewServerClass()
	singleton.CronShared = singleton.NewCronClass()

	t.Cleanup(func() {
		if singleton.CronShared != nil && singleton.CronShared.Cron != nil {
			singleton.CronShared.Cron.Stop()
		}
		singleton.DB = originalDB
		singleton.Loc = originalLoc
		singleton.Localizer = originalLocalizer
		singleton.ServerShared = originalServerShared
		singleton.CronShared = originalCronShared
		singleton.DDNSShared = originalDDNSShared
		singleton.NotificationShared = originalNotificationShared
	})

	gin.SetMode(gin.TestMode)
	return func() *gin.Context {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		setAuthUser(ctx, 200, model.RoleMember)
		return ctx
	}
}

func setJSONRequest(c *gin.Context, method, target, body string) {
	c.Request = httptest.NewRequest(method, target, strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
}

func TestResourceReferencesRejectForeignAndMissingIDs(t *testing.T) {
	newCtx := setupResourceReferenceFixture(t)

	tests := []struct {
		name string
		run  func(*gin.Context) error
		want string
	}{
		{
			name: "cron foreign server",
			run: func(c *gin.Context) error {
				setJSONRequest(c, http.MethodPost, "/cron", `{"task_type":1,"name":"bad cron","servers":[2]}`)
				_, err := createCron(c)
				return err
			},
			want: "permission denied",
		},
		{
			name: "cron missing server",
			run: func(c *gin.Context) error {
				setJSONRequest(c, http.MethodPost, "/cron", `{"task_type":1,"name":"bad cron","servers":[99]}`)
				_, err := createCron(c)
				return err
			},
			want: "server id 99 does not exist",
		},
		{
			name: "server foreign ddns profile",
			run: func(c *gin.Context) error {
				c.Params = gin.Params{{Key: "id", Value: "1"}}
				setJSONRequest(c, http.MethodPatch, "/server/1", `{"name":"owned","ddns_profiles":[22]}`)
				_, err := updateServer(c)
				return err
			},
			want: "permission denied",
		},
		{
			name: "server missing ddns profile",
			run: func(c *gin.Context) error {
				c.Params = gin.Params{{Key: "id", Value: "1"}}
				setJSONRequest(c, http.MethodPatch, "/server/1", `{"name":"owned","ddns_profiles":[99]}`)
				_, err := updateServer(c)
				return err
			},
			want: "ddns id 99 does not exist",
		},
		{
			name: "notification group foreign notification",
			run: func(c *gin.Context) error {
				setJSONRequest(c, http.MethodPost, "/notification-group", `{"name":"bad group","notifications":[32]}`)
				_, err := createNotificationGroup(c)
				return err
			},
			want: "permission denied",
		},
		{
			name: "notification group missing notification",
			run: func(c *gin.Context) error {
				setJSONRequest(c, http.MethodPost, "/notification-group", `{"name":"bad group","notifications":[99]}`)
				_, err := createNotificationGroup(c)
				return err
			},
			want: "notification id 99 does not exist",
		},
		{
			name: "server group foreign server",
			run: func(c *gin.Context) error {
				setJSONRequest(c, http.MethodPost, "/server-group", `{"name":"bad group","servers":[2]}`)
				_, err := createServerGroup(c)
				return err
			},
			want: "permission denied",
		},
		{
			name: "server group missing server",
			run: func(c *gin.Context) error {
				setJSONRequest(c, http.MethodPost, "/server-group", `{"name":"bad group","servers":[99]}`)
				_, err := createServerGroup(c)
				return err
			},
			want: "server id 99 does not exist",
		},
		{
			name: "service foreign skip server",
			run: func(c *gin.Context) error {
				return validateServers(c, &model.Service{SkipServers: map[uint64]bool{2: true}})
			},
			want: "permission denied",
		},
		{
			name: "service missing trigger task",
			run: func(c *gin.Context) error {
				return validateServers(c, &model.Service{FailTriggerTasks: []uint64{99}})
			},
			want: "task id 99 does not exist",
		},
		{
			name: "alert foreign ignored server",
			run: func(c *gin.Context) error {
				return validateRule(c, &model.AlertRule{Rules: []*model.Rule{{Type: "cpu", Duration: 3, Ignore: map[uint64]bool{2: true}}}})
			},
			want: "permission denied",
		},
		{
			name: "alert foreign trigger task",
			run: func(c *gin.Context) error {
				return validateRule(c, &model.AlertRule{
					Rules:            []*model.Rule{{Type: "cpu", Duration: 3, Ignore: map[uint64]bool{1: true}}},
					FailTriggerTasks: []uint64{12},
				})
			},
			want: "permission denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run(newCtx())
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.want)
		})
	}
}
