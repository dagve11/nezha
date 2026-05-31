package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/i18n"
	"github.com/nezhahq/nezha/service/singleton"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupNATPortControllerFixture(t *testing.T) *gin.Context {
	t.Helper()
	originalDB := singleton.DB
	originalServerShared := singleton.ServerShared
	originalNATShared := singleton.NATShared
	originalConf := singleton.Conf
	originalLocalizer := singleton.Localizer

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&model.Server{}, &model.NAT{}))
	require.NoError(t, db.Create(&model.Server{
		Common: model.Common{ID: 1, UserID: 200},
		Name:   "member-server",
		UUID:   "member-server",
	}).Error)

	singleton.DB = db
	singleton.Conf = &singleton.ConfigClass{Config: &model.Config{
		ListenPort: 8008,
		HTTPS:      model.HTTPSConf{ListenPort: 8443},
	}}
	singleton.Localizer = i18n.NewLocalizer("en_US", "nezha", "translations", i18n.Translations)
	singleton.ServerShared = singleton.NewServerClass()
	singleton.NATShared = singleton.NewNATClass()

	t.Cleanup(func() {
		singleton.DB = originalDB
		singleton.ServerShared = originalServerShared
		singleton.NATShared = originalNATShared
		singleton.Conf = originalConf
		singleton.Localizer = originalLocalizer
	})

	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	setAuthUser(ctx, 200, model.RoleMember)
	return ctx
}

func TestCreateNATStoresBindPort(t *testing.T) {
	ctx := setupNATPortControllerFixture(t)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/nat", strings.NewReader(`{"name":"ssh","enabled":false,"host":"127.0.0.1:22","port":2222,"server_id":1}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	id, err := createNAT(ctx)
	require.NoError(t, err)

	var got model.NAT
	require.NoError(t, singleton.DB.First(&got, id).Error)
	require.Equal(t, uint16(2222), got.Port)
	require.Equal(t, "127.0.0.1:22", got.Host)
	cached := singleton.NATShared.GetNATConfigByPort(2222)
	require.NotNil(t, cached)
	require.Equal(t, id, cached.ID)
}

func TestCreateNATRejectsDashboardListenPort(t *testing.T) {
	ctx := setupNATPortControllerFixture(t)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/nat", strings.NewReader(`{"name":"ssh","enabled":false,"host":"127.0.0.1:22","port":8008,"server_id":1}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	_, err := createNAT(ctx)
	require.Error(t, err)
}

func TestBatchDeleteNATRejectsForeignRecordWhenCacheMisses(t *testing.T) {
	ctx := setupNATPortControllerFixture(t)
	require.NoError(t, singleton.DB.Create(&model.NAT{
		Common:   model.Common{ID: 2, UserID: 201},
		Enabled:  false,
		Name:     "foreign-ssh",
		ServerID: 1,
		Host:     "127.0.0.1:22",
		Port:     2222,
	}).Error)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/batch-delete/nat", strings.NewReader(`[2]`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	_, err := batchDeleteNAT(ctx)
	require.Error(t, err)

	var count int64
	require.NoError(t, singleton.DB.Model(&model.NAT{}).Where("id = ?", 2).Count(&count).Error)
	require.Equal(t, int64(1), count)
}
