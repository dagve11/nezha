package controller

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/service/singleton"
)

func setupRegisterTest(t *testing.T) func() {
	t.Helper()
	originalDB := singleton.DB
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&model.User{}))
	singleton.DB = db
	originalUserInfoMap := singleton.UserInfoMap
	originalAgentSecretToUserId := singleton.AgentSecretToUserId
	singleton.UserInfoMap = make(map[uint64]model.UserInfo)
	singleton.AgentSecretToUserId = make(map[string]uint64)
	return func() {
		singleton.DB = originalDB
		singleton.UserInfoMap = originalUserInfoMap
		singleton.AgentSecretToUserId = originalAgentSecretToUserId
	}
}

func newRegisterContext(t *testing.T, payload any) *gin.Context {
	t.Helper()
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/api/v1/register", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	return c
}

func TestRegisterUserCreatesMemberWithDefaultPermissions(t *testing.T) {
	cleanup := setupRegisterTest(t)
	defer cleanup()

	id, err := registerUser(newRegisterContext(t, model.RegisterForm{
		Username: "member",
		Password: "secret123",
	}))
	require.NoError(t, err)
	require.NotZero(t, id)

	var user model.User
	require.NoError(t, singleton.DB.First(&user, id).Error)
	assert.Equal(t, "member", user.Username)
	assert.Equal(t, model.RoleMember, user.Role)
	assert.Equal(t, model.DefaultUserPermissions(model.RoleMember), user.Permissions)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(user.Password), []byte("secret123")))
}

func TestRegisterUserRejectsShortPassword(t *testing.T) {
	cleanup := setupRegisterTest(t)
	defer cleanup()

	_, err := registerUser(newRegisterContext(t, model.RegisterForm{
		Username: "member",
		Password: "short",
	}))
	require.Error(t, err)
}
