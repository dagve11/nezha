package controller

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/i18n"
	pb "github.com/nezhahq/nezha/proto"
	"github.com/nezhahq/nezha/service/singleton"
)

// fakeTaskStream is the minimum stub of pb.NezhaService_RequestTaskServer
// required to make a server look "online" to forceUpdateServer. Only Send is
// called; we capture its argument so the test can verify the upgrade task is
// NOT dispatched for foreign IDs.
type fakeTaskStream struct {
	pb.NezhaService_RequestTaskServer
	sentTasks []*pb.Task
}

func (f *fakeTaskStream) Send(t *pb.Task) error {
	f.sentTasks = append(f.sentTasks, t)
	return nil
}

// setupServerOwnershipFixture seeds an in-memory DB with alice's server
// (UserID=100, ID=1). The returned stream is wired in so the server is
// "online" — i.e. exercises the path that previously returned permission
// denied for foreign callers (the actual leak channel).
func setupServerOwnershipFixture(t *testing.T) (stream *fakeTaskStream, reset func()) {
	t.Helper()
	if singleton.Localizer == nil {
		singleton.Localizer = i18n.NewLocalizer("en_US", "nezha", "translations", i18n.Translations)
	}
	originalDB := singleton.DB
	originalShared := singleton.ServerShared

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)
	assert.NoError(t, db.AutoMigrate(&model.Server{}))
	assert.NoError(t, db.Create(&model.Server{
		Common: model.Common{ID: 1, UserID: 100},
		Name:   "alice-online",
	}).Error)
	singleton.DB = db
	singleton.ServerShared = singleton.NewServerClass()

	alice, _ := singleton.ServerShared.Get(1)
	stream = &fakeTaskStream{}
	alice.SetTaskStream(stream)

	return stream, func() {
		singleton.DB = originalDB
		singleton.ServerShared = originalShared
	}
}

func runForceUpdate(t *testing.T, callerID uint64, ids []uint64) []byte {
	t.Helper()
	r := gin.New()
	r.Use(func(c *gin.Context) {
		setAuthUser(c, callerID, model.RoleMember)
		c.Next()
	})
	r.POST("/force-update/server", commonHandler(forceUpdateServer))

	body, _ := json.Marshal(ids)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/force-update/server", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w.Body.Bytes()
}

type forceUpdateBody struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
	Data    struct {
		Offline []uint64 `json:"offline"`
		Success []uint64 `json:"success"`
		Failure []uint64 `json:"failure"`
	} `json:"data"`
}

func decodeForceUpdate(t *testing.T, body []byte) forceUpdateBody {
	t.Helper()
	var resp forceUpdateBody
	assert.NoError(t, json.Unmarshal(body, &resp))
	return resp
}

// Core regression: bob submitting alice's online server ID must NOT produce
// a distinct response from bob submitting an unknown ID. The original code
// returned "permission denied" for the former and a structured success/Offline
// response for the latter — that delta is the enumeration oracle for server
// IDs and online state.
func TestForceUpdateServerOnlineForeignIDIndistinguishableFromUnknown(t *testing.T) {
	gin.SetMode(gin.TestMode)
	_, reset := setupServerOwnershipFixture(t)
	defer reset()

	const bobID = uint64(200)
	foreignResp := decodeForceUpdate(t, runForceUpdate(t, bobID, []uint64{1}))    // alice's online
	unknownResp := decodeForceUpdate(t, runForceUpdate(t, bobID, []uint64{9999})) // does not exist

	assert.Equal(t, foreignResp.Success, unknownResp.Success,
		"top-level success flag must not differ between foreign-online and unknown IDs")
	assert.Equal(t, foreignResp.Error, unknownResp.Error,
		"error string must not differ — distinct error reveals existence/state of foreign servers")
	assert.Equal(t, foreignResp.Data.Success, unknownResp.Data.Success)
	assert.Equal(t, foreignResp.Data.Failure, unknownResp.Data.Failure)
}

// Submitting a foreign online server must NOT actually trigger the upgrade
// task on it — that would be a write primitive on someone else's machine.
func TestForceUpdateServerForeignOnlineDoesNotDispatchUpgrade(t *testing.T) {
	gin.SetMode(gin.TestMode)
	stream, reset := setupServerOwnershipFixture(t)
	defer reset()

	_ = runForceUpdate(t, 200, []uint64{1}) // bob hits alice's online server
	assert.Empty(t, stream.sentTasks,
		"foreign server must not receive the upgrade task even when online")
}

// Sanity: owner submitting their own online server must still get the upgrade
// dispatched and a structured success response — the hardening must not
// regress the legitimate case.
func TestForceUpdateServerOwnerOnlineStillDispatches(t *testing.T) {
	gin.SetMode(gin.TestMode)
	stream, reset := setupServerOwnershipFixture(t)
	defer reset()

	resp := decodeForceUpdate(t, runForceUpdate(t, 100, []uint64{1})) // alice on her own server
	assert.True(t, resp.Success)
	assert.Equal(t, []uint64{1}, resp.Data.Success)
	assert.Empty(t, resp.Data.Offline)
	assert.Empty(t, resp.Data.Failure)
	assert.Len(t, stream.sentTasks, 1, "owner's own server must receive the upgrade task exactly once")
}

func setupServerDeleteFixture(t *testing.T) (stream *fakeTaskStream, reset func()) {
	t.Helper()
	if singleton.Localizer == nil {
		singleton.Localizer = i18n.NewLocalizer("en_US", "nezha", "translations", i18n.Translations)
	}
	originalDB := singleton.DB
	originalShared := singleton.ServerShared
	originalTransferShared := singleton.ServerTransferShared

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)
	assert.NoError(t, db.AutoMigrate(&model.Server{}, &model.ServerGroupServer{}, &model.Transfer{}, &model.DeletedServer{}, &model.ServerTransfer{}))
	assert.NoError(t, db.Create(&model.Server{
		Common: model.Common{ID: 7, UserID: 100},
		UUID:   "33333333-3333-3333-3333-333333333333",
		Name:   "delete-me",
	}).Error)

	singleton.DB = db
	singleton.ServerShared = singleton.NewServerClass()
	singleton.ServerTransferShared = singleton.NewServerTransferClass()

	server, _ := singleton.ServerShared.Get(7)
	stream = &fakeTaskStream{}
	server.SetTaskStream(stream)

	return stream, func() {
		if singleton.ServerTransferShared != nil {
			singleton.ServerTransferShared.Stop()
		}
		singleton.DB = originalDB
		singleton.ServerShared = originalShared
		singleton.ServerTransferShared = originalTransferShared
	}
}

func runBatchDeleteServer(t *testing.T, callerID uint64, ids []uint64) []byte {
	t.Helper()
	r := gin.New()
	r.Use(func(c *gin.Context) {
		setAuthUser(c, callerID, model.RoleMember)
		c.Next()
	})
	r.POST("/batch-delete/server", commonHandler(batchDeleteServer))

	body, _ := json.Marshal(ids)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/batch-delete/server", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w.Body.Bytes()
}

func TestBatchDeleteServerSendsDestroyTaskAndBlocksUUIDReuse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	stream, reset := setupServerDeleteFixture(t)
	defer reset()

	body := runBatchDeleteServer(t, 100, []uint64{7})
	var resp struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	assert.NoError(t, json.Unmarshal(body, &resp))
	assert.True(t, resp.Success, "delete response: %s", string(body))
	assert.Empty(t, resp.Error)

	assert.Len(t, stream.sentTasks, 1, "online agent must receive a destroy task before the dashboard record is removed")
	assert.Equal(t, uint64(model.TaskTypeDestroyAgent), stream.sentTasks[0].Type)

	var tombstone model.DeletedServer
	assert.NoError(t, singleton.DB.Where("uuid = ?", "33333333-3333-3333-3333-333333333333").First(&tombstone).Error)
	assert.Equal(t, uint64(7), tombstone.ServerID)
	assert.Equal(t, uint64(100), tombstone.UserID)

	_, ok := singleton.ServerShared.UUIDToID("33333333-3333-3333-3333-333333333333")
	assert.False(t, ok, "deleted UUID must be removed from the live cache")
}

func TestBatchDeleteServerUsesCommandCleanupForWindowsAgent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	stream, reset := setupServerDeleteFixture(t)
	defer reset()

	server, ok := singleton.ServerShared.Get(7)
	assert.True(t, ok)
	server.Host.Platform = "windows"

	body := runBatchDeleteServer(t, 100, []uint64{7})
	var resp struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	assert.NoError(t, json.Unmarshal(body, &resp))
	assert.True(t, resp.Success, "delete response: %s", string(body))
	assert.Empty(t, resp.Error)

	assert.Len(t, stream.sentTasks, 1)
	task := stream.sentTasks[0]
	assert.Equal(t, uint64(model.TaskTypeCommand), task.Type)
	assert.Less(t, len(task.Data), 7500, "windows command task must stay below cmd.exe command line limits")
	script := decodePowerShellCommandForTest(t, task.Data)
	assert.Contains(t, script, "cleanup-agent.ps1")
	assert.Contains(t, script, "sc.exe delete")
	assert.Contains(t, script, "C:/Program Files/agent")
	assert.Contains(t, script, "Invoke-CimMethod")
	assert.Contains(t, script, "Win32_Process")
	assert.Contains(t, script, "cleanup-agent.log")
	assert.Contains(t, script, "sc.exe failure")
	assert.NotContains(t, script, "Register-ScheduledTask")
	assert.NotContains(t, script, "schtasks.exe")
}

func TestBatchDeleteServerUsesCommandCleanupForGopsutilWindowsPlatform(t *testing.T) {
	gin.SetMode(gin.TestMode)
	stream, reset := setupServerDeleteFixture(t)
	defer reset()

	server, ok := singleton.ServerShared.Get(7)
	assert.True(t, ok)
	server.Host.Platform = "Microsoft Windows 11 Pro"

	body := runBatchDeleteServer(t, 100, []uint64{7})
	var resp struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	assert.NoError(t, json.Unmarshal(body, &resp))
	assert.True(t, resp.Success, "delete response: %s", string(body))
	assert.Empty(t, resp.Error)

	assert.Len(t, stream.sentTasks, 1)
	assert.Equal(t, uint64(model.TaskTypeCommand), stream.sentTasks[0].Type)
}

func decodePowerShellCommandForTest(t *testing.T, command string) string {
	t.Helper()

	const marker = "-EncodedCommand "
	idx := strings.Index(command, marker)
	assert.NotEqual(t, -1, idx, "command must use PowerShell EncodedCommand to avoid cmd.exe quote splitting")
	if idx == -1 {
		return ""
	}

	encoded := strings.TrimSpace(command[idx+len(marker):])
	raw, err := base64.StdEncoding.DecodeString(encoded)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(raw)%2)

	utf16Chars := make([]uint16, len(raw)/2)
	for i := range utf16Chars {
		utf16Chars[i] = uint16(raw[i*2]) | uint16(raw[i*2+1])<<8
	}
	return string(utf16.Decode(utf16Chars))
}

func TestBatchDeleteServerDeduplicatesDestroyTasks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	stream, reset := setupServerDeleteFixture(t)
	defer reset()

	body := runBatchDeleteServer(t, 100, []uint64{7, 7})
	var resp struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	assert.NoError(t, json.Unmarshal(body, &resp))
	assert.True(t, resp.Success, "delete response: %s", string(body))
	assert.Empty(t, resp.Error)
	assert.Len(t, stream.sentTasks, 1, "duplicate ids in one delete request must not send duplicate destroy tasks")
}
