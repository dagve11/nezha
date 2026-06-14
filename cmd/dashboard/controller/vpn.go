package controller

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/service/singleton"
)

const vpnSessionStreamInterval = 2 * time.Second
const vpnSessionStreamWriteTimeout = 10 * time.Second

type vpnSessionStreamFrame struct {
	Session *model.AgentVPNSession `json:"session"`
	Logs    []string               `json:"logs,omitempty"`
}

func listVPNPolicy(c *gin.Context) ([]*model.AgentVPNPolicy, error) {
	var policies []*model.AgentVPNPolicy
	if err := singleton.DB.Order("id ASC").Find(&policies).Error; err != nil {
		return nil, newGormError("%v", err)
	}
	return filterVPNPolicies(c, policies), nil
}

func createVPNPolicy(c *gin.Context) (uint64, error) {
	var form model.AgentVPNPolicyForm
	if err := c.ShouldBindJSON(&form); err != nil {
		return 0, err
	}
	if err := assertOwnsNotificationGroup(c, form.NotificationGroupID); err != nil {
		return 0, err
	}
	policy, err := singleton.VPNShared.SavePolicy(vpnActorFromContext(c), form)
	if err != nil {
		return 0, err
	}
	return policy.ID, nil
}

func updateVPNPolicy(c *gin.Context) (any, error) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		return nil, err
	}
	var form model.AgentVPNPolicyForm
	if err := c.ShouldBindJSON(&form); err != nil {
		return nil, err
	}
	if err := assertOwnsNotificationGroup(c, form.NotificationGroupID); err != nil {
		return nil, err
	}
	if _, err := singleton.VPNShared.UpdatePolicy(vpnActorFromContext(c), id, form); err != nil {
		return nil, err
	}
	return nil, nil
}

func batchDeleteVPNPolicy(c *gin.Context) (any, error) {
	var ids []uint64
	if err := c.ShouldBindJSON(&ids); err != nil {
		return nil, err
	}
	if err := singleton.VPNShared.DeletePolicies(vpnActorFromContext(c), ids); err != nil {
		return nil, err
	}
	return nil, nil
}

func prepareVPNPolicyCore(c *gin.Context) (any, error) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		return nil, err
	}
	if err := singleton.VPNShared.PreparePolicyCore(vpnActorFromContext(c), id); err != nil {
		return nil, err
	}
	return nil, nil
}

func cleanupVPNPolicyCore(c *gin.Context) (any, error) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		return nil, err
	}
	if err := singleton.VPNShared.CleanupPolicyCore(vpnActorFromContext(c), id); err != nil {
		return nil, err
	}
	return nil, nil
}

func statusVPNPolicy(c *gin.Context) (*model.AgentVPNPolicyStatusCheck, error) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		return nil, err
	}
	return singleton.VPNShared.CheckPolicyStatus(vpnActorFromContext(c), id)
}

func listVPNSession(c *gin.Context) ([]*model.AgentVPNSession, error) {
	var sessions []*model.AgentVPNSession
	if err := singleton.DB.Order("id DESC").Find(&sessions).Error; err != nil {
		return nil, newGormError("%v", err)
	}
	return filterVPNSessions(c, sessions), nil
}

func startVPNSession(c *gin.Context) (*model.AgentVPNSession, error) {
	var form model.AgentVPNSessionStartForm
	if err := c.ShouldBindJSON(&form); err != nil {
		return nil, err
	}
	return singleton.VPNShared.StartSession(vpnActorFromContext(c), form.PolicyID)
}

func stopVPNSession(c *gin.Context) (*model.AgentVPNSession, error) {
	sessionID := strings.TrimSpace(c.Param("id"))
	return singleton.VPNShared.StopSession(vpnActorFromContext(c), sessionID)
}

func deleteVPNSession(c *gin.Context) (any, error) {
	sessionID := strings.TrimSpace(c.Param("id"))
	if err := singleton.VPNShared.DeleteSession(vpnActorFromContext(c), sessionID); err != nil {
		return nil, err
	}
	return nil, nil
}

func restartVPNSession(c *gin.Context) (*model.AgentVPNSession, error) {
	sessionID := strings.TrimSpace(c.Param("id"))
	return singleton.VPNShared.RestartSession(vpnActorFromContext(c), sessionID)
}

func statusVPNSession(c *gin.Context) (*model.AgentVPNSession, error) {
	sessionID := strings.TrimSpace(c.Param("id"))
	return singleton.VPNShared.RefreshSessionStatus(vpnActorFromContext(c), sessionID)
}

func vpnSessionStream(c *gin.Context) (any, error) {
	sessionID := strings.TrimSpace(c.Param("id"))
	session, err := getPermittedVPNSession(c, sessionID)
	if err != nil {
		c.JSON(http.StatusForbidden, newErrorResponse(err))
		return nil, errNoop
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return nil, newWsError("%v", err)
	}
	defer conn.Close()

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			if _, _, err := conn.NextReader(); err != nil {
				return
			}
		}
	}()

	writeFrame := func(frame vpnSessionStreamFrame) error {
		if err := conn.SetWriteDeadline(time.Now().Add(vpnSessionStreamWriteTimeout)); err != nil {
			return err
		}
		return conn.WriteJSON(frame)
	}
	if err := writeFrame(vpnSessionFrameFromSession(session)); err != nil {
		return nil, newWsError("%v", err)
	}

	ticker := time.NewTicker(vpnSessionStreamInterval)
	defer ticker.Stop()
	ping := time.NewTicker(transferStreamPingInterval)
	defer ping.Stop()
	for {
		select {
		case <-closed:
			return nil, newWsError("")
		case <-ping.C:
			if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(vpnSessionStreamWriteTimeout)); err != nil {
				return nil, newWsError("%v", err)
			}
		case <-ticker.C:
			session, err := getPermittedVPNSession(c, sessionID)
			if err != nil {
				return nil, newWsError("%v", err)
			}
			if err := writeFrame(vpnSessionFrameFromSession(session)); err != nil {
				return nil, newWsError("%v", err)
			}
		}
	}
}

func listVPNAudit(c *gin.Context) ([]*model.AgentVPNAuditLog, error) {
	var audits []*model.AgentVPNAuditLog
	query := singleton.DB.Model(&model.AgentVPNAuditLog{})
	if action := strings.TrimSpace(c.Query("action")); action != "" {
		query = query.Where("action LIKE ?", "%"+action+"%")
	}
	switch strings.TrimSpace(c.Query("result")) {
	case "success":
		query = query.Where("success = ?", true)
	case "failure":
		query = query.Where("success = ?", false)
	}
	if userID, ok := parseVPNQueryUint(c.Query("user")); ok {
		query = query.Where("user_id = ?", userID)
	}
	if entryID, ok := parseVPNQueryUint(c.Query("entry")); ok {
		query = query.Where("entry_server_id = ?", entryID)
	}
	if exitID, ok := parseVPNQueryUint(c.Query("exit")); ok {
		query = query.Where("exit_server_id = ?", exitID)
	}
	if from, ok := parseVPNQueryTime(c.Query("from")); ok {
		query = query.Where("created_at >= ?", from)
	}
	if to, ok := parseVPNQueryTime(c.Query("to")); ok {
		query = query.Where("created_at <= ?", to)
	}
	if err := query.Order("id DESC").Find(&audits).Error; err != nil {
		return nil, newGormError("%v", err)
	}
	if callerIsAdmin(c) {
		return audits, nil
	}
	uid := getUid(c)
	out := audits[:0]
	for _, audit := range audits {
		if audit.UserID == uid && vpnServersHavePermission(c, audit.EntryServerID, audit.ExitServerID) {
			out = append(out, audit)
		}
	}
	return out, nil
}

func parseVPNQueryUint(value string) (uint64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	return parsed, err == nil
}

func parseVPNQueryTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func vpnActorFromContext(c *gin.Context) singleton.VPNActor {
	user, _ := c.MustGet(model.CtxKeyAuthorizedUser).(*model.User)
	return singleton.VPNActor{
		UserID: user.ID,
		Role:   user.Role,
	}
}

func filterVPNPolicies(c *gin.Context, policies []*model.AgentVPNPolicy) []*model.AgentVPNPolicy {
	if callerIsAdmin(c) {
		return policies
	}
	out := policies[:0]
	for _, policy := range policies {
		if vpnPolicyHasPermission(c, policy) {
			out = append(out, policy)
		}
	}
	return out
}

func filterVPNSessions(c *gin.Context, sessions []*model.AgentVPNSession) []*model.AgentVPNSession {
	if callerIsAdmin(c) {
		return sessions
	}
	out := sessions[:0]
	for _, session := range sessions {
		if vpnSessionHasPermission(c, session) {
			out = append(out, session)
		}
	}
	return out
}

func vpnPolicyHasPermission(c *gin.Context, policy *model.AgentVPNPolicy) bool {
	if callerIsAdmin(c) {
		return true
	}
	if policy == nil || !policy.HasPermission(c) {
		return false
	}
	return vpnServersHavePermission(c, policy.EntryServerID, policy.ExitServerID)
}

func vpnSessionHasPermission(c *gin.Context, session *model.AgentVPNSession) bool {
	if callerIsAdmin(c) {
		return true
	}
	if session == nil || !session.HasPermission(c) {
		return false
	}
	return vpnServersHavePermission(c, session.EntryServerID, session.ExitServerID)
}

func vpnServersHavePermission(c *gin.Context, entryServerID uint64, exitServerID uint64) bool {
	if callerIsAdmin(c) {
		return true
	}
	entry, ok := singleton.ServerShared.Get(entryServerID)
	if !ok || entry == nil || !entry.HasPermission(c) {
		return false
	}
	exit, ok := singleton.ServerShared.Get(exitServerID)
	return ok && exit != nil && exit.HasPermission(c)
}

func getPermittedVPNSession(c *gin.Context, sessionID string) (*model.AgentVPNSession, error) {
	var session model.AgentVPNSession
	if err := singleton.DB.Where("session_id = ?", sessionID).First(&session).Error; err != nil {
		return nil, err
	}
	if !vpnSessionHasPermission(c, &session) {
		return nil, singleton.Localizer.ErrorT("permission denied")
	}
	return &session, nil
}

func vpnSessionFrameFromSession(session *model.AgentVPNSession) vpnSessionStreamFrame {
	frame := vpnSessionStreamFrame{Session: session}
	if session == nil {
		return frame
	}
	if singleton.VPNShared != nil {
		frame.Logs = singleton.VPNShared.SessionLogs(session.SessionID)
	}
	if len(frame.Logs) == 0 && strings.TrimSpace(session.LastError) != "" {
		frame.Logs = []string{session.LastError}
	}
	return frame
}
