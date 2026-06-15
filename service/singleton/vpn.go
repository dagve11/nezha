package singleton

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/goccy/go-json"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/utils"
	pb "github.com/nezhahq/nezha/proto"
)

const (
	defaultVPNExpiresSeconds        = 24 * 60 * 60
	defaultVPNCoreDownloadBaseURL   = "https://github.com/dagve11/sb-core/releases/download/V1.0.0"
	defaultVPNCoreCNDownloadBaseURL = "https://gitee.com/AGZZY11/sb-core/releases/download/V1.0.0"
	defaultVPNCoreManifestURL       = defaultVPNCoreDownloadBaseURL + "/manifest.json"
	defaultVPNCoreCNManifestURL     = defaultVPNCoreCNDownloadBaseURL + "/manifest.json"
)

var (
	vpnSHA256HexPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	vpnANSISequence     = regexp.MustCompile(`(?:\x1b)?\[[0-9;]*m`)
	vpnLogTimestamp     = regexp.MustCompile(`^\[\d{2}:\d{2}:\d{2}\]\s`)
)

const defaultVPNRelayTrafficFlushInterval = 2 * time.Second
const vpnPolicyStatusCheckTimeout = 5 * time.Second
const vpnAgentDebugResultLimit = 30
const vpnSessionLogLimit = 50

var vpnLogTimeLocation = time.FixedZone("UTC+8", 8*60*60)

var (
	VPNShared *VPNClass

	VPNTokenGenerator = func() (string, error) {
		return utils.GenerateRandomString(32)
	}
	VPNIDGenerator = func(prefix string) (string, error) {
		id, err := utils.GenerateRandomString(24)
		if err != nil {
			return "", err
		}
		return prefix + id, nil
	}
	VPNNotificationSender = func(groupID uint64, message string, mute string) {
		if groupID == 0 || NotificationShared == nil {
			return
		}
		NotificationShared.SendNotification(groupID, message, mute)
	}
	VPNRelayCreator func(sessionID string, entryStreamID string, entryServerID uint64, exitStreamID string, exitServerID uint64)
	VPNRelayCloser  func(sessionID string)
)

func sendVPNNotification(groupID uint64, message string, mute string) {
	if groupID == 0 {
		return
	}
	VPNNotificationSender(groupID, message, mute)
}

type VPNActor struct {
	UserID uint64
	Role   model.Role
}

func (a VPNActor) IsAdmin() bool {
	return a.Role.IsAdmin()
}

type VPNClass struct {
	mu                sync.Mutex
	sessionTokens     map[string]string
	sessionPolicies   map[string]*model.AgentVPNPolicy
	sessionLogs       map[string][]string
	relayTraffic      map[string]vpnRelayTrafficSnapshot
	statusWaiters     map[string]chan vpnPolicyStatusAgentResult
	agentDebugSeq     uint64
	agentDebugResults []model.AgentVPNDebugResult

	relayTrafficFlushInterval time.Duration
}

type vpnRelayTrafficSnapshot struct {
	uploadBytes       uint64
	downloadBytes     uint64
	activeConnections uint32
	lastFlushAt       time.Time
}

type vpnPolicyStatusAgentResult struct {
	serverID uint64
	result   model.VPNControlResult
}

func StartVPNLifecycleJobs() error {
	if VPNShared == nil {
		return errors.New("vpn service is not initialized")
	}
	if err := VPNShared.RecoverActiveSessions(); err != nil {
		log.Printf("NEZHA>> VPN session recovery failed: %v", err)
	}
	if CronShared == nil {
		return errors.New("cron scheduler is not initialized")
	}
	_, err := CronShared.AddFunc("@every 30s", func() {
		if VPNShared == nil {
			return
		}
		if err := VPNShared.ExpireSessions(time.Now()); err != nil {
			log.Printf("NEZHA>> VPN session expiry scan failed: %v", err)
		}
	})
	return err
}

func NewVPNClass() *VPNClass {
	return &VPNClass{
		sessionTokens:   map[string]string{},
		sessionPolicies: map[string]*model.AgentVPNPolicy{},
		sessionLogs:     map[string][]string{},
		relayTraffic:    map[string]vpnRelayTrafficSnapshot{},
		statusWaiters:   map[string]chan vpnPolicyStatusAgentResult{},

		relayTrafficFlushInterval: defaultVPNRelayTrafficFlushInterval,
	}
}

func (v *VPNClass) SavePolicy(actor VPNActor, form model.AgentVPNPolicyForm) (*model.AgentVPNPolicy, error) {
	if err := v.validatePolicyForm(actor, form); err != nil {
		return nil, err
	}
	policy := vpnPolicyFromForm(actor.UserID, form)
	if err := DB.Create(policy).Error; err != nil {
		return nil, err
	}
	_ = v.writeAudit(actor, model.VPNAuditActionCreatePolicy, "", policy.EntryServerID, policy.ExitServerID, true, "policy created", vpnPolicyAuditDetail(policy))
	return policy, nil
}

func (v *VPNClass) UpdatePolicy(actor VPNActor, policyID uint64, form model.AgentVPNPolicyForm) (*model.AgentVPNPolicy, error) {
	var existing model.AgentVPNPolicy
	if err := DB.First(&existing, policyID).Error; err != nil {
		return nil, err
	}
	if !actor.IsAdmin() && existing.GetUserID() != actor.UserID {
		return nil, errors.New("permission denied")
	}
	if err := v.validatePolicyForm(actor, form); err != nil {
		return nil, err
	}
	updated := vpnPolicyFromForm(existing.GetUserID(), form)
	updated.ID = existing.ID
	updated.CreatedAt = existing.CreatedAt
	if err := DB.Save(updated).Error; err != nil {
		return nil, err
	}
	v.mu.Lock()
	for sessionID, policy := range v.sessionPolicies {
		if policy != nil && policy.ID == updated.ID {
			v.sessionPolicies[sessionID] = cloneVPNPolicy(updated)
		}
	}
	v.mu.Unlock()
	_ = v.writeAudit(actor, model.VPNAuditActionUpdatePolicy, "", updated.EntryServerID, updated.ExitServerID, true, "policy updated", vpnPolicyAuditDetail(updated))
	return updated, nil
}

func (v *VPNClass) DeletePolicies(actor VPNActor, policyIDs []uint64) error {
	policies := make([]*model.AgentVPNPolicy, 0, len(policyIDs))
	for _, policyID := range policyIDs {
		policy, err := v.getPolicyForActor(actor, policyID)
		if err != nil {
			return err
		}
		policies = append(policies, policy)
	}
	var activeSessionCount int64
	if err := DB.Model(&model.AgentVPNSession{}).
		Where("policy_id IN ? AND state IN ?", policyIDs, []string{
			model.VPNStatePending,
			model.VPNStateStarting,
			model.VPNStateRunning,
			model.VPNStateUnknown,
		}).
		Count(&activeSessionCount).Error; err != nil {
		return err
	}
	if activeSessionCount > 0 {
		return errors.New("vpn policy has active session, stop it before deleting")
	}
	if err := DB.Unscoped().Delete(&model.AgentVPNPolicy{}, "id in (?)", policyIDs).Error; err != nil {
		return err
	}
	for _, policy := range policies {
		_ = v.writeAudit(actor, model.VPNAuditActionDeletePolicy, "", policy.EntryServerID, policy.ExitServerID, true, "policy deleted", vpnPolicyAuditDetail(policy))
	}
	return nil
}

func (v *VPNClass) PreparePolicyCore(actor VPNActor, policyID uint64) error {
	return v.dispatchPolicyCoreControl(actor, policyID, model.VPNActionPrepare)
}

func (v *VPNClass) CleanupPolicyCore(actor VPNActor, policyID uint64) error {
	return v.dispatchPolicyCoreControl(actor, policyID, model.VPNActionCleanup)
}

func (v *VPNClass) PreparePolicyRules(actor VPNActor, policyID uint64) error {
	return v.dispatchPolicyCoreControl(actor, policyID, model.VPNActionRulesPrepare)
}

func (v *VPNClass) CleanupPolicyRules(actor VPNActor, policyID uint64) error {
	return v.dispatchPolicyCoreControl(actor, policyID, model.VPNActionRulesCleanup)
}

func (v *VPNClass) CheckPolicyStatus(actor VPNActor, policyID uint64) (*model.AgentVPNPolicyStatusCheck, error) {
	policy, err := v.getPolicyForActor(actor, policyID)
	if err != nil {
		return nil, err
	}
	if err := validateVPNPolicyRuntime(policy); err != nil {
		return nil, err
	}
	entry, err := v.getUsableServer(actor, policy.EntryServerID)
	if err != nil {
		return nil, err
	}
	exit, err := v.getUsableServer(actor, policy.ExitServerID)
	if err != nil {
		return nil, err
	}

	checkID, err := VPNIDGenerator("vpn_status_")
	if err != nil {
		return nil, err
	}
	expiresSeconds := policy.ExpiresSeconds
	if expiresSeconds == 0 {
		expiresSeconds = defaultVPNExpiresSeconds
	}
	session := &model.AgentVPNSession{
		Common: model.Common{
			ID:     policy.ID,
			UserID: policy.GetUserID(),
		},
		PolicyID:      policy.ID,
		EntryServerID: policy.EntryServerID,
		ExitServerID:  policy.ExitServerID,
		SessionID:     policyCoreSessionID(policy.ID),
		Mode:          policy.Mode,
		RelayMode:     model.VPNRelayModeDashboard,
		ExpiresAt:     time.Now().Add(time.Duration(expiresSeconds) * time.Second),
	}
	status := &model.AgentVPNPolicyStatusCheck{
		PolicyID:   policy.ID,
		PolicyName: policy.Name,
		CheckID:    checkID,
		CheckedAt:  time.Now(),
		Nodes: []model.AgentVPNPolicyNodeStatus{
			newVPNPolicyNodeStatus(model.VPNRoleEntry, entry),
			newVPNPolicyNodeStatus(model.VPNRoleExit, exit),
		},
	}
	nodes := map[string]*model.AgentVPNPolicyNodeStatus{
		model.VPNRoleEntry: &status.Nodes[0],
		model.VPNRoleExit:  &status.Nodes[1],
	}
	waitCh := make(chan vpnPolicyStatusAgentResult, 2)
	v.registerPolicyStatusWaiter(checkID, waitCh)
	defer v.unregisterPolicyStatusWaiter(checkID)

	pending := map[string]struct{}{}
	dispatchStatus := func(role string, server *model.Server) {
		node := nodes[role]
		if server == nil {
			node.LastError = fmt.Sprintf("%s server not found", role)
			return
		}
		if server.GetTaskStream() == nil {
			node.LastError = fmt.Sprintf("%s server %d is offline", role, server.ID)
			return
		}
		pending[role] = struct{}{}
		if err := v.sendPolicyStatusControl(server, session, policy, role, checkID); err != nil {
			delete(pending, role)
			node.LastError = err.Error()
		}
	}
	dispatchStatus(model.VPNRoleEntry, entry)
	dispatchStatus(model.VPNRoleExit, exit)
	if len(pending) == 0 {
		return status, nil
	}

	timer := time.NewTimer(vpnPolicyStatusCheckTimeout)
	defer timer.Stop()
	for len(pending) > 0 {
		select {
		case agentResult := <-waitCh:
			role := agentResult.result.Role
			node := nodes[role]
			if node == nil || node.ServerID != agentResult.serverID {
				continue
			}
			if _, ok := pending[role]; !ok {
				continue
			}
			updateVPNPolicyNodeStatus(node, agentResult.result)
			delete(pending, role)
		case <-timer.C:
			status.TimedOut = true
			for role := range pending {
				if node := nodes[role]; node != nil {
					node.LastError = "agent status check timed out"
				}
			}
			return status, nil
		}
	}
	return status, nil
}

func (v *VPNClass) dispatchPolicyCoreControl(actor VPNActor, policyID uint64, action string) error {
	policy, err := v.getPolicyForActor(actor, policyID)
	if err != nil {
		return err
	}
	if err := validateVPNPolicyRuntime(policy); err != nil {
		return err
	}
	entry, err := v.getUsableServer(actor, policy.EntryServerID)
	if err != nil {
		return err
	}
	exit, err := v.getUsableServer(actor, policy.ExitServerID)
	if err != nil {
		return err
	}
	if entry.GetTaskStream() == nil {
		return fmt.Errorf("entry server %d is offline", entry.ID)
	}
	if exit.GetTaskStream() == nil {
		return fmt.Errorf("exit server %d is offline", exit.ID)
	}

	expiresSeconds := policy.ExpiresSeconds
	if expiresSeconds == 0 {
		expiresSeconds = defaultVPNExpiresSeconds
	}
	session := &model.AgentVPNSession{
		Common: model.Common{
			ID:     policy.ID,
			UserID: policy.GetUserID(),
		},
		PolicyID:      policy.ID,
		EntryServerID: policy.EntryServerID,
		ExitServerID:  policy.ExitServerID,
		SessionID:     policyCoreSessionID(policy.ID),
		Mode:          policy.Mode,
		RelayMode:     model.VPNRelayModeDashboard,
		ExpiresAt:     time.Now().Add(time.Duration(expiresSeconds) * time.Second),
	}
	if err := v.sendControl(exit, session, policy, model.VPNRoleExit, action, ""); err != nil {
		return err
	}
	if err := v.sendControl(entry, session, policy, model.VPNRoleEntry, action, ""); err != nil {
		return err
	}
	return nil
}

func (v *VPNClass) StartSession(actor VPNActor, policyID uint64) (*model.AgentVPNSession, error) {
	policy, err := v.getPolicyForActor(actor, policyID)
	if err != nil {
		return nil, err
	}
	if err := validateVPNPolicyRuntime(policy); err != nil {
		v.recordStartSessionPreflightFailure(actor, policy, err, "policy_validation")
		return nil, err
	}
	entry, err := v.getUsableServer(actor, policy.EntryServerID)
	if err != nil {
		return nil, err
	}
	exit, err := v.getUsableServer(actor, policy.ExitServerID)
	if err != nil {
		return nil, err
	}
	if entry.GetTaskStream() == nil {
		err := fmt.Errorf("entry server %d is offline", entry.ID)
		v.recordStartSessionPreflightFailure(actor, policy, err, "")
		return nil, err
	}
	if exit.GetTaskStream() == nil {
		err := fmt.Errorf("exit server %d is offline", exit.ID)
		v.recordStartSessionPreflightFailure(actor, policy, err, "")
		return nil, err
	}
	if err := validateVPNServerCapabilities(policy, entry, exit); err != nil {
		v.recordStartSessionPreflightFailure(actor, policy, err, "")
		return nil, err
	}

	token, err := VPNTokenGenerator()
	if err != nil {
		v.recordStartSessionPreflightFailure(actor, policy, err, "token_generation")
		return nil, err
	}
	sessionID, err := VPNIDGenerator("vpn_")
	if err != nil {
		v.recordStartSessionPreflightFailure(actor, policy, err, "session_id_generation")
		return nil, err
	}
	entryStreamID, err := VPNIDGenerator("vpn_entry_")
	if err != nil {
		v.recordStartSessionPreflightFailure(actor, policy, err, "entry_stream_id_generation")
		return nil, err
	}
	exitStreamID, err := VPNIDGenerator("vpn_exit_")
	if err != nil {
		v.recordStartSessionPreflightFailure(actor, policy, err, "exit_stream_id_generation")
		return nil, err
	}

	now := time.Now()
	session := &model.AgentVPNSession{
		Common: model.Common{
			UserID: actor.UserID,
		},
		PolicyID:       policy.ID,
		EntryServerID:  policy.EntryServerID,
		ExitServerID:   policy.ExitServerID,
		SessionID:      sessionID,
		TokenHash:      hashVPNToken(token),
		Mode:           policy.Mode,
		RuleMode:       normalizeVPNRuleMode(policy.RuleMode),
		RelayMode:      model.VPNRelayModeDashboard,
		State:          model.VPNStateStarting,
		EntryState:     model.VPNStateStarting,
		ExitState:      model.VPNStateStarting,
		EntryStreamID:  entryStreamID,
		ExitStreamID:   exitStreamID,
		LocalHTTP:      policy.ListenHTTP,
		LocalSOCKS:     policy.ListenSOCKS,
		TunName:        policy.TunName,
		SetSystemProxy: policy.SetSystemProxy,
		StartedAt:      now,
		ExpiresAt:      now.Add(time.Duration(policy.ExpiresSeconds) * time.Second),
	}
	if err := DB.Create(session).Error; err != nil {
		return nil, err
	}
	v.appendControlLog(session.SessionID, "session created policy=%d mode=%s entry=%d exit=%d", policy.ID, policy.Mode, policy.EntryServerID, policy.ExitServerID)

	v.mu.Lock()
	v.sessionTokens[session.SessionID] = token
	v.sessionPolicies[session.SessionID] = cloneVPNPolicy(policy)
	v.mu.Unlock()

	if err := v.sendControl(exit, session, policy, model.VPNRoleExit, model.VPNActionPrepare, ""); err != nil {
		session.State = model.VPNStateFailed
		session.ExitState = model.VPNStateFailed
		session.LastError = err.Error()
		_ = DB.Save(session).Error
		v.finalizeVPNSessionRuntime(session.SessionID)
		_ = v.writeAudit(actor, model.VPNAuditActionStartSession, session.SessionID, policy.EntryServerID, policy.ExitServerID, false, err.Error(), map[string]string{
			"stage":              "exit_prepare_dispatch",
			"cleanup_dispatched": "false",
		})
		v.notifyFailure(policy, session, "")
		return session, err
	}
	if err := v.sendControl(entry, session, policy, model.VPNRoleEntry, model.VPNActionPrepare, ""); err != nil {
		session.State = model.VPNStateFailed
		session.EntryState = model.VPNStateFailed
		session.LastError = err.Error()
		cleanupErrors := v.dispatchSessionCleanupStops(session, policy)
		if len(cleanupErrors) > 0 {
			session.LastError += "; cleanup dispatch failed: " + strings.Join(cleanupErrors, "; ")
		}
		_ = DB.Save(session).Error
		v.finalizeVPNSessionRuntime(session.SessionID)
		auditDetail := map[string]string{
			"stage":              "entry_prepare_dispatch",
			"cleanup_dispatched": "true",
		}
		if len(cleanupErrors) > 0 {
			auditDetail["cleanup_errors"] = strings.Join(cleanupErrors, "; ")
		}
		_ = v.writeAudit(actor, model.VPNAuditActionStartSession, session.SessionID, policy.EntryServerID, policy.ExitServerID, false, session.LastError, auditDetail)
		v.notifyFailure(policy, session, "")
		return session, err
	}
	_ = v.writeAudit(actor, model.VPNAuditActionStartSession, session.SessionID, policy.EntryServerID, policy.ExitServerID, true, "core prepare dispatched", vpnPolicyAuditDetail(policy))
	return session, nil
}

func (v *VPNClass) HandleControlResult(reporterServerID uint64, result model.VPNControlResult) (*model.AgentVPNSession, error) {
	var session model.AgentVPNSession
	sessionID := strings.TrimSpace(result.SessionID)
	result.SessionID = sessionID
	if Conf != nil && Conf.VPNDebug {
		v.recordAgentDebugResult(reporterServerID, result)
	}
	v.deliverPolicyStatusResult(reporterServerID, result)
	if err := DB.Where("session_id = ?", sessionID).First(&session).Error; err != nil {
		if isPolicyCoreSessionID(sessionID) {
			return nil, nil
		}
		return nil, err
	}
	if !reporterMatchesVPNRole(reporterServerID, result.Role, &session) {
		v.appendControlLog(session.SessionID, "ignored unauthorized agent report server=%d role=%s action=%s state=%s", reporterServerID, result.Role, result.Action, result.State)
		return nil, fmt.Errorf("server %d is not authorized to report %s for session %s", reporterServerID, result.Role, session.SessionID)
	}

	v.appendControlLog(session.SessionID, "agent report server=%d role=%s action=%s state=%s%s", reporterServerID, result.Role, result.Action, result.State, vpnControlResultDetail(result))
	if len(result.Logs) > 0 {
		v.appendSessionLogs(session.SessionID, result.Logs)
	}
	policy, err := v.policyForSession(&session)
	if err != nil {
		if !canHandleVPNResultWithoutPolicy(result) {
			return nil, err
		}
		policy = v.fallbackVPNPolicyForLostSession(&session)
	}
	if isVPNTerminalState(session.State) {
		v.recordLateAgentCleanupResult(policy, &session, result)
		return &session, nil
	}
	if result.Action == model.VPNActionControl {
		return v.handleRuntimeControlResult(policy, &session, result)
	}

	wasRunning := session.State == model.VPNStateRunning
	updateSessionFromVPNResult(&session, result)

	if result.State == model.VPNStateFailed {
		session.State = model.VPNStateFailed
		if session.LastError == "" {
			session.LastError = result.LastError
		}
		v.appendControlLog(session.SessionID, "session failed by %s agent: %s", result.Role, firstNonEmptyString(session.LastError, result.LastError, "unknown error"))
		cleanupDispatched := false
		cleanupErrors := make([]string, 0, 2)
		if shouldDispatchVPNFailureCleanup(wasRunning, &session, result) {
			cleanupErrors = v.dispatchSessionCleanupStops(&session, policy)
			cleanupDispatched = true
		}
		if len(cleanupErrors) > 0 {
			session.LastError += "; cleanup dispatch failed: " + strings.Join(cleanupErrors, "; ")
		}
		if err := DB.Save(&session).Error; err != nil {
			return nil, err
		}
		auditAction := vpnLifecycleFailureAuditAction(result.Action)
		agentCleanupLogs := vpnAgentCleanupLogSummary(result.Logs)
		auditDetail := vpnFailedResultAuditDetail(result, cleanupDispatched, cleanupErrors)
		addVPNAuditAgentCleanupDetail(auditDetail, agentCleanupLogs)
		if wasRunning {
			auditAction = model.VPNAuditActionStatus
			auditDetail = vpnFailedRuntimeAuditDetail(result, cleanupDispatched, cleanupErrors)
			addVPNAuditAgentCleanupDetail(auditDetail, agentCleanupLogs)
		}
		_ = v.writeAudit(VPNActor{UserID: session.GetUserID(), Role: model.RoleAdmin}, auditAction, session.SessionID, session.EntryServerID, session.ExitServerID, false, session.LastError, auditDetail)
		v.finalizeVPNSessionRuntime(session.SessionID)
		if wasRunning {
			v.notifyRuntimeFailure(policy, &session, cleanupErrors, agentCleanupLogs)
		} else {
			v.notifyLifecycleFailure(policy, &session, result.Action, agentCleanupLogs)
		}
		return &session, nil
	}

	if result.Action == model.VPNActionPrepare && result.State == model.VPNStatePrepared {
		if session.EntryState == model.VPNStatePrepared && session.ExitState == model.VPNStatePrepared {
			return v.startPreparedVPNSession(&session, policy, model.VPNActionStart)
		}
		v.appendControlLog(session.SessionID, "core prepared on %s agent; waiting for peer", result.Role)
		if err := DB.Save(&session).Error; err != nil {
			return nil, err
		}
		return &session, nil
	}

	if result.State == model.VPNStateStopped || (result.Action == model.VPNActionStop && result.State == "") {
		now := time.Now()
		session.State = model.VPNStateStopped
		session.EntryState = model.VPNStateStopped
		session.ExitState = model.VPNStateStopped
		if result.StoppedAtUnix > 0 {
			stoppedAt := time.Unix(result.StoppedAtUnix, 0)
			session.StoppedAt = &stoppedAt
		} else {
			session.StoppedAt = &now
		}
		if session.LastError == "" {
			session.LastError = result.LastError
		}
		v.appendControlLog(session.SessionID, "session stopped by %s agent", result.Role)
		if err := DB.Save(&session).Error; err != nil {
			return nil, err
		}
		v.finalizeVPNSessionRuntime(session.SessionID)
		auditDetail := map[string]string{
			"role": result.Role,
		}
		agentCleanupLogs := vpnAgentCleanupLogSummary(result.Logs)
		addVPNAuditAgentCleanupDetail(auditDetail, agentCleanupLogs)
		_ = v.writeAudit(VPNActor{UserID: session.GetUserID(), Role: model.RoleAdmin}, model.VPNAuditActionStopSession, session.SessionID, session.EntryServerID, session.ExitServerID, true, "session stopped by agent", auditDetail)
		message := vpnNotificationBase("[Agent VPN] 已停止", policy, &session, "")
		if agentCleanupLogs != "" {
			message += "\nAgent 清理日志: " + agentCleanupLogs
		}
		sendVPNNotification(policy.NotificationGroupID, message, "")
		return &session, nil
	}

	if (result.Action == model.VPNActionStart || result.Action == model.VPNActionRestart) && result.Role == model.VPNRoleExit && result.State == model.VPNStateRunning && session.EntryState == model.VPNStatePending {
		entry, ok := ServerShared.Get(session.EntryServerID)
		if !ok || entry.GetTaskStream() == nil {
			session.State = model.VPNStateFailed
			session.EntryState = model.VPNStateFailed
			session.LastError = fmt.Sprintf("entry server %d is offline", session.EntryServerID)
			v.appendControlLog(session.SessionID, "entry start blocked after exit ready: %s", session.LastError)
			if err := DB.Save(&session).Error; err != nil {
				return nil, err
			}
			cleanupErrors := v.dispatchSessionCleanupStops(&session, policy)
			if len(cleanupErrors) > 0 {
				session.LastError += "; cleanup dispatch failed: " + strings.Join(cleanupErrors, "; ")
				_ = DB.Save(&session).Error
			}
			auditDetail := map[string]string{
				"stage":              vpnLifecycleFailureStage(result.Action, "entry_offline_after_exit_running"),
				"cleanup_dispatched": "true",
			}
			if len(cleanupErrors) > 0 {
				auditDetail["cleanup_errors"] = strings.Join(cleanupErrors, "; ")
			}
			_ = v.writeAudit(VPNActor{UserID: session.GetUserID(), Role: model.RoleAdmin}, vpnLifecycleFailureAuditAction(result.Action), session.SessionID, session.EntryServerID, session.ExitServerID, false, session.LastError, auditDetail)
			v.finalizeVPNSessionRuntime(session.SessionID)
			v.notifyLifecycleFailure(policy, &session, result.Action, "")
			return &session, errors.New(session.LastError)
		}
		session.EntryState = model.VPNStateStarting
		if err := DB.Save(&session).Error; err != nil {
			return nil, err
		}
		token, err := v.tokenForSession(&session)
		if err != nil {
			session.State = model.VPNStateFailed
			session.EntryState = model.VPNStateFailed
			session.LastError = err.Error()
			v.appendControlLog(session.SessionID, "entry start blocked after exit ready: %s", session.LastError)
			_ = DB.Save(&session).Error
			cleanupErrors := v.dispatchSessionCleanupStops(&session, policy)
			if len(cleanupErrors) > 0 {
				session.LastError += "; cleanup dispatch failed: " + strings.Join(cleanupErrors, "; ")
				_ = DB.Save(&session).Error
			}
			auditDetail := map[string]string{
				"stage":              vpnLifecycleFailureStage(result.Action, "entry_token_missing_after_exit_running"),
				"cleanup_dispatched": "true",
			}
			if len(cleanupErrors) > 0 {
				auditDetail["cleanup_errors"] = strings.Join(cleanupErrors, "; ")
			}
			_ = v.writeAudit(VPNActor{UserID: session.GetUserID(), Role: model.RoleAdmin}, vpnLifecycleFailureAuditAction(result.Action), session.SessionID, session.EntryServerID, session.ExitServerID, false, session.LastError, auditDetail)
			v.finalizeVPNSessionRuntime(session.SessionID)
			v.notifyLifecycleFailure(policy, &session, result.Action, "")
			return &session, err
		}
		if err := v.sendControl(entry, &session, policy, model.VPNRoleEntry, result.Action, token); err != nil {
			session.State = model.VPNStateFailed
			session.EntryState = model.VPNStateFailed
			session.LastError = err.Error()
			v.appendControlLog(session.SessionID, "entry start dispatch failed after exit ready: %s", session.LastError)
			_ = DB.Save(&session).Error
			cleanupErrors := v.dispatchSessionCleanupStops(&session, policy)
			if len(cleanupErrors) > 0 {
				session.LastError += "; cleanup dispatch failed: " + strings.Join(cleanupErrors, "; ")
				_ = DB.Save(&session).Error
			}
			auditDetail := map[string]string{
				"stage":              vpnLifecycleFailureStage(result.Action, "entry_start_dispatch"),
				"cleanup_dispatched": "true",
			}
			if len(cleanupErrors) > 0 {
				auditDetail["cleanup_errors"] = strings.Join(cleanupErrors, "; ")
			}
			_ = v.writeAudit(VPNActor{UserID: session.GetUserID(), Role: model.RoleAdmin}, vpnLifecycleFailureAuditAction(result.Action), session.SessionID, session.EntryServerID, session.ExitServerID, false, session.LastError, auditDetail)
			v.finalizeVPNSessionRuntime(session.SessionID)
			v.notifyLifecycleFailure(policy, &session, result.Action, "")
			return &session, err
		}
		return &session, nil
	}

	if session.EntryState == model.VPNStateRunning && session.ExitState == model.VPNStateRunning {
		if session.State != model.VPNStateRunning {
			session.State = model.VPNStateRunning
			if err := DB.Save(&session).Error; err != nil {
				return nil, err
			}
			if result.Action == model.VPNActionRestart {
				v.appendControlLog(session.SessionID, "session restarted; entry and exit agents are running")
				_ = v.writeAudit(VPNActor{UserID: session.GetUserID(), Role: model.RoleAdmin}, model.VPNAuditActionRestart, session.SessionID, session.EntryServerID, session.ExitServerID, true, "session restarted", vpnStartSuccessAuditDetail(policy, v.SessionLogs(session.SessionID)))
				v.notifyRestarted(policy, &session)
			} else if result.Action == model.VPNActionStart {
				v.appendControlLog(session.SessionID, "session started; entry and exit agents are running")
				_ = v.writeAudit(VPNActor{UserID: session.GetUserID(), Role: model.RoleAdmin}, model.VPNAuditActionStartSession, session.SessionID, session.EntryServerID, session.ExitServerID, true, "session started", vpnStartSuccessAuditDetail(policy, v.SessionLogs(session.SessionID)))
				v.notifyStarted(policy, &session)
			}
		} else if err := DB.Save(&session).Error; err != nil {
			return nil, err
		}
		return &session, nil
	}

	if err := DB.Save(&session).Error; err != nil {
		return nil, err
	}
	return &session, nil
}

func (v *VPNClass) AgentDebugResults(actor VPNActor, limit int) []model.AgentVPNDebugResult {
	if Conf == nil || !Conf.VPNDebug {
		return []model.AgentVPNDebugResult{}
	}
	if limit <= 0 || limit > vpnAgentDebugResultLimit {
		limit = vpnAgentDebugResultLimit
	}
	v.mu.Lock()
	copied := make([]model.AgentVPNDebugResult, len(v.agentDebugResults))
	copy(copied, v.agentDebugResults)
	v.mu.Unlock()

	results := make([]model.AgentVPNDebugResult, 0, limit)
	for i := len(copied) - 1; i >= 0 && len(results) < limit; i-- {
		entry := copied[i]
		if !actor.IsAdmin() && !actorCanUseVPNServer(actor, entry.ReporterServerID) {
			continue
		}
		if len(entry.Result.Logs) > 0 {
			entry.Result.Logs = append([]string(nil), entry.Result.Logs...)
		}
		results = append(results, entry)
	}
	return results
}

func (v *VPNClass) ClearAgentDebugResults() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.agentDebugResults = nil
}

func (v *VPNClass) recordAgentDebugResult(reporterServerID uint64, result model.VPNControlResult) {
	copied := result
	if len(result.Logs) > 0 {
		logs := result.Logs
		if len(logs) > vpnAgentDebugResultLimit {
			logs = logs[len(logs)-vpnAgentDebugResultLimit:]
		}
		copied.Logs = append([]string(nil), logs...)
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	v.agentDebugSeq++
	entry := model.AgentVPNDebugResult{
		ID:                 v.agentDebugSeq,
		ReportedAt:         time.Now(),
		ReporterServerID:   reporterServerID,
		ReporterServerName: serverName(reporterServerID),
		SessionID:          copied.SessionID,
		Action:             copied.Action,
		Role:               copied.Role,
		State:              copied.State,
		LastError:          copied.LastError,
		Result:             copied,
	}
	v.agentDebugResults = append(v.agentDebugResults, entry)
	if len(v.agentDebugResults) > vpnAgentDebugResultLimit {
		v.agentDebugResults = append([]model.AgentVPNDebugResult(nil), v.agentDebugResults[len(v.agentDebugResults)-vpnAgentDebugResultLimit:]...)
	}
}

func (v *VPNClass) StopSession(actor VPNActor, sessionID string) (*model.AgentVPNSession, error) {
	var session model.AgentVPNSession
	if err := DB.Where("session_id = ?", strings.TrimSpace(sessionID)).First(&session).Error; err != nil {
		return nil, err
	}
	if !actorCanUseVPNSession(actor, &session) {
		return nil, errors.New("permission denied")
	}
	policy, err := v.policyForSession(&session)
	if err != nil {
		policy = v.fallbackVPNPolicyForLostSession(&session)
	}
	token, err := v.tokenForSession(&session)
	if err != nil {
		token = ""
	}

	stopErrors := make([]string, 0, 2)
	if entry, ok := ServerShared.Get(session.EntryServerID); ok && entry.GetTaskStream() != nil {
		if err := v.sendControl(entry, &session, policy, model.VPNRoleEntry, model.VPNActionStop, token); err != nil {
			stopErrors = append(stopErrors, "entry: "+err.Error())
			log.Printf("NEZHA>> VPN manual stop dispatch failed: session=%s role=entry err=%v", session.SessionID, err)
		}
	} else {
		v.appendControlLog(session.SessionID, "skip stop request to entry agent server=%d: offline", session.EntryServerID)
	}
	if exit, ok := ServerShared.Get(session.ExitServerID); ok && exit.GetTaskStream() != nil {
		if err := v.sendControl(exit, &session, policy, model.VPNRoleExit, model.VPNActionStop, token); err != nil {
			stopErrors = append(stopErrors, "exit: "+err.Error())
			log.Printf("NEZHA>> VPN manual stop dispatch failed: session=%s role=exit err=%v", session.SessionID, err)
		}
	} else {
		v.appendControlLog(session.SessionID, "skip stop request to exit agent server=%d: offline", session.ExitServerID)
	}

	now := time.Now()
	session.State = model.VPNStateStopped
	session.EntryState = model.VPNStateStopped
	session.ExitState = model.VPNStateStopped
	if len(stopErrors) > 0 {
		session.LastError = "cleanup dispatch failed: " + strings.Join(stopErrors, "; ")
	}
	session.StoppedAt = &now
	if len(stopErrors) > 0 {
		v.appendControlLog(session.SessionID, "manual stop completed with cleanup dispatch errors: %s", strings.Join(stopErrors, "; "))
	} else {
		v.appendControlLog(session.SessionID, "manual stop completed; session marked stopped")
	}
	if err := DB.Save(&session).Error; err != nil {
		return nil, err
	}
	v.finalizeVPNSessionRuntime(session.SessionID)
	detail := map[string]string(nil)
	if len(stopErrors) > 0 {
		detail = map[string]string{
			"cleanup_errors": strings.Join(stopErrors, "; "),
		}
	}
	_ = v.writeAudit(actor, model.VPNAuditActionStopSession, session.SessionID, session.EntryServerID, session.ExitServerID, true, "session stopped", detail)
	message := vpnNotificationBase("[Agent VPN] 已停止", policy, &session, "")
	if len(stopErrors) > 0 {
		message += "\n清理下发失败: " + strings.Join(stopErrors, "; ")
	}
	sendVPNNotification(policy.NotificationGroupID, message, "")
	return &session, nil
}

func (v *VPNClass) DeleteSession(actor VPNActor, sessionID string) error {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return errors.New("session_id is required")
	}
	var session model.AgentVPNSession
	if err := DB.Where("session_id = ?", sessionID).First(&session).Error; err != nil {
		return err
	}
	if !actorCanUseVPNSession(actor, &session) {
		return errors.New("permission denied")
	}

	if !isVPNTerminalState(session.State) {
		stopped, err := v.StopSession(actor, sessionID)
		if err != nil {
			return err
		}
		if stopped != nil {
			session = *stopped
		}
	} else {
		policy, err := v.policyForSession(&session)
		if err != nil {
			policy = v.fallbackVPNPolicyForLostSession(&session)
		}
		cleanupErrors := v.dispatchSessionCleanupStops(&session, policy)
		if len(cleanupErrors) > 0 {
			v.appendControlLog(session.SessionID, "delete cleanup stop completed with dispatch errors: %s", strings.Join(cleanupErrors, "; "))
		} else {
			v.appendControlLog(session.SessionID, "delete cleanup stop dispatched for stopped session")
		}
	}

	v.forgetVPNSessionRuntime(sessionID)
	if err := DB.Delete(&session).Error; err != nil {
		return err
	}
	_ = v.writeAudit(actor, model.VPNAuditActionDeleteSession, session.SessionID, session.EntryServerID, session.ExitServerID, true, "session deleted", nil)
	return nil
}

func (v *VPNClass) RestartSession(actor VPNActor, sessionID string) (*model.AgentVPNSession, error) {
	var session model.AgentVPNSession
	if err := DB.Where("session_id = ?", strings.TrimSpace(sessionID)).First(&session).Error; err != nil {
		return nil, err
	}
	if !actorCanUseVPNSession(actor, &session) {
		return nil, errors.New("permission denied")
	}
	policy, err := v.policyForSession(&session)
	if err != nil {
		policy = v.fallbackVPNPolicyForLostSession(&session)
	}
	if err := v.restartExistingSessionWithAction(actor, &session, policy, model.VPNActionRestart); err != nil {
		return &session, err
	}
	return &session, nil
}

func (v *VPNClass) ControlSession(actor VPNActor, sessionID string, form model.AgentVPNSessionControlForm) (*model.AgentVPNSession, error) {
	var session model.AgentVPNSession
	if err := DB.Where("session_id = ?", strings.TrimSpace(sessionID)).First(&session).Error; err != nil {
		return nil, err
	}
	if !actorCanUseVPNSession(actor, &session) {
		return nil, errors.New("permission denied")
	}
	policy, err := v.policyForSession(&session)
	if err != nil {
		policy = v.fallbackVPNPolicyForLostSession(&session)
	}
	policy = cloneVPNPolicy(policy)
	if err := validateVPNMode(form.Mode); err != nil {
		return &session, err
	}
	if err := validateVPNRuleMode(form.RuleMode); err != nil {
		return &session, err
	}
	if strings.TrimSpace(form.Mode) != "" {
		policy.Mode = normalizeVPNMode(form.Mode)
	}
	if strings.TrimSpace(form.RuleMode) != "" {
		policy.RuleMode = normalizeVPNRuleMode(form.RuleMode)
	}
	policy.SetSystemProxy = policy.Mode == model.VPNModeSystemProxy && form.SetSystemProxy
	if err := validateVPNPolicyRuntime(policy); err != nil {
		return &session, err
	}
	entry, err := v.getUsableServer(actor, session.EntryServerID)
	if err != nil {
		return &session, err
	}
	exit, err := v.getUsableServer(actor, session.ExitServerID)
	if err != nil {
		return &session, err
	}
	if err := validateVPNServerCapabilities(policy, entry, exit); err != nil {
		return &session, err
	}
	if session.State == model.VPNStateRunning && !vpnRuntimeModesCompatible(session.Mode, policy.Mode) {
		return &session, fmt.Errorf("changing VPN runtime from %s to %s requires restarting the session", normalizeVPNMode(session.Mode), normalizeVPNMode(policy.Mode))
	}

	session.Mode = policy.Mode
	session.RuleMode = normalizeVPNRuleMode(policy.RuleMode)
	session.SetSystemProxy = policy.SetSystemProxy
	session.ControlOverride = true
	session.LocalHTTP = policy.ListenHTTP
	session.LocalSOCKS = policy.ListenSOCKS
	session.TunName = policy.TunName
	session.LastError = ""
	if err := DB.Save(&session).Error; err != nil {
		return nil, err
	}
	v.appendControlLog(session.SessionID, "session controls updated mode=%s rule_mode=%s set_system_proxy=%t", session.Mode, session.RuleMode, session.SetSystemProxy)
	v.mu.Lock()
	v.sessionPolicies[session.SessionID] = cloneVPNPolicy(policy)
	v.mu.Unlock()

	detail := vpnSessionControlAuditDetail(policy)
	if isVPNTerminalState(session.State) {
		_ = v.writeAudit(actor, model.VPNAuditActionControl, session.SessionID, session.EntryServerID, session.ExitServerID, true, "session controls saved", detail)
		return &session, nil
	}
	if session.State != model.VPNStateRunning {
		_ = v.writeAudit(actor, model.VPNAuditActionControl, session.SessionID, session.EntryServerID, session.ExitServerID, true, "session controls saved", detail)
		return &session, nil
	}
	if err := v.applyRunningSessionControls(&session, policy); err != nil {
		_ = v.writeAudit(actor, model.VPNAuditActionControl, session.SessionID, session.EntryServerID, session.ExitServerID, false, err.Error(), detail)
		return &session, err
	}
	_ = v.writeAudit(actor, model.VPNAuditActionControl, session.SessionID, session.EntryServerID, session.ExitServerID, true, "session controls dispatched", detail)
	return &session, nil
}

func (v *VPNClass) applyRunningSessionControls(session *model.AgentVPNSession, policy *model.AgentVPNPolicy) error {
	if session == nil || policy == nil {
		return errors.New("vpn session and policy are required")
	}
	entry, ok := ServerShared.Get(session.EntryServerID)
	if !ok || entry == nil || entry.GetTaskStream() == nil {
		return fmt.Errorf("entry server %d is offline", session.EntryServerID)
	}
	v.appendControlLog(session.SessionID, "applying runtime controls without restarting session")
	return v.sendControl(entry, session, policy, model.VPNRoleEntry, model.VPNActionControl, "")
}

func (v *VPNClass) handleRuntimeControlResult(policy *model.AgentVPNPolicy, session *model.AgentVPNSession, result model.VPNControlResult) (*model.AgentVPNSession, error) {
	if session == nil {
		return nil, errors.New("vpn session is required")
	}
	detail := vpnSessionControlAuditDetail(policy)
	if detail == nil {
		detail = map[string]string{}
	}
	detail["role"] = result.Role
	detail["result_action"] = result.Action
	if result.State == model.VPNStateFailed {
		session.LastError = firstNonEmptyString(result.LastError, "runtime control failed")
		v.appendControlLog(session.SessionID, "session controls failed by %s agent: %s", result.Role, session.LastError)
		if err := DB.Save(session).Error; err != nil {
			return nil, err
		}
		_ = v.writeAudit(VPNActor{UserID: session.GetUserID(), Role: model.RoleAdmin}, model.VPNAuditActionControl, session.SessionID, session.EntryServerID, session.ExitServerID, false, session.LastError, detail)
		return session, nil
	}
	if result.State != "" {
		updateSessionFromVPNResult(session, result)
	}
	if session.State != model.VPNStateRunning {
		session.State = model.VPNStateRunning
	}
	session.LastError = ""
	v.appendControlLog(session.SessionID, "session controls applied by %s agent", result.Role)
	if err := DB.Save(session).Error; err != nil {
		return nil, err
	}
	_ = v.writeAudit(VPNActor{UserID: session.GetUserID(), Role: model.RoleAdmin}, model.VPNAuditActionControl, session.SessionID, session.EntryServerID, session.ExitServerID, true, "session controls applied", detail)
	return session, nil
}

func (v *VPNClass) RefreshSessionStatus(actor VPNActor, sessionID string) (*model.AgentVPNSession, error) {
	var session model.AgentVPNSession
	if err := DB.Where("session_id = ?", strings.TrimSpace(sessionID)).First(&session).Error; err != nil {
		return nil, err
	}
	if !actorCanUseVPNSession(actor, &session) {
		return nil, errors.New("permission denied")
	}
	policy, err := v.policyForSession(&session)
	if err != nil {
		policy = v.fallbackVPNPolicyForLostSession(&session)
	}
	v.appendControlLog(session.SessionID, "status query requested")
	if err := v.querySessionStatus(&session, policy, session.EntryServerID, model.VPNRoleEntry); err != nil {
		v.appendControlLog(session.SessionID, "status query failed for entry agent: %v", err)
		_ = v.writeAudit(actor, model.VPNAuditActionStatus, session.SessionID, session.EntryServerID, session.ExitServerID, false, err.Error(), map[string]string{
			"role": model.VPNRoleEntry,
		})
		return &session, err
	}
	if err := v.querySessionStatus(&session, policy, session.ExitServerID, model.VPNRoleExit); err != nil {
		v.appendControlLog(session.SessionID, "status query failed for exit agent: %v", err)
		_ = v.writeAudit(actor, model.VPNAuditActionStatus, session.SessionID, session.EntryServerID, session.ExitServerID, false, err.Error(), map[string]string{
			"role": model.VPNRoleExit,
		})
		return &session, err
	}
	v.appendControlLog(session.SessionID, "status query dispatched; waiting for agent reports")
	_ = v.writeAudit(actor, model.VPNAuditActionStatus, session.SessionID, session.EntryServerID, session.ExitServerID, true, "status query dispatched", nil)
	return &session, nil
}

func (v *VPNClass) HandleRelayTraffic(sessionID string, uploadBytes uint64, downloadBytes uint64, activeConnections uint32) (bool, string) {
	session, policy, err := v.sessionAndPolicyByID(sessionID)
	if err != nil {
		return false, ""
	}
	session.UploadBytes = uploadBytes
	session.DownloadBytes = downloadBytes
	session.ActiveConnections = activeConnections

	if exceeded, reason := vpnTrafficLimitExceeded(policy, uploadBytes, downloadBytes); exceeded {
		v.stopSessionForRelayLimit(session, policy, reason, "traffic limit exceeded", "已因流量超限停止", describeVPNTrafficLimit(policy), fmt.Sprintf("上传 %d B / 下载 %d B", uploadBytes, downloadBytes), map[string]string{
			"reason":         reason,
			"upload_bytes":   fmt.Sprint(uploadBytes),
			"download_bytes": fmt.Sprint(downloadBytes),
		})
		return true, reason
	}
	if exceeded, reason := vpnConnectionLimitExceeded(policy, activeConnections); exceeded {
		v.stopSessionForRelayLimit(session, policy, reason, "connection limit exceeded", "已因连接数超限停止", describeVPNConnectionLimit(policy), fmt.Sprintf("连接数 %d", activeConnections), map[string]string{
			"reason":             reason,
			"active_connections": fmt.Sprint(activeConnections),
			"max_connections":    fmt.Sprint(policy.MaxConnections),
		})
		return true, reason
	}

	v.recordRelayTraffic(sessionID, uploadBytes, downloadBytes, activeConnections)
	return false, ""
}

func (v *VPNClass) stopSessionForRelayLimit(session *model.AgentVPNSession, policy *model.AgentVPNPolicy, reason string, auditMessage string, notificationTitle string, limitDescription string, actualDescription string, detail map[string]string) {
	now := time.Now()
	session.State = model.VPNStateStopped
	session.EntryState = model.VPNStateStopped
	session.ExitState = model.VPNStateStopped
	session.StoppedAt = &now
	session.LastError = reason
	cleanupErrors := v.dispatchSessionCleanupStops(session, policy)
	if len(cleanupErrors) > 0 {
		session.LastError += "; cleanup dispatch failed: " + strings.Join(cleanupErrors, "; ")
	}
	_ = DB.Save(session).Error
	v.finalizeVPNSessionRuntime(session.SessionID)
	if detail == nil {
		detail = map[string]string{"reason": reason}
	}
	if len(cleanupErrors) > 0 {
		detail["cleanup_errors"] = strings.Join(cleanupErrors, "; ")
	}
	_ = v.writeAudit(VPNActor{UserID: session.GetUserID(), Role: model.RoleAdmin}, model.VPNAuditActionStopSession, session.SessionID, session.EntryServerID, session.ExitServerID, true, auditMessage, detail)
	message := vpnNotificationBase("[Agent VPN] "+notificationTitle, policy, session, reason)
	message += "\n限制: " + limitDescription
	message += "\n实际: " + actualDescription
	if len(cleanupErrors) > 0 {
		message += "\n清理下发失败: " + strings.Join(cleanupErrors, "; ")
	}
	sendVPNNotification(policy.NotificationGroupID, message, "")
}

func (v *VPNClass) HandleRelayEvent(sessionID string, event string, detail string) {
	sessionID = strings.TrimSpace(sessionID)
	event = strings.TrimSpace(event)
	if sessionID == "" || event == "" {
		return
	}
	line := "[dashboard] " + event
	if detail = strings.TrimSpace(detail); detail != "" {
		line += ": " + detail
	}
	v.appendSessionLogs(sessionID, []string{line})
}

func (v *VPNClass) HandleRelayClosed(sessionID string, uploadBytes uint64, downloadBytes uint64, closeErr error) {
	v.recordRelayTraffic(sessionID, uploadBytes, downloadBytes, 0)
	v.FlushRelayTraffic(sessionID)
	session, policy, err := v.sessionAndPolicyByID(sessionID)
	if err != nil {
		return
	}
	session.UploadBytes = uploadBytes
	session.DownloadBytes = downloadBytes
	session.ActiveConnections = 0
	if session.State != model.VPNStateRunning && session.State != model.VPNStateStarting {
		_ = DB.Save(session).Error
		return
	}
	message := "relay disconnected"
	if closeErr != nil {
		message = closeErr.Error()
	}
	session.State = model.VPNStateFailed
	session.LastError = message
	cleanupErrors := v.dispatchSessionCleanupStops(session, policy)
	if len(cleanupErrors) > 0 {
		session.LastError += "; cleanup dispatch failed: " + strings.Join(cleanupErrors, "; ")
	}
	_ = DB.Save(session).Error
	v.finalizeVPNSessionRuntime(session.SessionID)
	detail := map[string]string{
		"source":         "relay_closed",
		"upload_bytes":   fmt.Sprint(uploadBytes),
		"download_bytes": fmt.Sprint(downloadBytes),
	}
	if len(cleanupErrors) > 0 {
		detail["cleanup_errors"] = strings.Join(cleanupErrors, "; ")
	}
	_ = v.writeAudit(VPNActor{UserID: session.GetUserID(), Role: model.RoleAdmin}, model.VPNAuditActionStatus, session.SessionID, session.EntryServerID, session.ExitServerID, false, message, detail)
	notification := vpnNotificationBase("[Agent VPN] 异常停止", policy, session, message)
	if len(cleanupErrors) > 0 {
		notification += "\n清理下发失败: " + strings.Join(cleanupErrors, "; ")
	}
	sendVPNNotification(policy.NotificationGroupID, notification, "")
}

func (v *VPNClass) dispatchSessionCleanupStops(session *model.AgentVPNSession, policy *model.AgentVPNPolicy) []string {
	cleanupErrors := make([]string, 0, 2)
	if session == nil || policy == nil {
		return cleanupErrors
	}
	token, err := v.tokenForSession(session)
	if err != nil {
		token = ""
	}
	if entry, ok := ServerShared.Get(session.EntryServerID); ok && entry.GetTaskStream() != nil {
		if err := v.sendControl(entry, session, policy, model.VPNRoleEntry, model.VPNActionStop, token); err != nil {
			cleanupErrors = append(cleanupErrors, "entry: "+err.Error())
			log.Printf("NEZHA>> VPN cleanup stop dispatch failed: session=%s role=entry err=%v", session.SessionID, err)
		}
	}
	if exit, ok := ServerShared.Get(session.ExitServerID); ok && exit.GetTaskStream() != nil {
		if err := v.sendControl(exit, session, policy, model.VPNRoleExit, model.VPNActionStop, token); err != nil {
			cleanupErrors = append(cleanupErrors, "exit: "+err.Error())
			log.Printf("NEZHA>> VPN cleanup stop dispatch failed: session=%s role=exit err=%v", session.SessionID, err)
		}
	}
	return cleanupErrors
}

func shouldDispatchVPNFailureCleanup(wasRunning bool, session *model.AgentVPNSession, result model.VPNControlResult) bool {
	if session == nil {
		return false
	}
	if result.Action == model.VPNActionPrepare || result.Action == model.VPNActionStart || result.Action == model.VPNActionRestart {
		return true
	}
	return wasRunning && result.Role == model.VPNRoleEntry && session.ExitState == model.VPNStateRunning
}

func (v *VPNClass) startPreparedVPNSession(session *model.AgentVPNSession, policy *model.AgentVPNPolicy, action string) (*model.AgentVPNSession, error) {
	if session == nil {
		return nil, errors.New("vpn session is required")
	}
	if policy == nil {
		err := errors.New("vpn policy is required")
		session.State = model.VPNStateFailed
		session.LastError = err.Error()
		_ = DB.Save(session).Error
		v.finalizeVPNSessionRuntime(session.SessionID)
		return session, err
	}
	exit, ok := ServerShared.Get(session.ExitServerID)
	if !ok || exit == nil || exit.GetTaskStream() == nil {
		err := fmt.Errorf("exit server %d is offline", session.ExitServerID)
		return v.failPreparedVPNStart(session, policy, action, "exit_offline_after_core_prepared", err)
	}
	token, err := v.tokenForSession(session)
	if err != nil {
		return v.failPreparedVPNStart(session, policy, action, "exit_token_missing_after_core_prepared", err)
	}

	if VPNRelayCreator != nil {
		VPNRelayCreator(session.SessionID, session.EntryStreamID, session.EntryServerID, session.ExitStreamID, session.ExitServerID)
		v.appendControlLog(session.SessionID, "relay created entry_stream=%s exit_stream=%s", session.EntryStreamID, session.ExitStreamID)
	}
	session.State = model.VPNStateStarting
	session.EntryState = model.VPNStatePending
	session.ExitState = model.VPNStateStarting
	if err := DB.Save(session).Error; err != nil {
		return nil, err
	}
	v.appendControlLog(session.SessionID, "core prepared on both agents; dispatching exit %s", action)
	if err := v.sendControl(exit, session, policy, model.VPNRoleExit, action, token); err != nil {
		return v.failPreparedVPNStart(session, policy, action, "exit_start_dispatch", err)
	}
	_ = v.writeAudit(VPNActor{UserID: session.GetUserID(), Role: model.RoleAdmin}, vpnLifecycleFailureAuditAction(action), session.SessionID, session.EntryServerID, session.ExitServerID, true, "exit "+action+" dispatched", vpnPolicyAuditDetail(policy))
	return session, nil
}

func (v *VPNClass) failPreparedVPNStart(session *model.AgentVPNSession, policy *model.AgentVPNPolicy, action string, stage string, cause error) (*model.AgentVPNSession, error) {
	if cause == nil {
		cause = errors.New("vpn start failed")
	}
	session.State = model.VPNStateFailed
	session.ExitState = model.VPNStateFailed
	session.LastError = cause.Error()
	v.appendControlLog(session.SessionID, "exit %s blocked after core prepared: %s", action, session.LastError)
	cleanupErrors := v.dispatchSessionCleanupStops(session, policy)
	if len(cleanupErrors) > 0 {
		session.LastError += "; cleanup dispatch failed: " + strings.Join(cleanupErrors, "; ")
	}
	_ = DB.Save(session).Error
	auditDetail := map[string]string{
		"stage":              vpnLifecycleFailureStage(action, stage),
		"cleanup_dispatched": "true",
	}
	if len(cleanupErrors) > 0 {
		auditDetail["cleanup_errors"] = strings.Join(cleanupErrors, "; ")
	}
	_ = v.writeAudit(VPNActor{UserID: session.GetUserID(), Role: model.RoleAdmin}, vpnLifecycleFailureAuditAction(action), session.SessionID, session.EntryServerID, session.ExitServerID, false, session.LastError, auditDetail)
	v.finalizeVPNSessionRuntime(session.SessionID)
	v.notifyLifecycleFailure(policy, session, action, "")
	return session, cause
}

func (v *VPNClass) recordRelayTraffic(sessionID string, uploadBytes uint64, downloadBytes uint64, activeConnections uint32) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return
	}
	now := time.Now()
	v.mu.Lock()
	snapshot := v.relayTraffic[sessionID]
	connectionsChanged := snapshot.activeConnections != activeConnections
	snapshot.uploadBytes = uploadBytes
	snapshot.downloadBytes = downloadBytes
	snapshot.activeConnections = activeConnections
	shouldFlush := false
	if snapshot.lastFlushAt.IsZero() {
		snapshot.lastFlushAt = now
		shouldFlush = connectionsChanged
	} else if connectionsChanged || now.Sub(snapshot.lastFlushAt) >= v.relayTrafficFlushInterval {
		shouldFlush = true
		snapshot.lastFlushAt = now
	}
	v.relayTraffic[sessionID] = snapshot
	v.mu.Unlock()
	if shouldFlush {
		v.FlushRelayTraffic(sessionID)
	}
}

func (v *VPNClass) recordLateAgentCleanupResult(policy *model.AgentVPNPolicy, session *model.AgentVPNSession, result model.VPNControlResult) {
	if policy == nil || session == nil {
		return
	}
	if result.Action != model.VPNActionStop && result.State != model.VPNStateStopped {
		return
	}
	agentCleanupLogs := vpnAgentCleanupLogSummary(result.Logs)
	if agentCleanupLogs == "" {
		return
	}
	detail := map[string]string{
		"role":          result.Role,
		"result_action": result.Action,
	}
	addVPNAuditAgentCleanupDetail(detail, agentCleanupLogs)
	_ = v.writeAudit(VPNActor{UserID: session.GetUserID(), Role: model.RoleAdmin}, model.VPNAuditActionStopSession, session.SessionID, session.EntryServerID, session.ExitServerID, true, "late agent cleanup result", detail)
	message := fmt.Sprintf("[Agent VPN] 停止清理结果\n入口节点: %s\n出口节点: %s\n角色: %s\nSession: %s\nAgent 清理日志: %s",
		serverName(session.EntryServerID),
		serverName(session.ExitServerID),
		result.Role,
		session.SessionID,
		agentCleanupLogs,
	)
	sendVPNNotification(policy.NotificationGroupID, message, "")
}

func (v *VPNClass) FlushRelayTraffic(sessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return
	}
	v.mu.Lock()
	snapshot, ok := v.relayTraffic[sessionID]
	if !ok {
		v.mu.Unlock()
		return
	}
	snapshot.lastFlushAt = time.Now()
	v.relayTraffic[sessionID] = snapshot
	v.mu.Unlock()

	_ = DB.Model(&model.AgentVPNSession{}).
		Where("session_id = ?", sessionID).
		Updates(map[string]any{
			"upload_bytes":       snapshot.uploadBytes,
			"download_bytes":     snapshot.downloadBytes,
			"active_connections": snapshot.activeConnections,
		}).Error
}

func (v *VPNClass) RecoverActiveSessions() error {
	var sessions []model.AgentVPNSession
	if err := DB.Where("state IN ?", []string{model.VPNStateStarting, model.VPNStateRunning, model.VPNStateUnknown}).Find(&sessions).Error; err != nil {
		return err
	}
	for i := range sessions {
		session := &sessions[i]
		policy, err := v.policyForSession(session)
		if err != nil {
			reason := "policy not found during recovery: " + err.Error()
			_ = v.markSessionLost(session, v.fallbackVPNPolicyForLostSession(session), model.VPNRoleEntry, reason, "dashboard recovery")
			continue
		}
		session.State = model.VPNStateUnknown
		session.EntryState = model.VPNStateUnknown
		session.ExitState = model.VPNStateUnknown
		session.RelayMode = normalizeVPNRelayMode(session.RelayMode)
		session.LastError = "dashboard restarted; waiting for agent status"
		if err := DB.Save(session).Error; err != nil {
			return err
		}
		if err := v.querySessionStatus(session, policy, session.EntryServerID, model.VPNRoleEntry); err != nil {
			_ = v.markSessionLost(session, policy, model.VPNRoleEntry, err.Error(), "dashboard recovery")
			continue
		}
		if err := v.querySessionStatus(session, policy, session.ExitServerID, model.VPNRoleExit); err != nil {
			_ = v.markSessionLost(session, policy, model.VPNRoleExit, err.Error(), "dashboard recovery")
		}
	}
	return nil
}

func (v *VPNClass) ExpireSessions(now time.Time) error {
	var sessions []model.AgentVPNSession
	if err := DB.Where("state IN ? AND expires_at <= ?", []string{model.VPNStateStarting, model.VPNStateRunning, model.VPNStateUnknown}, now).Find(&sessions).Error; err != nil {
		return err
	}
	for i := range sessions {
		if err := v.expireSession(&sessions[i], now); err != nil {
			return err
		}
	}
	return nil
}

func (v *VPNClass) OnAgentReconnect(serverID uint64) error {
	var sessions []model.AgentVPNSession
	if err := DB.Where("state IN ? AND (entry_server_id = ? OR exit_server_id = ?)", []string{model.VPNStateStarting, model.VPNStateRunning, model.VPNStateUnknown, model.VPNStateLost, model.VPNStateFailed}, serverID, serverID).Find(&sessions).Error; err != nil {
		return err
	}
	for i := range sessions {
		session := &sessions[i]
		policy, err := v.policyForSession(session)
		if err != nil {
			reason := "policy not found during reconnect: " + err.Error()
			_ = v.markSessionLost(session, v.fallbackVPNPolicyForLostSession(session), model.VPNRoleEntry, reason, "agent reconnect")
			continue
		}
		now := time.Now()
		if !session.ExpiresAt.IsZero() && !session.ExpiresAt.After(now) {
			if err := v.expireSession(session, now); err != nil {
				session.State = model.VPNStateLost
				session.LastError = err.Error()
				_ = DB.Save(session).Error
			}
			continue
		}
		if shouldAutoRestartVPNSession(policy, session, now) {
			if err := v.restartExistingSession(session, policy); err != nil {
				_ = v.markSessionLost(session, policy, model.VPNRoleEntry, err.Error(), "auto restart")
			}
			continue
		}
		role := model.VPNRoleEntry
		if session.ExitServerID == serverID {
			role = model.VPNRoleExit
		}
		if err := v.querySessionStatus(session, policy, serverID, role); err != nil {
			_ = v.markSessionLost(session, policy, role, err.Error(), "agent reconnect")
		}
	}
	return nil
}

func closeVPNRelay(sessionID string) {
	if VPNRelayCloser != nil {
		VPNRelayCloser(sessionID)
	}
}

func (v *VPNClass) SessionLogs(sessionID string) []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.sessionLogs[strings.TrimSpace(sessionID)]...)
}

func (v *VPNClass) appendSessionLogs(sessionID string, lines []string) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" || len(lines) == 0 {
		return
	}
	normalized := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimRight(stripVPNLogANSI(line), "\r\n")
		if line != "" && !isRoutineVPNAccessLog(line) {
			normalized = append(normalized, line)
		}
	}
	if len(normalized) == 0 {
		return
	}
	receivedAt := time.Now()
	for i, line := range normalized {
		normalized[i] = timestampVPNLogLine(receivedAt, line)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	logs := append(v.sessionLogs[sessionID], normalized...)
	if len(logs) > vpnSessionLogLimit {
		logs = logs[len(logs)-vpnSessionLogLimit:]
	}
	v.sessionLogs[sessionID] = logs
}

func (v *VPNClass) appendControlLog(sessionID string, format string, args ...any) {
	if strings.TrimSpace(sessionID) == "" {
		return
	}
	v.appendSessionLogs(sessionID, []string{"[dashboard] " + fmt.Sprintf(format, args...)})
}

func stripVPNLogANSI(line string) string {
	if strings.TrimSpace(line) == "" {
		return line
	}
	return vpnANSISequence.ReplaceAllString(line, "")
}

func timestampVPNLogLine(receivedAt time.Time, line string) string {
	if vpnLogTimestamp.MatchString(line) {
		return line
	}
	return "[" + receivedAt.In(vpnLogTimeLocation).Format("15:04:05") + "] " + line
}

func isRoutineVPNAccessLog(line string) bool {
	line = strings.TrimSpace(line)
	if !strings.Contains(line, "INFO") {
		return false
	}
	return strings.Contains(line, "inbound connection from ") ||
		strings.Contains(line, "inbound connection to ") ||
		strings.Contains(line, "outbound connection to ")
}

func (v *VPNClass) sendControl(server *model.Server, session *model.AgentVPNSession, policy *model.AgentVPNPolicy, role string, action string, token string) error {
	if server == nil {
		err := errors.New("server not found")
		if session != nil {
			v.appendControlLog(session.SessionID, "failed to send %s request to %s agent: %v", action, role, err)
		}
		return err
	}
	stream := server.GetTaskStream()
	if stream == nil {
		err := fmt.Errorf("server %d is offline", server.ID)
		if session != nil {
			v.appendControlLog(session.SessionID, "failed to send %s request to %s agent server=%d name=%q: %v", action, role, server.ID, server.Name, err)
		}
		return err
	}
	req := buildVPNControlRequest(session, policy, role, action, token)
	data, err := json.Marshal(req)
	if err != nil {
		if session != nil {
			v.appendControlLog(session.SessionID, "failed to encode %s request for %s agent server=%d name=%q: %v", action, role, server.ID, server.Name, err)
		}
		return err
	}
	err = stream.Send(&pb.Task{
		Id:   session.ID,
		Type: model.TaskTypeVPNControl,
		Data: string(data),
	})
	if err != nil {
		v.appendControlLog(session.SessionID, "failed to send %s request to %s agent server=%d name=%q: %v", action, role, server.ID, server.Name, err)
		return err
	}
	v.appendControlLog(session.SessionID, "sent %s request to %s agent server=%d name=%q task_id=%d", action, role, server.ID, server.Name, session.ID)
	return nil
}

func (v *VPNClass) sendPolicyStatusControl(server *model.Server, session *model.AgentVPNSession, policy *model.AgentVPNPolicy, role string, checkID string) error {
	if server == nil {
		return errors.New("server not found")
	}
	stream := server.GetTaskStream()
	if stream == nil {
		return fmt.Errorf("server %d is offline", server.ID)
	}
	req := buildVPNControlRequest(session, policy, role, model.VPNActionStatus, "")
	setVPNRequestExtra(&req, "status_check_id", checkID)
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if err := stream.Send(&pb.Task{
		Id:   session.ID,
		Type: model.TaskTypeVPNControl,
		Data: string(data),
	}); err != nil {
		return fmt.Errorf("send status request to %s agent server=%d name=%q: %w", role, server.ID, server.Name, err)
	}
	return nil
}

func (v *VPNClass) querySessionStatus(session *model.AgentVPNSession, policy *model.AgentVPNPolicy, serverID uint64, role string) error {
	if err := validateVPNPolicyRuntime(policy); err != nil {
		return err
	}
	server, ok := ServerShared.Get(serverID)
	if !ok || server == nil || server.GetTaskStream() == nil {
		return fmt.Errorf("server %d is offline", serverID)
	}
	return v.sendControl(server, session, policy, role, model.VPNActionStatus, "")
}

func newVPNPolicyNodeStatus(role string, server *model.Server) model.AgentVPNPolicyNodeStatus {
	node := model.AgentVPNPolicyNodeStatus{
		Role:        role,
		State:       model.VPNStateUnknown,
		CoreStatus:  "unknown",
		RulesStatus: "unknown",
	}
	if server == nil {
		return node
	}
	node.ServerID = server.ID
	node.ServerName = server.Name
	node.Online = server.GetTaskStream() != nil
	return node
}

func updateVPNPolicyNodeStatus(node *model.AgentVPNPolicyNodeStatus, result model.VPNControlResult) {
	if node == nil {
		return
	}
	node.Responded = true
	node.State = firstNonEmptyString(result.State, node.State, model.VPNStateUnknown)
	node.CoreStatus = firstNonEmptyString(result.CoreStatus, node.CoreStatus, "unknown")
	node.CorePath = firstNonEmptyString(result.CorePath, node.CorePath)
	node.CoreVersion = firstNonEmptyString(result.CoreVersion, node.CoreVersion)
	node.RulesStatus = firstNonEmptyString(result.RulesStatus, node.RulesStatus, "unknown")
	node.RulesPath = firstNonEmptyString(result.RulesPath, node.RulesPath)
	node.RulesVersion = firstNonEmptyString(result.RulesVersion, node.RulesVersion)
	node.LastError = firstNonEmptyString(result.LastError, node.LastError)
	if len(result.Logs) > 0 {
		node.Logs = append([]string{}, result.Logs...)
	}
}

func (v *VPNClass) registerPolicyStatusWaiter(checkID string, ch chan vpnPolicyStatusAgentResult) {
	checkID = strings.TrimSpace(checkID)
	if checkID == "" || ch == nil {
		return
	}
	v.mu.Lock()
	v.statusWaiters[checkID] = ch
	v.mu.Unlock()
}

func (v *VPNClass) unregisterPolicyStatusWaiter(checkID string) {
	checkID = strings.TrimSpace(checkID)
	if checkID == "" {
		return
	}
	v.mu.Lock()
	delete(v.statusWaiters, checkID)
	v.mu.Unlock()
}

func (v *VPNClass) deliverPolicyStatusResult(reporterServerID uint64, result model.VPNControlResult) {
	checkID := strings.TrimSpace(result.CheckID)
	if checkID == "" {
		return
	}
	v.mu.Lock()
	ch := v.statusWaiters[checkID]
	v.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- vpnPolicyStatusAgentResult{serverID: reporterServerID, result: result}:
	default:
	}
}

func (v *VPNClass) restartExistingSession(session *model.AgentVPNSession, policy *model.AgentVPNPolicy) error {
	return v.restartExistingSessionWithAction(VPNActor{UserID: session.GetUserID(), Role: model.RoleAdmin}, session, policy, model.VPNActionStart)
}

func (v *VPNClass) restartExistingSessionWithAction(actor VPNActor, session *model.AgentVPNSession, policy *model.AgentVPNPolicy, action string) error {
	if err := validateVPNPolicyRuntime(policy); err != nil {
		v.recordRestartSessionPreflightFailure(actor, session, policy, err, "policy_validation", action)
		return err
	}
	entry, ok := ServerShared.Get(session.EntryServerID)
	if !ok || entry == nil || entry.GetTaskStream() == nil {
		err := fmt.Errorf("entry server %d is offline", session.EntryServerID)
		v.recordRestartSessionPreflightFailure(actor, session, policy, err, "entry_offline", action)
		return err
	}
	exit, ok := ServerShared.Get(session.ExitServerID)
	if !ok || exit == nil || exit.GetTaskStream() == nil {
		err := fmt.Errorf("exit server %d is offline", session.ExitServerID)
		v.recordRestartSessionPreflightFailure(actor, session, policy, err, "exit_offline", action)
		return err
	}
	if err := validateVPNServerCapabilities(policy, entry, exit); err != nil {
		v.recordRestartSessionPreflightFailure(actor, session, policy, err, "capability_validation", action)
		return err
	}

	token, err := VPNTokenGenerator()
	if err != nil {
		v.recordRestartSessionPreflightFailure(actor, session, policy, err, "token_generation", action)
		return err
	}
	entryStreamID, err := VPNIDGenerator("vpn_entry_")
	if err != nil {
		v.recordRestartSessionPreflightFailure(actor, session, policy, err, "entry_stream_id_generation", action)
		return err
	}
	exitStreamID, err := VPNIDGenerator("vpn_exit_")
	if err != nil {
		v.recordRestartSessionPreflightFailure(actor, session, policy, err, "exit_stream_id_generation", action)
		return err
	}

	closeVPNRelay(session.SessionID)
	now := time.Now()
	session.TokenHash = hashVPNToken(token)
	session.Mode = policy.Mode
	session.RuleMode = normalizeVPNRuleMode(policy.RuleMode)
	session.RelayMode = model.VPNRelayModeDashboard
	session.State = model.VPNStateStarting
	session.EntryState = model.VPNStatePending
	session.ExitState = model.VPNStateStarting
	session.EntryStreamID = entryStreamID
	session.ExitStreamID = exitStreamID
	session.LocalHTTP = policy.ListenHTTP
	session.LocalSOCKS = policy.ListenSOCKS
	session.TunName = policy.TunName
	session.SetSystemProxy = policy.SetSystemProxy
	session.LastError = ""
	session.StoppedAt = nil
	session.StartedAt = now
	if err := DB.Save(session).Error; err != nil {
		return err
	}
	v.appendControlLog(session.SessionID, "%s requested; relay streams rotated entry_stream=%s exit_stream=%s", action, session.EntryStreamID, session.ExitStreamID)

	v.mu.Lock()
	v.sessionTokens[session.SessionID] = token
	v.sessionPolicies[session.SessionID] = cloneVPNPolicy(policy)
	v.mu.Unlock()

	if VPNRelayCreator != nil {
		VPNRelayCreator(session.SessionID, session.EntryStreamID, session.EntryServerID, session.ExitStreamID, session.ExitServerID)
		v.appendControlLog(session.SessionID, "relay recreated entry_stream=%s exit_stream=%s", session.EntryStreamID, session.ExitStreamID)
	}

	if err := v.sendControl(exit, session, policy, model.VPNRoleExit, action, token); err != nil {
		session.State = model.VPNStateFailed
		session.ExitState = model.VPNStateFailed
		session.LastError = err.Error()
		_ = DB.Save(session).Error
		v.finalizeVPNSessionRuntime(session.SessionID)
		_ = v.writeAudit(actor, model.VPNAuditActionRestart, session.SessionID, session.EntryServerID, session.ExitServerID, false, err.Error(), map[string]string{
			"stage":              vpnLifecycleFailureStage(action, "exit_start_dispatch"),
			"cleanup_dispatched": "false",
		})
		if action == model.VPNActionRestart {
			v.notifyRestartFailure(policy, session, "")
		}
		return err
	}
	_ = v.writeAudit(actor, model.VPNAuditActionRestart, session.SessionID, session.EntryServerID, session.ExitServerID, true, "exit restart dispatched", nil)
	return nil
}

func (v *VPNClass) expireSession(session *model.AgentVPNSession, now time.Time) error {
	policy, err := v.policyForSession(session)
	if err != nil {
		policy = v.fallbackVPNPolicyForLostSession(session)
	}
	token, err := v.tokenForSession(session)
	if err != nil {
		token = ""
	}
	stopErrors := make([]string, 0, 2)
	if entry, ok := ServerShared.Get(session.EntryServerID); ok && entry.GetTaskStream() != nil {
		if err := v.sendControl(entry, session, policy, model.VPNRoleEntry, model.VPNActionStop, token); err != nil {
			stopErrors = append(stopErrors, "entry: "+err.Error())
			log.Printf("NEZHA>> VPN expiry stop dispatch failed: session=%s role=entry err=%v", session.SessionID, err)
		}
	}
	if exit, ok := ServerShared.Get(session.ExitServerID); ok && exit.GetTaskStream() != nil {
		if err := v.sendControl(exit, session, policy, model.VPNRoleExit, model.VPNActionStop, token); err != nil {
			stopErrors = append(stopErrors, "exit: "+err.Error())
			log.Printf("NEZHA>> VPN expiry stop dispatch failed: session=%s role=exit err=%v", session.SessionID, err)
		}
	}
	session.State = model.VPNStateStopped
	session.EntryState = model.VPNStateStopped
	session.ExitState = model.VPNStateStopped
	session.LastError = "session expired"
	if len(stopErrors) > 0 {
		session.LastError += "; cleanup dispatch failed: " + strings.Join(stopErrors, "; ")
	}
	session.StoppedAt = &now
	if err := DB.Save(session).Error; err != nil {
		return err
	}
	v.finalizeVPNSessionRuntime(session.SessionID)
	detail := map[string]string(nil)
	if len(stopErrors) > 0 {
		detail = map[string]string{
			"cleanup_errors": strings.Join(stopErrors, "; "),
		}
	}
	_ = v.writeAudit(VPNActor{UserID: session.GetUserID(), Role: model.RoleAdmin}, model.VPNAuditActionStopSession, session.SessionID, session.EntryServerID, session.ExitServerID, true, "session expired", detail)
	message := vpnNotificationBase("[Agent VPN] 已过期停止", policy, session, "session expired")
	if len(stopErrors) > 0 {
		message += "\n清理下发失败: " + strings.Join(stopErrors, "; ")
	}
	sendVPNNotification(policy.NotificationGroupID, message, "")
	return nil
}

func (v *VPNClass) finalizeVPNSessionRuntime(sessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return
	}
	closeVPNRelay(sessionID)
	v.mu.Lock()
	delete(v.sessionTokens, sessionID)
	delete(v.relayTraffic, sessionID)
	v.mu.Unlock()
}

func (v *VPNClass) forgetVPNSessionRuntime(sessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return
	}
	v.finalizeVPNSessionRuntime(sessionID)
	v.mu.Lock()
	delete(v.sessionPolicies, sessionID)
	delete(v.sessionLogs, sessionID)
	v.mu.Unlock()
}

func (v *VPNClass) validatePolicyForm(actor VPNActor, form model.AgentVPNPolicyForm) error {
	if form.EntryServerID == 0 || form.ExitServerID == 0 {
		return errors.New("entry and exit server are required")
	}
	if form.EntryServerID == form.ExitServerID {
		return errors.New("entry and exit server must be different")
	}
	if _, err := v.getUsableServer(actor, form.EntryServerID); err != nil {
		return fmt.Errorf("entry server: %w", err)
	}
	if _, err := v.getUsableServer(actor, form.ExitServerID); err != nil {
		return fmt.Errorf("exit server: %w", err)
	}
	if err := validateVPNNotificationGroupForActor(actor, form.NotificationGroupID); err != nil {
		return err
	}
	if err := validateVPNMode(form.Mode); err != nil {
		return err
	}
	if err := validateVPNRuleMode(form.RuleMode); err != nil {
		return err
	}
	mode := normalizeVPNMode(form.Mode)
	if mode == model.VPNModeSystemProxy && strings.TrimSpace(form.ListenHTTP) == "" && strings.TrimSpace(form.ListenSOCKS) == "" {
		return errors.New("system proxy mode requires http or socks listen address")
	}
	if err := validateVPNListenAddress("http listen address", form.ListenHTTP); err != nil {
		return err
	}
	if err := validateVPNListenAddress("socks listen address", form.ListenSOCKS); err != nil {
		return err
	}
	if err := validateVPNRules(normalizeVPNRuleMode(form.RuleMode), form.Domains, form.CIDRs, form.DirectCIDRs); err != nil {
		return err
	}
	if form.ExpiresSeconds == 0 {
		return errors.New("expires seconds must be greater than 0")
	}
	if err := validateVPNTunHealthPolicy(mode, form.TunHealthURL); err != nil {
		return err
	}
	if err := validateVPNEgressProbeURL(form.EgressProbeURL); err != nil {
		return err
	}
	if err := validateVPNCoreSpec(form.CoreDownloadURL, form.CoreSHA256); err != nil {
		return err
	}
	return nil
}

func (v *VPNClass) getPolicyForActor(actor VPNActor, policyID uint64) (*model.AgentVPNPolicy, error) {
	var policy model.AgentVPNPolicy
	if err := DB.First(&policy, policyID).Error; err != nil {
		return nil, err
	}
	if !actor.IsAdmin() && policy.GetUserID() != actor.UserID {
		return nil, errors.New("permission denied")
	}
	if !actorCanUseVPNServer(actor, policy.EntryServerID) || !actorCanUseVPNServer(actor, policy.ExitServerID) {
		return nil, errors.New("permission denied")
	}
	return &policy, nil
}

func (v *VPNClass) getUsableServer(actor VPNActor, serverID uint64) (*model.Server, error) {
	server, ok := ServerShared.Get(serverID)
	if !ok || server == nil {
		return nil, fmt.Errorf("server %d not found", serverID)
	}
	if !actor.IsAdmin() && server.GetUserID() != actor.UserID {
		return nil, errors.New("permission denied")
	}
	return server, nil
}

func validateVPNNotificationGroupForActor(actor VPNActor, groupID uint64) error {
	if groupID == 0 {
		return nil
	}
	var group model.NotificationGroup
	if err := DB.First(&group, groupID).Error; err != nil {
		return fmt.Errorf("notification group %d does not exist", groupID)
	}
	if !actor.IsAdmin() && group.GetUserID() != actor.UserID {
		return errors.New("permission denied")
	}
	return nil
}

func (v *VPNClass) policyForSession(session *model.AgentVPNSession) (*model.AgentVPNPolicy, error) {
	v.mu.Lock()
	if policy := v.sessionPolicies[session.SessionID]; policy != nil {
		v.mu.Unlock()
		return applyVPNSessionControls(cloneVPNPolicy(policy), session), nil
	}
	v.mu.Unlock()
	var policy model.AgentVPNPolicy
	if err := DB.First(&policy, session.PolicyID).Error; err != nil {
		return nil, err
	}
	v.mu.Lock()
	v.sessionPolicies[session.SessionID] = cloneVPNPolicy(&policy)
	v.mu.Unlock()
	return applyVPNSessionControls(&policy, session), nil
}

func (v *VPNClass) tokenForSession(session *model.AgentVPNSession) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	token := v.sessionTokens[session.SessionID]
	if token == "" {
		return "", errors.New("session token is no longer available")
	}
	return token, nil
}

func (v *VPNClass) writeAudit(actor VPNActor, action string, sessionID string, entryServerID uint64, exitServerID uint64, success bool, message string, detail map[string]string) error {
	audit := &model.AgentVPNAuditLog{
		Common: model.Common{
			UserID: actor.UserID,
		},
		SessionID:     sessionID,
		UserID:        actor.UserID,
		Action:        action,
		EntryServerID: entryServerID,
		ExitServerID:  exitServerID,
		Success:       success,
		Message:       message,
		Detail:        detail,
	}
	return DB.Create(audit).Error
}

func vpnPolicyAuditDetail(policy *model.AgentVPNPolicy) map[string]string {
	if policy == nil {
		return nil
	}
	return map[string]string{
		"policy_id":                  fmt.Sprint(policy.ID),
		"policy_name":                policy.Name,
		"mode":                       policy.Mode,
		"rule_mode":                  policy.RuleMode,
		"domains":                    strings.Join(policy.Domains, ","),
		"cidrs":                      strings.Join(policy.CIDRs, ","),
		"direct_cidrs":               strings.Join(policy.DirectCIDRs, ","),
		"listen_http":                policy.ListenHTTP,
		"listen_socks":               policy.ListenSOCKS,
		"tun_name":                   policy.TunName,
		"dns_server":                 policy.DNSServer,
		"expires_seconds":            fmt.Sprint(policy.ExpiresSeconds),
		"max_upload_bytes":           fmt.Sprint(policy.MaxUploadBytes),
		"max_download_bytes":         fmt.Sprint(policy.MaxDownloadBytes),
		"max_connections":            fmt.Sprint(policy.MaxConnections),
		"idle_timeout_seconds":       fmt.Sprint(policy.IdleTimeoutSeconds),
		"notification_group_id":      fmt.Sprint(policy.NotificationGroupID),
		"auto_restart":               fmt.Sprint(policy.AutoRestart),
		"set_system_proxy":           fmt.Sprint(policy.SetSystemProxy),
		"tun_health_url":             policy.TunHealthURL,
		"tun_health_timeout_seconds": fmt.Sprint(policy.TunHealthTimeoutSeconds),
		"egress_probe_url":           policy.EgressProbeURL,
		"core_version":               policy.CoreVersion,
		"core_download_url":          policy.CoreDownloadURL,
		"core_sha256":                policy.CoreSHA256,
	}
}

func vpnSessionControlAuditDetail(policy *model.AgentVPNPolicy) map[string]string {
	if policy == nil {
		return nil
	}
	return map[string]string{
		"mode":             policy.Mode,
		"rule_mode":        policy.RuleMode,
		"set_system_proxy": fmt.Sprint(policy.SetSystemProxy),
	}
}

func vpnStartSuccessAuditDetail(policy *model.AgentVPNPolicy, logs []string) map[string]string {
	detail := vpnPolicyAuditDetail(policy)
	if detail == nil {
		detail = map[string]string{}
	}
	if summary := vpnEgressProbeSummary(logs); summary != "" {
		detail["egress_probe"] = summary
	}
	return detail
}

func vpnFailedResultAuditDetail(result model.VPNControlResult, cleanupDispatched bool, cleanupErrors []string) map[string]string {
	detail := map[string]string{
		"role":               result.Role,
		"result_action":      result.Action,
		"cleanup_dispatched": fmt.Sprint(cleanupDispatched),
	}
	if len(cleanupErrors) > 0 {
		detail["cleanup_errors"] = strings.Join(cleanupErrors, "; ")
	}
	return detail
}

func vpnFailedRuntimeAuditDetail(result model.VPNControlResult, cleanupDispatched bool, cleanupErrors []string) map[string]string {
	detail := vpnFailedResultAuditDetail(result, cleanupDispatched, cleanupErrors)
	detail["source"] = "agent_failed_result"
	return detail
}

func vpnAgentCleanupLogSummary(logs []string) string {
	cleanup := make([]string, 0, len(logs))
	for _, line := range logs {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[cleanup]") || strings.HasPrefix(line, "[tun-health]") {
			cleanup = append(cleanup, line)
		}
	}
	return strings.Join(cleanup, "; ")
}

func addVPNAuditAgentCleanupDetail(detail map[string]string, cleanupLogs string) {
	if detail == nil {
		return
	}
	cleanupLogs = strings.TrimSpace(cleanupLogs)
	if cleanupLogs == "" {
		return
	}
	detail["agent_cleanup_logs"] = cleanupLogs
	okItems := make([]string, 0, 2)
	failedItems := make([]string, 0, 2)
	stateKept := false
	for _, raw := range strings.Split(cleanupLogs, ";") {
		line := strings.TrimSpace(raw)
		line = strings.TrimPrefix(line, "[cleanup]")
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "state=kept-for-restore-retry") {
			stateKept = true
			continue
		}
		if name, ok := strings.CutSuffix(line, "=ok"); ok {
			name = strings.TrimSpace(name)
			if name != "" {
				okItems = append(okItems, name)
			}
			continue
		}
		if idx := strings.Index(line, "=failed"); idx > 0 {
			name := strings.TrimSpace(line[:idx])
			if name != "" {
				failedItems = append(failedItems, name)
			}
		}
	}
	detail["agent_cleanup_ok"] = strings.Join(okItems, ",")
	detail["agent_cleanup_failed"] = strings.Join(failedItems, ",")
	detail["agent_cleanup_state_kept"] = fmt.Sprint(stateKept)
}

func vpnLifecycleFailureAuditAction(action string) string {
	if action == model.VPNActionRestart {
		return model.VPNAuditActionRestart
	}
	return model.VPNAuditActionStartSession
}

func vpnLifecycleFailureStage(action string, startStage string) string {
	if action != model.VPNActionRestart {
		return startStage
	}
	if strings.Contains(startStage, "_start_") {
		return strings.Replace(startStage, "_start_", "_restart_", 1)
	}
	if strings.HasSuffix(startStage, "_start_dispatch") {
		return strings.TrimSuffix(startStage, "_start_dispatch") + "_restart_dispatch"
	}
	return "restart_" + startStage
}

func (v *VPNClass) markSessionLost(session *model.AgentVPNSession, policy *model.AgentVPNPolicy, role string, reason string, source string) error {
	if session == nil {
		return nil
	}
	if strings.TrimSpace(reason) == "" {
		reason = "agent status unavailable"
	}
	if vpnLostAlreadyRecorded(session, role, reason, source) {
		return nil
	}
	if role == model.VPNRoleEntry {
		session.EntryState = model.VPNStateLost
	} else if role == model.VPNRoleExit {
		session.ExitState = model.VPNStateLost
	}
	session.State = model.VPNStateLost
	session.LastError = reason
	if err := DB.Save(session).Error; err != nil {
		return err
	}
	detail := map[string]string{
		"role":   role,
		"source": source,
		"reason": reason,
	}
	_ = v.writeAudit(VPNActor{UserID: session.GetUserID(), Role: model.RoleAdmin}, model.VPNAuditActionStatus, session.SessionID, session.EntryServerID, session.ExitServerID, false, reason, detail)
	if policy != nil {
		v.notifyLost(policy, session, role, reason)
	}
	return nil
}

func vpnLostAlreadyRecorded(session *model.AgentVPNSession, role string, reason string, source string) bool {
	if session == nil || session.State != model.VPNStateLost || session.LastError != reason {
		return false
	}
	var audit model.AgentVPNAuditLog
	if err := DB.Where("action = ? AND session_id = ? AND success = ?", model.VPNAuditActionStatus, session.SessionID, false).
		Order("id DESC").
		First(&audit).Error; err != nil {
		return false
	}
	return audit.Detail["role"] == role && audit.Detail["source"] == source && audit.Detail["reason"] == reason
}

func canHandleVPNResultWithoutPolicy(result model.VPNControlResult) bool {
	if result.State == model.VPNStateFailed || result.State == model.VPNStateStopped {
		return true
	}
	if result.Action == model.VPNActionLogs || result.Action == model.VPNActionCleanup || result.Action == model.VPNActionStatus || result.Action == model.VPNActionControl {
		return true
	}
	if result.Action == model.VPNActionPrepare && result.State == model.VPNStatePrepared {
		return true
	}
	if (result.Action == model.VPNActionStart || result.Action == model.VPNActionRestart) &&
		(result.Role == model.VPNRoleExit || result.Role == model.VPNRoleEntry) &&
		result.State == model.VPNStateRunning {
		return true
	}
	if result.Action == model.VPNActionStop && result.State == "" {
		return true
	}
	return false
}

func (v *VPNClass) notifyStarted(policy *model.AgentVPNPolicy, session *model.AgentVPNSession) {
	message := vpnNotificationBase("[Agent VPN] 已启动", policy, session, "")
	if summary := vpnEgressProbeSummary(v.SessionLogs(session.SessionID)); summary != "" {
		message += "\n出口探测: " + summary
	}
	sendVPNNotification(policy.NotificationGroupID, message, "")
}

func (v *VPNClass) notifyRestarted(policy *model.AgentVPNPolicy, session *model.AgentVPNSession) {
	message := vpnNotificationBase("[Agent VPN] 已重启", policy, session, "")
	if summary := vpnEgressProbeSummary(v.SessionLogs(session.SessionID)); summary != "" {
		message += "\n出口探测: " + summary
	}
	sendVPNNotification(policy.NotificationGroupID, message, "")
}

func vpnNotificationBase(title string, policy *model.AgentVPNPolicy, session *model.AgentVPNSession, reason string) string {
	if policy == nil || session == nil {
		return title
	}
	lines := []string{
		title,
		"策略: " + policy.Name,
		fmt.Sprintf("Session: %s", session.SessionID),
		fmt.Sprintf("入口节点: %s", serverName(session.EntryServerID)),
		fmt.Sprintf("出口节点: %s", serverName(session.ExitServerID)),
		fmt.Sprintf("模式: %s", session.Mode),
		fmt.Sprintf("状态: %s", session.State),
		fmt.Sprintf("本地代理: %s", describeVPNLocalAccess(policy)),
		fmt.Sprintf("上传/下载: %d B / %d B", session.UploadBytes, session.DownloadBytes),
		fmt.Sprintf("连接数: %d", session.ActiveConnections),
		fmt.Sprintf("有效期: %s", time.Until(session.ExpiresAt).Round(time.Second).String()),
	}
	if strings.TrimSpace(reason) != "" {
		lines = append(lines, "错误原因: "+strings.TrimSpace(reason))
	}
	lines = append(lines, "时间: "+time.Now().Format(time.RFC3339))
	return strings.Join(lines, "\n")
}

func vpnPolicyFailureNotification(title string, policy *model.AgentVPNPolicy, reason string) string {
	if policy == nil {
		return title
	}
	lines := []string{
		title,
		"策略: " + policy.Name,
		"Session: -",
		fmt.Sprintf("入口节点: %s", serverName(policy.EntryServerID)),
		fmt.Sprintf("出口节点: %s", serverName(policy.ExitServerID)),
		fmt.Sprintf("模式: %s", policy.Mode),
		"状态: failed",
		fmt.Sprintf("本地代理: %s", describeVPNLocalAccess(policy)),
	}
	if strings.TrimSpace(reason) != "" {
		lines = append(lines, "错误原因: "+strings.TrimSpace(reason))
	}
	lines = append(lines, "时间: "+time.Now().Format(time.RFC3339))
	return strings.Join(lines, "\n")
}

func vpnEgressProbeSummary(logs []string) string {
	for i := len(logs) - 1; i >= 0; i-- {
		line := strings.TrimSpace(logs[i])
		idx := strings.Index(line, "[egress]")
		if idx < 0 {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(line[idx:], "[egress]"))
	}
	return ""
}

func (v *VPNClass) notifyLost(policy *model.AgentVPNPolicy, session *model.AgentVPNSession, role string, reason string) {
	message := vpnNotificationBase("[Agent VPN] 已失联", policy, session, reason)
	message += "\n角色: " + role
	sendVPNNotification(policy.NotificationGroupID, message, "")
}

func (v *VPNClass) notifyFailure(policy *model.AgentVPNPolicy, session *model.AgentVPNSession, agentCleanupLogs string) {
	message := vpnNotificationBase("[Agent VPN] 启动失败", policy, session, session.LastError)
	if strings.TrimSpace(agentCleanupLogs) != "" {
		message += "\nAgent 清理日志: " + agentCleanupLogs
	}
	sendVPNNotification(policy.NotificationGroupID, message, "")
}

func (v *VPNClass) notifyLifecycleFailure(policy *model.AgentVPNPolicy, session *model.AgentVPNSession, action string, agentCleanupLogs string) {
	if action == model.VPNActionRestart {
		v.notifyRestartFailure(policy, session, agentCleanupLogs)
		return
	}
	v.notifyFailure(policy, session, agentCleanupLogs)
}

func (v *VPNClass) notifyRestartFailure(policy *model.AgentVPNPolicy, session *model.AgentVPNSession, agentCleanupLogs string) {
	message := vpnNotificationBase("[Agent VPN] 重启失败", policy, session, session.LastError)
	if strings.TrimSpace(agentCleanupLogs) != "" {
		message += "\nAgent 清理日志: " + agentCleanupLogs
	}
	sendVPNNotification(policy.NotificationGroupID, message, "")
}

func (v *VPNClass) notifyRuntimeFailure(policy *model.AgentVPNPolicy, session *model.AgentVPNSession, cleanupErrors []string, agentCleanupLogs string) {
	message := vpnNotificationBase("[Agent VPN] 异常停止", policy, session, session.LastError)
	if len(cleanupErrors) > 0 {
		message += "\n清理下发失败: " + strings.Join(cleanupErrors, "; ")
	}
	if strings.TrimSpace(agentCleanupLogs) != "" {
		message += "\nAgent 清理日志: " + agentCleanupLogs
	}
	sendVPNNotification(policy.NotificationGroupID, message, "")
}

func (v *VPNClass) recordStartSessionPreflightFailure(actor VPNActor, policy *model.AgentVPNPolicy, cause error, stage string) {
	if policy == nil || cause == nil {
		return
	}
	detail := vpnPolicyAuditDetail(policy)
	if stage != "" {
		if detail == nil {
			detail = map[string]string{}
		}
		detail["stage"] = stage
	}
	_ = v.writeAudit(actor, model.VPNAuditActionStartSession, "", policy.EntryServerID, policy.ExitServerID, false, cause.Error(), detail)
	sendVPNNotification(policy.NotificationGroupID, vpnPolicyFailureNotification("[Agent VPN] 启动失败", policy, cause.Error()), "")
}

func (v *VPNClass) recordRestartSessionPreflightFailure(actor VPNActor, session *model.AgentVPNSession, policy *model.AgentVPNPolicy, cause error, stage string, action string) {
	if session == nil || policy == nil || cause == nil {
		return
	}
	v.appendControlLog(session.SessionID, "%s preflight failed stage=%s: %s", action, stage, cause.Error())
	detail := vpnPolicyAuditDetail(policy)
	if detail == nil {
		detail = map[string]string{}
	}
	if stage != "" {
		detail["stage"] = stage
	}
	_ = v.writeAudit(actor, model.VPNAuditActionRestart, session.SessionID, session.EntryServerID, session.ExitServerID, false, cause.Error(), detail)
	if action != model.VPNActionRestart {
		return
	}
	snapshot := *session
	snapshot.LastError = cause.Error()
	v.notifyRestartFailure(policy, &snapshot, "")
}

func buildVPNControlRequest(session *model.AgentVPNSession, policy *model.AgentVPNPolicy, role string, action string, token string) model.VPNControlRequest {
	peerServerID := session.ExitServerID
	relayStreamID := session.EntryStreamID
	if role == model.VPNRoleExit {
		peerServerID = session.EntryServerID
		relayStreamID = session.ExitStreamID
	}
	req := model.VPNControlRequest{
		SessionID:     session.SessionID,
		Action:        action,
		Role:          role,
		Mode:          policy.Mode,
		RelayMode:     normalizeVPNRelayMode(session.RelayMode),
		PeerServerID:  peerServerID,
		RelayStreamID: relayStreamID,
		Token:         token,
		ExpiresAtUnix: session.ExpiresAt.Unix(),
		ListenHTTP:    policy.ListenHTTP,
		ListenSOCKS:   policy.ListenSOCKS,
		TunName:       policy.TunName,
		Rules: model.VPNRules{
			Mode:        policy.RuleMode,
			Domains:     policy.Domains,
			CIDRs:       policy.CIDRs,
			DirectCIDRs: policy.DirectCIDRs,
		},
		Limits: model.VPNLimits{
			MaxUploadBytes:     policy.MaxUploadBytes,
			MaxDownloadBytes:   policy.MaxDownloadBytes,
			MaxConnections:     policy.MaxConnections,
			IdleTimeoutSeconds: policy.IdleTimeoutSeconds,
		},
		Core:            buildVPNCoreSpec(policy),
		DashboardBypass: buildVPNDashboardBypass(session),
	}
	setVPNRequestExtra(&req, "core_session_id", policyCoreSessionID(policy.ID))
	if action == model.VPNActionPrepare {
		req.PeerServerID = 0
		req.RelayStreamID = ""
		req.Token = ""
		req.ListenHTTP = ""
		req.ListenSOCKS = ""
		req.TunName = ""
		req.Rules = model.VPNRules{}
		req.Limits = model.VPNLimits{}
		req.DashboardBypass = nil
		return req
	}
	if role == model.VPNRoleEntry && isVPNTunMode(policy.Mode) {
		req.DNSServer = strings.TrimSpace(policy.DNSServer)
	}
	if role == model.VPNRoleEntry {
		setVPNRequestExtra(&req, "set_system_proxy", fmt.Sprint(policy.SetSystemProxy))
	}
	if role == model.VPNRoleEntry && isVPNTunMode(policy.Mode) && strings.TrimSpace(policy.TunHealthURL) != "" {
		setVPNRequestExtra(&req, "tun_health_url", strings.TrimSpace(policy.TunHealthURL))
		if policy.TunHealthTimeoutSeconds > 0 {
			setVPNRequestExtra(&req, "tun_health_timeout_seconds", fmt.Sprint(policy.TunHealthTimeoutSeconds))
		}
	}
	if role == model.VPNRoleEntry && strings.TrimSpace(policy.EgressProbeURL) != "" {
		setVPNRequestExtra(&req, "egress_probe_url", strings.TrimSpace(policy.EgressProbeURL))
		if expectedIPs := strings.Join(vpnServerPublicIPs(session.ExitServerID), ","); expectedIPs != "" {
			setVPNRequestExtra(&req, "egress_expected_ips", expectedIPs)
		}
	}
	return req
}

func updateSessionFromVPNResult(session *model.AgentVPNSession, result model.VPNControlResult) {
	if result.Role == model.VPNRoleEntry {
		session.EntryState = result.State
	} else if result.Role == model.VPNRoleExit {
		session.ExitState = result.State
	}
	if result.LocalHTTP != "" {
		session.LocalHTTP = result.LocalHTTP
	}
	if result.LocalSOCKS != "" {
		session.LocalSOCKS = result.LocalSOCKS
	}
	if result.TunName != "" {
		session.TunName = result.TunName
	}
	if result.Role == model.VPNRoleEntry {
		if result.RuntimeStatus != "" {
			session.RuntimeStatus = result.RuntimeStatus
		}
		if result.ModeStatus != "" {
			session.ModeStatus = result.ModeStatus
		}
		if result.RuleModeStatus != "" {
			session.RuleModeStatus = result.RuleModeStatus
		}
		if result.CoreStatus != "" {
			session.CoreStatus = result.CoreStatus
		}
		if result.CorePath != "" {
			session.CorePath = result.CorePath
		}
		if result.CoreVersion != "" {
			session.CoreVersion = result.CoreVersion
		}
		if result.RulesStatus != "" {
			session.RulesStatus = result.RulesStatus
		}
		if result.RulesPath != "" {
			session.RulesPath = result.RulesPath
		}
		if result.RulesVersion != "" {
			session.RulesVersion = result.RulesVersion
		}
		if result.SystemProxyApplied != nil {
			session.SystemProxyApplied = result.SystemProxyApplied
		}
		if result.SystemProxyStatus != "" {
			session.SystemProxyStatus = result.SystemProxyStatus
			session.SystemProxyCurrent = result.SystemProxyCurrent
			session.SystemProxyExpected = result.SystemProxyExpected
		}
		if result.TunStatus != "" {
			session.TunStatus = result.TunStatus
			session.TunInterface = result.TunInterface
		}
	}
	if result.UploadBytes != 0 {
		session.UploadBytes = result.UploadBytes
	}
	if result.DownloadBytes != 0 {
		session.DownloadBytes = result.DownloadBytes
	}
	if result.ActiveConns != 0 {
		session.ActiveConnections = result.ActiveConns
	}
	if result.LastError != "" {
		session.LastError = result.LastError
	}
}

func vpnControlResultDetail(result model.VPNControlResult) string {
	parts := make([]string, 0, 6)
	if result.LocalSOCKS != "" {
		parts = append(parts, "socks="+result.LocalSOCKS)
	}
	if result.LocalHTTP != "" {
		parts = append(parts, "http="+result.LocalHTTP)
	}
	if result.TunName != "" {
		parts = append(parts, "tun="+result.TunName)
	}
	if result.RuntimeStatus != "" {
		parts = append(parts, "runtime="+result.RuntimeStatus)
	}
	if result.RuleModeStatus != "" {
		parts = append(parts, "rule_mode="+result.RuleModeStatus)
	}
	if result.CoreStatus != "" {
		parts = append(parts, "core="+result.CoreStatus)
	}
	if result.RulesStatus != "" {
		parts = append(parts, "rules="+result.RulesStatus)
	}
	if result.SystemProxyApplied != nil {
		status := "cleared"
		if *result.SystemProxyApplied {
			status = "applied"
		}
		parts = append(parts, "system_proxy="+status)
	}
	if result.SystemProxyStatus != "" {
		parts = append(parts, "system_proxy_status="+result.SystemProxyStatus)
	}
	if result.TunStatus != "" {
		parts = append(parts, "tun_status="+result.TunStatus)
	}
	if result.UploadBytes != 0 || result.DownloadBytes != 0 {
		parts = append(parts, fmt.Sprintf("traffic=%d/%d", result.UploadBytes, result.DownloadBytes))
	}
	if result.ActiveConns != 0 {
		parts = append(parts, fmt.Sprintf("connections=%d", result.ActiveConns))
	}
	if result.LastError != "" {
		parts = append(parts, "error="+result.LastError)
	}
	if len(result.Logs) > 0 {
		parts = append(parts, fmt.Sprintf("agent_logs=%d", len(result.Logs)))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func reporterMatchesVPNRole(reporterServerID uint64, role string, session *model.AgentVPNSession) bool {
	switch role {
	case model.VPNRoleEntry:
		return reporterServerID == session.EntryServerID
	case model.VPNRoleExit:
		return reporterServerID == session.ExitServerID
	default:
		return false
	}
}

func actorCanUseVPNServer(actor VPNActor, serverID uint64) bool {
	server, ok := ServerShared.Get(serverID)
	if !ok || server == nil {
		return false
	}
	return actor.IsAdmin() || server.GetUserID() == actor.UserID
}

func actorCanUseVPNSession(actor VPNActor, session *model.AgentVPNSession) bool {
	if session == nil {
		return false
	}
	if !actor.IsAdmin() && session.GetUserID() != actor.UserID {
		return false
	}
	return actorCanUseVPNServer(actor, session.EntryServerID) && actorCanUseVPNServer(actor, session.ExitServerID)
}

func validateVPNServerCapabilities(policy *model.AgentVPNPolicy, entry *model.Server, exit *model.Server) error {
	if policy == nil {
		return errors.New("vpn policy is required")
	}
	if err := validateVPNRoleCapability(model.VPNRoleEntry, entry); err != nil {
		return err
	}
	if policy.Mode == model.VPNModeSystemProxy && !entry.Host.VPNAllowSystemProxy {
		return fmt.Errorf("entry server %d does not allow Agent VPN system_proxy mode", entry.ID)
	}
	if isVPNTunMode(policy.Mode) && !entry.Host.VPNAllowTun {
		return fmt.Errorf("entry server %d does not allow Agent VPN TUN mode", entry.ID)
	}
	if err := validateVPNRoleCapability(model.VPNRoleExit, exit); err != nil {
		return err
	}
	return nil
}

func fallbackVPNPolicyForSession(session *model.AgentVPNSession) *model.AgentVPNPolicy {
	if session == nil {
		return nil
	}
	return &model.AgentVPNPolicy{
		Name:           fmt.Sprintf("session %s", session.SessionID),
		EntryServerID:  session.EntryServerID,
		ExitServerID:   session.ExitServerID,
		Mode:           session.Mode,
		RuleMode:       session.RuleMode,
		ListenHTTP:     session.LocalHTTP,
		ListenSOCKS:    session.LocalSOCKS,
		TunName:        session.TunName,
		SetSystemProxy: session.SetSystemProxy,
	}
}

func (v *VPNClass) fallbackVPNPolicyForLostSession(session *model.AgentVPNSession) *model.AgentVPNPolicy {
	policy := fallbackVPNPolicyForSession(session)
	if session == nil {
		return policy
	}
	var sessionAudit model.AgentVPNAuditLog
	if err := DB.Where("session_id = ?", session.SessionID).
		Where("action IN ?", []string{
			model.VPNAuditActionStartSession,
			model.VPNAuditActionRestart,
			model.VPNAuditActionStopSession,
			model.VPNAuditActionStatus,
			model.VPNAuditActionControl,
		}).
		Order("id DESC").
		First(&sessionAudit).Error; err == nil {
		applyVPNPolicyAuditDetail(policy, sessionAudit.Detail)
	}
	if session.PolicyID != 0 {
		var policyAudit model.AgentVPNAuditLog
		if err := DB.Where("action IN ?", []string{
			model.VPNAuditActionCreatePolicy,
			model.VPNAuditActionUpdatePolicy,
			model.VPNAuditActionDeletePolicy,
		}).
			Where("entry_server_id = ? AND exit_server_id = ?", session.EntryServerID, session.ExitServerID).
			Order("id DESC").
			First(&policyAudit).Error; err == nil {
			if policy == nil {
				policy = &model.AgentVPNPolicy{}
			}
			if policyID := strings.TrimSpace(policyAudit.Detail["policy_id"]); policyID == fmt.Sprint(session.PolicyID) {
				applyVPNPolicyAuditDetail(policy, policyAudit.Detail)
			}
		}
	}

	if session.ControlOverride {
		return applyVPNSessionControls(policy, session)
	}
	return policy
}

func applyVPNPolicyAuditDetail(policy *model.AgentVPNPolicy, detail map[string]string) {
	if policy == nil || detail == nil {
		return
	}
	if value := strings.TrimSpace(detail["policy_name"]); value != "" {
		policy.Name = value
	}
	if value := strings.TrimSpace(detail["mode"]); value != "" {
		policy.Mode = value
	}
	if value := strings.TrimSpace(detail["rule_mode"]); value != "" {
		policy.RuleMode = value
	}
	if value := strings.TrimSpace(detail["domains"]); value != "" {
		policy.Domains = normalizeVPNStringList(strings.Split(value, ","))
	}
	if value := strings.TrimSpace(detail["cidrs"]); value != "" {
		policy.CIDRs = normalizeVPNStringList(strings.Split(value, ","))
	}
	if value := strings.TrimSpace(detail["direct_cidrs"]); value != "" {
		policy.DirectCIDRs = normalizeVPNStringList(strings.Split(value, ","))
	}
	if value := strings.TrimSpace(detail["listen_http"]); value != "" {
		policy.ListenHTTP = value
	}
	if value := strings.TrimSpace(detail["listen_socks"]); value != "" {
		policy.ListenSOCKS = value
	}
	if value := strings.TrimSpace(detail["tun_name"]); value != "" {
		policy.TunName = value
	}
	if value := strings.TrimSpace(detail["dns_server"]); value != "" {
		policy.DNSServer = value
	}
	if value := strings.TrimSpace(detail["notification_group_id"]); value != "" {
		if parsed, err := strconv.ParseUint(value, 10, 64); err == nil {
			policy.NotificationGroupID = parsed
		}
	}
	if value := strings.TrimSpace(detail["expires_seconds"]); value != "" {
		if parsed, err := strconv.ParseUint(value, 10, 32); err == nil {
			policy.ExpiresSeconds = uint32(parsed)
		}
	}
	if value := strings.TrimSpace(detail["max_upload_bytes"]); value != "" {
		if parsed, err := strconv.ParseUint(value, 10, 64); err == nil {
			policy.MaxUploadBytes = parsed
		}
	}
	if value := strings.TrimSpace(detail["max_download_bytes"]); value != "" {
		if parsed, err := strconv.ParseUint(value, 10, 64); err == nil {
			policy.MaxDownloadBytes = parsed
		}
	}
	if value := strings.TrimSpace(detail["max_connections"]); value != "" {
		if parsed, err := strconv.ParseUint(value, 10, 32); err == nil {
			policy.MaxConnections = uint32(parsed)
		}
	}
	if value := strings.TrimSpace(detail["idle_timeout_seconds"]); value != "" {
		if parsed, err := strconv.ParseUint(value, 10, 32); err == nil {
			policy.IdleTimeoutSeconds = uint32(parsed)
		}
	}
	if value := strings.TrimSpace(detail["auto_restart"]); value != "" {
		policy.AutoRestart = strings.EqualFold(value, "true")
	}
	if value := strings.TrimSpace(detail["set_system_proxy"]); value != "" {
		policy.SetSystemProxy = strings.EqualFold(value, "true")
	}
	if value := strings.TrimSpace(detail["tun_health_url"]); value != "" {
		policy.TunHealthURL = value
	}
	if value := strings.TrimSpace(detail["tun_health_timeout_seconds"]); value != "" {
		if parsed, err := strconv.ParseUint(value, 10, 32); err == nil {
			policy.TunHealthTimeoutSeconds = uint32(parsed)
		}
	}
	if value := strings.TrimSpace(detail["egress_probe_url"]); value != "" {
		policy.EgressProbeURL = value
	}
	if value := strings.TrimSpace(detail["core_version"]); value != "" {
		policy.CoreVersion = value
	}
	if value := strings.TrimSpace(detail["core_download_url"]); value != "" {
		policy.CoreDownloadURL = value
	}
	if value := strings.TrimSpace(detail["core_sha256"]); value != "" {
		policy.CoreSHA256 = value
	}
}

func validateVPNPolicyRuntime(policy *model.AgentVPNPolicy) error {
	if policy == nil {
		return errors.New("vpn policy is required")
	}
	if err := validateVPNMode(policy.Mode); err != nil {
		return err
	}
	if err := validateVPNRuleMode(policy.RuleMode); err != nil {
		return err
	}
	mode := normalizeVPNMode(policy.Mode)
	ruleMode := normalizeVPNRuleMode(policy.RuleMode)
	if mode == model.VPNModeSystemProxy && strings.TrimSpace(policy.ListenHTTP) == "" && strings.TrimSpace(policy.ListenSOCKS) == "" {
		return errors.New("system proxy mode requires http or socks listen address")
	}
	if err := validateVPNListenAddress("http listen address", policy.ListenHTTP); err != nil {
		return err
	}
	if err := validateVPNListenAddress("socks listen address", policy.ListenSOCKS); err != nil {
		return err
	}
	if err := validateVPNRules(ruleMode, policy.Domains, policy.CIDRs, policy.DirectCIDRs); err != nil {
		return err
	}
	if policy.ExpiresSeconds == 0 {
		return errors.New("expires seconds must be greater than 0")
	}
	if err := validateVPNTunHealthPolicy(mode, policy.TunHealthURL); err != nil {
		return err
	}
	if err := validateVPNEgressProbeURL(policy.EgressProbeURL); err != nil {
		return err
	}
	if err := validateVPNCoreSpec(policy.CoreDownloadURL, policy.CoreSHA256); err != nil {
		return err
	}
	return nil
}

func validateVPNRoleCapability(role string, server *model.Server) error {
	if server == nil {
		return fmt.Errorf("%s server not found", role)
	}
	if server.Host == nil || !server.Host.VPNEnabled {
		return fmt.Errorf("%s server %d has not reported Agent VPN capability", role, server.ID)
	}
	return nil
}

func normalizeVPNMode(mode string) string {
	switch strings.TrimSpace(mode) {
	case model.VPNModeTunSplit:
		return model.VPNModeTunSplit
	case model.VPNModeTunGlobal:
		return model.VPNModeTunGlobal
	default:
		return model.VPNModeSystemProxy
	}
}

func validateVPNMode(mode string) error {
	switch strings.TrimSpace(mode) {
	case "", model.VPNModeSystemProxy, model.VPNModeTunSplit, model.VPNModeTunGlobal:
		return nil
	default:
		return fmt.Errorf("unsupported vpn mode %q", mode)
	}
}

func normalizeVPNRelayMode(relayMode string) string {
	switch strings.TrimSpace(relayMode) {
	case model.VPNRelayModeDashboard:
		return model.VPNRelayModeDashboard
	default:
		return model.VPNRelayModeDashboard
	}
}

func normalizeVPNRuleMode(mode string) string {
	switch strings.TrimSpace(mode) {
	case model.VPNRuleModeDomain:
		return model.VPNRuleModeDomain
	case model.VPNRuleModeIP:
		return model.VPNRuleModeIP
	case model.VPNRuleModeDirect:
		return model.VPNRuleModeDirect
	default:
		return model.VPNRuleModeGlobal
	}
}

func validateVPNRuleMode(mode string) error {
	switch strings.TrimSpace(mode) {
	case "", model.VPNRuleModeGlobal, model.VPNRuleModeDomain, model.VPNRuleModeIP, model.VPNRuleModeDirect:
		return nil
	default:
		return fmt.Errorf("unsupported vpn rule mode %q", mode)
	}
}

func vpnRuntimeModesCompatible(current string, next string) bool {
	return vpnRuntimeModeFamily(current) == vpnRuntimeModeFamily(next)
}

func vpnRuntimeModeFamily(mode string) string {
	if isVPNTunMode(normalizeVPNMode(mode)) {
		return "tun"
	}
	return model.VPNModeSystemProxy
}

func normalizeVPNExpires(seconds uint32) uint32 {
	if seconds == 0 {
		return defaultVPNExpiresSeconds
	}
	return seconds
}

func normalizeVPNTunHealthTimeout(seconds uint32) uint32 {
	if seconds == 0 {
		return 10
	}
	if seconds > 60 {
		return 60
	}
	return seconds
}

func validateVPNListenAddress(label string, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("invalid %s: must be a valid host:port", label)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("invalid %s: port must be between 1 and 65535", label)
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("invalid %s: host must be localhost or a loopback IP address", label)
	}
	if !addr.IsLoopback() {
		return fmt.Errorf("invalid %s: host must be loopback", label)
	}
	return nil
}

func validateVPNRules(ruleMode string, domains []string, cidrs []string, directCIDRs []string) error {
	if ruleMode == model.VPNRuleModeDomain {
		for _, domain := range domains {
			if err := validateVPNDomain(domain); err != nil {
				return err
			}
		}
	}
	if ruleMode == model.VPNRuleModeIP {
		for _, cidr := range cidrs {
			if err := validateVPNCIDR("CIDR", cidr); err != nil {
				return err
			}
		}
	}
	for _, cidr := range directCIDRs {
		if err := validateVPNCIDR("direct CIDR", cidr); err != nil {
			return err
		}
	}
	return nil
}

func validateVPNCIDR(label string, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s must not be empty", label)
	}
	if _, err := netip.ParsePrefix(value); err != nil {
		return fmt.Errorf("invalid %s %q: %w", label, value, err)
	}
	return nil
}

func validateVPNDomain(value string) error {
	domain := strings.TrimSpace(value)
	if domain == "" {
		return errors.New("domain must not be empty")
	}
	if domain != value {
		return fmt.Errorf("invalid domain %q: surrounding whitespace is not allowed", value)
	}
	if len(domain) > 253 {
		return fmt.Errorf("invalid domain %q: too long", domain)
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("invalid domain %q", domain)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid domain %q", domain)
		}
		for _, r := range label {
			if r > unicode.MaxASCII || !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-') {
				return fmt.Errorf("invalid domain %q", domain)
			}
		}
	}
	return nil
}

func isVPNTunMode(mode string) bool {
	return mode == model.VPNModeTunSplit || mode == model.VPNModeTunGlobal
}

func validateVPNTunHealthPolicy(mode string, healthURL string) error {
	healthURL = strings.TrimSpace(healthURL)
	if healthURL == "" {
		return nil
	}
	if !isVPNTunMode(mode) {
		return errors.New("tun health probe is only supported for TUN mode")
	}
	parsed, err := url.ParseRequestURI(healthURL)
	if err != nil {
		return fmt.Errorf("invalid tun health url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("tun health url must use http or https")
	}
	return nil
}

func validateVPNEgressProbeURL(probeURL string) error {
	probeURL = strings.TrimSpace(probeURL)
	if probeURL == "" {
		return nil
	}
	parsed, err := url.ParseRequestURI(probeURL)
	if err != nil {
		return fmt.Errorf("invalid egress probe url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("egress probe url must use http or https")
	}
	return nil
}

func validateVPNCoreSpec(downloadURL string, sha256Value string) error {
	downloadURL = strings.TrimSpace(downloadURL)
	if downloadURL != "" {
		parsed, err := url.ParseRequestURI(downloadURL)
		if err != nil {
			return fmt.Errorf("invalid core download url: %w", err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return errors.New("core download url must use http or https")
		}
	}
	sha256Value = strings.TrimSpace(sha256Value)
	if sha256Value == "" {
		return nil
	}
	if !vpnSHA256HexPattern.MatchString(sha256Value) {
		return errors.New("core sha256 must be a 64-character hex digest without prefix")
	}
	return nil
}

func normalizeVPNStringList(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func vpnPolicyFromForm(userID uint64, form model.AgentVPNPolicyForm) *model.AgentVPNPolicy {
	policy := &model.AgentVPNPolicy{
		Common: model.Common{
			UserID: userID,
		},
		Name:                    strings.TrimSpace(form.Name),
		EntryServerID:           form.EntryServerID,
		ExitServerID:            form.ExitServerID,
		Mode:                    normalizeVPNMode(form.Mode),
		RuleMode:                normalizeVPNRuleMode(form.RuleMode),
		Domains:                 normalizeVPNStringList(form.Domains),
		CIDRs:                   normalizeVPNStringList(form.CIDRs),
		DirectCIDRs:             normalizeVPNStringList(form.DirectCIDRs),
		ListenHTTP:              strings.TrimSpace(form.ListenHTTP),
		ListenSOCKS:             strings.TrimSpace(form.ListenSOCKS),
		TunName:                 strings.TrimSpace(form.TunName),
		DNSServer:               strings.TrimSpace(form.DNSServer),
		ExpiresSeconds:          normalizeVPNExpires(form.ExpiresSeconds),
		MaxUploadBytes:          form.MaxUploadBytes,
		MaxDownloadBytes:        form.MaxDownloadBytes,
		MaxConnections:          form.MaxConnections,
		IdleTimeoutSeconds:      form.IdleTimeoutSeconds,
		NotificationGroupID:     form.NotificationGroupID,
		AutoRestart:             form.AutoRestart,
		SetSystemProxy:          form.SetSystemProxy,
		TunHealthURL:            strings.TrimSpace(form.TunHealthURL),
		TunHealthTimeoutSeconds: normalizeVPNTunHealthTimeout(form.TunHealthTimeoutSeconds),
		EgressProbeURL:          strings.TrimSpace(form.EgressProbeURL),
		CoreVersion:             strings.TrimSpace(form.CoreVersion),
		CoreDownloadURL:         strings.TrimSpace(form.CoreDownloadURL),
		CoreSHA256:              strings.TrimSpace(form.CoreSHA256),
	}
	if policy.Name == "" {
		policy.Name = fmt.Sprintf("VPN %d -> %d", policy.EntryServerID, policy.ExitServerID)
	}
	return policy
}

func buildVPNCoreSpec(policy *model.AgentVPNPolicy) model.VPNCoreSpec {
	spec := model.VPNCoreSpec{
		Name:        "sing-box",
		Version:     strings.TrimSpace(policy.CoreVersion),
		SHA256:      strings.TrimSpace(policy.CoreSHA256),
		DownloadURL: strings.TrimSpace(policy.CoreDownloadURL),
	}
	if spec.DownloadURL != "" {
		return spec
	}
	spec.DownloadBaseURL = defaultVPNCoreDownloadBaseURL
	spec.CNDownloadBaseURL = defaultVPNCoreCNDownloadBaseURL
	spec.ManifestURL = defaultVPNCoreManifestURL
	spec.CNManifestURL = defaultVPNCoreCNManifestURL
	return spec
}

func setVPNRequestExtra(req *model.VPNControlRequest, key string, value string) {
	if req.Extra == nil {
		req.Extra = map[string]string{}
	}
	req.Extra[key] = value
}

func hashVPNToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func defaultVPNDashboardBypass() []string {
	return nil
}

func buildVPNDashboardBypass(session *model.AgentVPNSession) []string {
	values := defaultVPNDashboardBypass()
	values = append(values, vpnDashboardInstallHost()...)
	values = append(values, vpnServerPublicIPs(session.EntryServerID)...)
	values = append(values, vpnServerPublicIPs(session.ExitServerID)...)
	return normalizeVPNStringList(values)
}

func vpnDashboardInstallHost() []string {
	if Conf == nil || Conf.Config == nil {
		return nil
	}
	host := strings.TrimSpace(Conf.InstallHost)
	if host == "" {
		return nil
	}
	return []string{hostWithoutPort(host)}
}

func vpnServerPublicIPs(serverID uint64) []string {
	server, ok := ServerShared.Get(serverID)
	if !ok || server == nil || server.GeoIP == nil {
		return nil
	}
	ips := []string{server.GeoIP.IP.IPv4Addr, server.GeoIP.IP.IPv6Addr}
	return normalizeVPNStringList(ips)
}

func hostWithoutPort(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Host != "" {
		value = parsed.Host
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(value, "[]")
}

func describeVPNRules(policy *model.AgentVPNPolicy) string {
	switch policy.RuleMode {
	case model.VPNRuleModeDomain:
		if len(policy.Domains) > 0 {
			return strings.Join(policy.Domains, ", ")
		}
	case model.VPNRuleModeIP:
		if len(policy.CIDRs) > 0 {
			return strings.Join(policy.CIDRs, ", ")
		}
	}
	return policy.RuleMode
}

func describeVPNLocalProxy(policy *model.AgentVPNPolicy) string {
	parts := make([]string, 0, 2)
	if policy.ListenHTTP != "" {
		parts = append(parts, "HTTP "+policy.ListenHTTP)
	}
	if policy.ListenSOCKS != "" {
		parts = append(parts, "SOCKS "+policy.ListenSOCKS)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " / ")
}

func describeVPNLocalAccess(policy *model.AgentVPNPolicy) string {
	if policy == nil {
		return "-"
	}
	if isVPNTunMode(policy.Mode) {
		tunName := strings.TrimSpace(policy.TunName)
		if tunName == "" {
			tunName = "nezha-vpn"
		}
		return "TUN " + tunName
	}
	return describeVPNLocalProxy(policy)
}

func describeVPNTrafficLimit(policy *model.AgentVPNPolicy) string {
	parts := make([]string, 0, 2)
	if policy.MaxUploadBytes > 0 {
		parts = append(parts, fmt.Sprintf("上传 %d B", policy.MaxUploadBytes))
	}
	if policy.MaxDownloadBytes > 0 {
		parts = append(parts, fmt.Sprintf("下载 %d B", policy.MaxDownloadBytes))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " / ")
}

func describeVPNConnectionLimit(policy *model.AgentVPNPolicy) string {
	if policy == nil || policy.MaxConnections == 0 {
		return "-"
	}
	return fmt.Sprintf("连接数 %d", policy.MaxConnections)
}

func vpnTrafficLimitExceeded(policy *model.AgentVPNPolicy, uploadBytes uint64, downloadBytes uint64) (bool, string) {
	if policy == nil {
		return false, ""
	}
	if policy.MaxUploadBytes > 0 && uploadBytes > policy.MaxUploadBytes {
		return true, fmt.Sprintf("upload traffic limit exceeded: %d > %d", uploadBytes, policy.MaxUploadBytes)
	}
	if policy.MaxDownloadBytes > 0 && downloadBytes > policy.MaxDownloadBytes {
		return true, fmt.Sprintf("download traffic limit exceeded: %d > %d", downloadBytes, policy.MaxDownloadBytes)
	}
	return false, ""
}

func vpnConnectionLimitExceeded(policy *model.AgentVPNPolicy, activeConnections uint32) (bool, string) {
	if policy == nil || policy.MaxConnections == 0 {
		return false, ""
	}
	if activeConnections > policy.MaxConnections {
		return true, fmt.Sprintf("connection limit exceeded: %d > %d", activeConnections, policy.MaxConnections)
	}
	return false, ""
}

func shouldAutoRestartVPNSession(policy *model.AgentVPNPolicy, session *model.AgentVPNSession, now time.Time) bool {
	if policy == nil || session == nil || !policy.AutoRestart {
		return false
	}
	if !session.ExpiresAt.IsZero() && !session.ExpiresAt.After(now) {
		return false
	}
	return session.State == model.VPNStateLost || session.State == model.VPNStateFailed
}

func policyCoreSessionID(policyID uint64) string {
	return fmt.Sprintf("core_policy_%d", policyID)
}

func isPolicyCoreSessionID(sessionID string) bool {
	if !strings.HasPrefix(sessionID, "core_policy_") {
		return false
	}
	_, err := strconv.ParseUint(strings.TrimPrefix(sessionID, "core_policy_"), 10, 64)
	return err == nil
}

func isVPNTerminalState(state string) bool {
	return state == model.VPNStateStopped
}

func (v *VPNClass) sessionAndPolicyByID(sessionID string) (*model.AgentVPNSession, *model.AgentVPNPolicy, error) {
	var session model.AgentVPNSession
	if err := DB.Where("session_id = ?", strings.TrimSpace(sessionID)).First(&session).Error; err != nil {
		return nil, nil, err
	}
	policy, err := v.policyForSession(&session)
	if err != nil {
		policy = v.fallbackVPNPolicyForLostSession(&session)
	}
	return &session, policy, nil
}

func serverName(serverID uint64) string {
	server, ok := ServerShared.Get(serverID)
	if !ok || server == nil || strings.TrimSpace(server.Name) == "" {
		return fmt.Sprintf("#%d", serverID)
	}
	return server.Name
}

func cloneVPNPolicy(policy *model.AgentVPNPolicy) *model.AgentVPNPolicy {
	if policy == nil {
		return nil
	}
	clone := *policy
	clone.Domains = append([]string(nil), policy.Domains...)
	clone.CIDRs = append([]string(nil), policy.CIDRs...)
	clone.DirectCIDRs = append([]string(nil), policy.DirectCIDRs...)
	return &clone
}

func applyVPNSessionControls(policy *model.AgentVPNPolicy, session *model.AgentVPNSession) *model.AgentVPNPolicy {
	if policy == nil || session == nil {
		return policy
	}
	if !session.ControlOverride {
		return policy
	}
	if strings.TrimSpace(session.Mode) != "" {
		policy.Mode = normalizeVPNMode(session.Mode)
	}
	if strings.TrimSpace(session.RuleMode) != "" {
		policy.RuleMode = normalizeVPNRuleMode(session.RuleMode)
		policy.SetSystemProxy = session.SetSystemProxy
	}
	if strings.TrimSpace(session.LocalHTTP) != "" {
		policy.ListenHTTP = session.LocalHTTP
	}
	if strings.TrimSpace(session.LocalSOCKS) != "" {
		policy.ListenSOCKS = session.LocalSOCKS
	}
	if strings.TrimSpace(session.TunName) != "" {
		policy.TunName = session.TunName
	}
	return policy
}
