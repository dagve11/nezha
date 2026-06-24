package singleton

import (
	"strings"

	"github.com/nezhahq/nezha/model"
)

const (
	vpnDiagnosticCritical = "critical"
	vpnDiagnosticWarning  = "warning"
	vpnDiagnosticNotice   = "notice"
)

func (v *VPNClass) DecorateSessionDiagnostics(session *model.AgentVPNSession) {
	if session == nil {
		return
	}
	logs := []string(nil)
	if v != nil {
		logs = v.SessionLogs(session.SessionID)
	}
	session.Diagnostics = VPNDiagnosticsForSession(session, logs)
}

func (v *VPNClass) DecorateSessionsDiagnostics(sessions []*model.AgentVPNSession) {
	for _, session := range sessions {
		v.DecorateSessionDiagnostics(session)
	}
}

func VPNDiagnosticsForSession(session *model.AgentVPNSession, logs []string) []model.VPNDiagnostic {
	if session == nil {
		return nil
	}

	var out []model.VPNDiagnostic
	seen := make(map[string]struct{})
	add := func(diag model.VPNDiagnostic) {
		if diag.Code == "" {
			return
		}
		if _, ok := seen[diag.Code]; ok {
			return
		}
		seen[diag.Code] = struct{}{}
		out = append(out, diag)
	}

	if session.RecoveryState == model.VPNRecoveryStateScheduled || session.RecoveryState == model.VPNRecoveryStateRestarting {
		add(model.VPNDiagnostic{
			Code:     "RecoveryActive",
			Severity: vpnDiagnosticNotice,
			Source:   "session",
			Message:  firstNonEmptyString(session.RecoveryLastError, session.LastError),
		})
	}
	if session.RecoveryState == model.VPNRecoveryStateExhausted {
		add(model.VPNDiagnostic{
			Code:     "RecoveryExhausted",
			Severity: vpnDiagnosticCritical,
			Source:   "session",
			Message:  firstNonEmptyString(session.RecoveryLastError, session.LastError),
		})
	}
	if session.State == model.VPNStateRunning && (session.RuntimeStatus == "inactive" || session.RuntimeStatus == "unavailable") {
		add(model.VPNDiagnostic{
			Code:     "RuntimeInactive",
			Severity: vpnDiagnosticWarning,
			Source:   "session",
			Message:  session.RuntimeStatus,
		})
	}

	for _, candidate := range []struct {
		source  string
		message string
	}{
		{source: "last_error", message: session.LastError},
		{source: "recovery_last_error", message: session.RecoveryLastError},
	} {
		if diag, ok := diagnoseVPNText(candidate.message); ok {
			diag.Source = candidate.source
			add(diag)
		}
	}

	for i := len(logs) - 1; i >= 0 && len(out) < 6; i-- {
		if diag, ok := diagnoseVPNText(logs[i]); ok {
			diag.Source = "log"
			if diag.Message == "" {
				diag.Message = trimVPNDiagnosticMessage(logs[i])
			}
			add(diag)
		}
	}

	return out
}

func diagnoseVPNText(value string) (model.VPNDiagnostic, bool) {
	text := strings.ToLower(strings.TrimSpace(vpnANSISequence.ReplaceAllString(value, "")))
	if text == "" {
		return model.VPNDiagnostic{}, false
	}

	diag := func(code string, severity string) (model.VPNDiagnostic, bool) {
		return model.VPNDiagnostic{
			Code:     code,
			Severity: severity,
			Message:  trimVPNDiagnosticMessage(value),
		}, true
	}

	switch {
	case strings.Contains(text, "fatal") &&
		(strings.Contains(text, "decode config") ||
			strings.Contains(text, "legacy inbound fields") ||
			strings.Contains(text, "removed in sing-box")):
		return diag("CoreConfigIncompatible", vpnDiagnosticCritical)
	case strings.Contains(text, "direct websocket dial failed") &&
		(strings.Contains(text, "404") || strings.Contains(text, "not found") || strings.Contains(text, "bad handshake")):
		return diag("WSSRouteNotFound", vpnDiagnosticWarning)
	case strings.Contains(text, "websocket: close 1006") ||
		strings.Contains(text, "unexpected eof") ||
		strings.Contains(text, "websocket bad handshake"):
		return diag("WSSHandshakeClosed", vpnDiagnosticWarning)
	case strings.Contains(text, "handshake timestamp expired") || strings.Contains(text, "local cmos clock"):
		return diag("ClockNotSynced", vpnDiagnosticWarning)
	case strings.Contains(text, "heartbeat_timeout") || strings.Contains(text, "heartbeat timeout"):
		return diag("HeartbeatTimeout", vpnDiagnosticWarning)
	case strings.Contains(text, "connection: open connection to") &&
		(strings.Contains(text, "i/o timeout") ||
			strings.Contains(text, "context deadline exceeded") ||
			strings.Contains(text, "did not properly respond")):
		return diag("DestinationTimeout", vpnDiagnosticNotice)
	case strings.Contains(text, "i/o timeout") ||
		strings.Contains(text, "did not properly respond") ||
		strings.Contains(text, "context deadline exceeded"):
		return diag("ConnectTimeout", vpnDiagnosticWarning)
	case strings.Contains(text, "network is unreachable") || strings.Contains(text, "no route to host"):
		return diag("RouteUnavailable", vpnDiagnosticWarning)
	case strings.Contains(text, "failed to receive handshake") ||
		strings.Contains(text, "connection was reset") ||
		strings.Contains(text, "connection reset") ||
		strings.Contains(text, "recv failure"):
		return diag("TLSConnectionReset", vpnDiagnosticWarning)
	case strings.Contains(text, "connection upload closed") ||
		strings.Contains(text, "connection download closed") ||
		strings.Contains(text, "forcibly closed by the remote host"):
		return diag("RemoteClosed", vpnDiagnosticNotice)
	case strings.Contains(text, "lookup ") &&
		(strings.Contains(text, "nxdomain") || strings.Contains(text, "empty result") || strings.Contains(text, "no such host")):
		return diag("DNSFailed", vpnDiagnosticNotice)
	case strings.Contains(text, "socks5: request rejected"):
		return diag("SocksRejected", vpnDiagnosticWarning)
	case strings.Contains(text, "address already in use") || strings.Contains(text, "bind:"):
		return diag("PortInUse", vpnDiagnosticCritical)
	case strings.Contains(text, "actively refused") || strings.Contains(text, "connection refused"):
		return diag("LocalServiceRefused", vpnDiagnosticWarning)
	case strings.Contains(text, "missing default interface"):
		return diag("MissingDefaultInterface", vpnDiagnosticWarning)
	case strings.Contains(text, "legacy inbound fields") || strings.Contains(text, "legacy domain strategy"):
		return diag("SingBoxConfigDeprecated", vpnDiagnosticNotice)
	case strings.Contains(text, "certificate") ||
		strings.Contains(text, "unknown authority") ||
		strings.Contains(text, "fingerprint mismatch") ||
		strings.Contains(text, "direct_cert_sha256 is required"):
		return diag("CertificateProblem", vpnDiagnosticWarning)
	case strings.Contains(text, "unknown vpn direct session") ||
		strings.Contains(text, "invalid vpn direct session token") ||
		strings.Contains(text, "unknown or invalid vpn direct session"):
		return diag("DirectSessionMismatch", vpnDiagnosticWarning)
	case strings.Contains(text, "system proxy") ||
		strings.Contains(text, "proxyserver") ||
		strings.Contains(text, "proxyoverride") ||
		strings.Contains(text, "reg delete"):
		return diag("SystemProxyCleanup", vpnDiagnosticWarning)
	case strings.Contains(text, "state=kept-for-restore-retry") ||
		(strings.Contains(text, "sidecar_pid") && strings.Contains(text, "kill=failed")) ||
		strings.Contains(text, "access is denied"):
		return diag("CleanupRetry", vpnDiagnosticNotice)
	case strings.Contains(text, "agent is offline") || (strings.Contains(text, "server ") && strings.Contains(text, " is offline")):
		return diag("AgentOffline", vpnDiagnosticWarning)
	case strings.Contains(text, "using outbound/direct[direct]"):
		return diag("DirectOutboundUsed", vpnDiagnosticNotice)
	default:
		return model.VPNDiagnostic{}, false
	}
}

func trimVPNDiagnosticMessage(value string) string {
	value = strings.TrimSpace(vpnANSISequence.ReplaceAllString(value, ""))
	value = vpnLogTimestamp.ReplaceAllString(value, "")
	if len(value) <= 240 {
		return value
	}
	return value[:237] + "..."
}
