package singleton

import (
	"testing"

	"github.com/nezhahq/nezha/model"
)

func TestVPNDiagnosticsClassifiesOperationalNoiseAsNotice(t *testing.T) {
	session := &model.AgentVPNSession{SessionID: "s1", State: model.VPNStateRunning}
	logs := []string{
		`[15:41:27] ERROR connection: open connection to ads-twitter.com:443 using outbound/direct[direct]: lookup ads-twitter.com: empty result`,
		`[15:41:27] ERROR connection: open connection to 88.191.249.182:443 using outbound/direct[direct]: dial tcp 88.191.249.182:443: i/o timeout`,
	}

	diagnostics := VPNDiagnosticsForSession(session, logs)

	assertVPNDiagnostic(t, diagnostics, "DNSFailed", vpnDiagnosticNotice)
	assertVPNDiagnostic(t, diagnostics, "DestinationTimeout", vpnDiagnosticNotice)
}

func TestVPNDiagnosticsClassifiesActionableFailures(t *testing.T) {
	session := &model.AgentVPNSession{
		SessionID:     "s1",
		State:         model.VPNStateFailed,
		LastError:     `start service: start inbound/socks[relay-in]: listen tcp 127.0.0.1:19091: bind: address already in use`,
		RuntimeStatus: "inactive",
	}
	logs := []string{
		`FATAL decode config at /opt/agent/config.json: legacy inbound fields are deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0`,
	}

	diagnostics := VPNDiagnosticsForSession(session, logs)

	assertVPNDiagnostic(t, diagnostics, "PortInUse", vpnDiagnosticCritical)
	assertVPNDiagnostic(t, diagnostics, "CoreConfigIncompatible", vpnDiagnosticCritical)
}

func TestVPNDiagnosticsAddsRecoveryState(t *testing.T) {
	session := &model.AgentVPNSession{
		SessionID:         "s1",
		State:             model.VPNStateStarting,
		RecoveryState:     model.VPNRecoveryStateScheduled,
		RecoveryLastError: "heartbeat timeout",
		RecoveryAttempt:   1,
		RecoveryReason:    model.VPNFailureReasonHeartbeatTimeout,
		RuntimeInstanceID: "runtime-1",
		RuntimeStatus:     "available",
		ActiveConnections: 1,
		UploadBytes:       1024,
		DownloadBytes:     2048,
	}

	diagnostics := VPNDiagnosticsForSession(session, nil)

	assertVPNDiagnostic(t, diagnostics, "RecoveryActive", vpnDiagnosticNotice)
	assertVPNDiagnostic(t, diagnostics, "HeartbeatTimeout", vpnDiagnosticWarning)
}

func assertVPNDiagnostic(t *testing.T, diagnostics []model.VPNDiagnostic, code string, severity string) {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			if diagnostic.Severity != severity {
				t.Fatalf("diagnostic %s severity = %q, want %q", code, diagnostic.Severity, severity)
			}
			return
		}
	}
	t.Fatalf("diagnostic %s not found in %#v", code, diagnostics)
}
