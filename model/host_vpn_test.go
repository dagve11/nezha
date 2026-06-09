package model

import (
	"testing"

	pb "github.com/nezhahq/nezha/proto"
)

func TestPB2HostReadsVPNCapabilitiesFromHostReport(t *testing.T) {
	payload := &pb.Host{
		VpnEnabled:          true,
		VpnAllowSystemProxy: true,
		VpnAllowTun:         false,
		VpnCoreVersion:      "1.12.0",
		VpnLastError:        "Core not installed",
	}

	host := PB2Host(payload)

	if !host.VPNEnabled {
		t.Fatal("PB2Host must decode vpn_enabled from Agent host report")
	}
	if !host.VPNAllowSystemProxy {
		t.Fatal("PB2Host must decode vpn_allow_system_proxy from Agent host report")
	}
	if host.VPNAllowTun {
		t.Fatal("PB2Host must decode vpn_allow_tun=false from Agent host report")
	}
	if host.VPNCoreVersion != "1.12.0" {
		t.Fatalf("VPNCoreVersion = %q, want 1.12.0", host.VPNCoreVersion)
	}
	if host.VPNLastError != "Core not installed" {
		t.Fatalf("VPNLastError = %q, want Core not installed", host.VPNLastError)
	}
}

func TestHostFilterKeepsVPNCapabilityForDashboardOverview(t *testing.T) {
	host := (&Host{
		Platform:            "linux",
		Arch:                "amd64",
		VPNEnabled:          true,
		VPNAllowSystemProxy: true,
		VPNAllowTun:         true,
		VPNCoreVersion:      "1.12.0",
		VPNLastError:        "",
	}).Filter()

	if !host.VPNEnabled || !host.VPNAllowSystemProxy || !host.VPNAllowTun {
		t.Fatalf("filtered Host dropped VPN capabilities: %#v", host)
	}
	if host.VPNCoreVersion != "1.12.0" {
		t.Fatalf("filtered Host core version = %q, want 1.12.0", host.VPNCoreVersion)
	}
}

func TestPB2HostHandlesNilHostReport(t *testing.T) {
	host := PB2Host(nil)

	if host.VPNEnabled || host.VPNAllowSystemProxy || host.VPNAllowTun {
		t.Fatalf("nil Host report should not advertise VPN capability: %#v", host)
	}
	if host.Platform != "" || host.Arch != "" {
		t.Fatalf("nil Host report should decode to zero-value Host: %#v", host)
	}
}
