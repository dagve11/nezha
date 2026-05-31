package rpc

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/nezhahq/nezha/model"
)

func TestNATPortManagerStartsUpdatesAndDeletesListener(t *testing.T) {
	port := freeTCPPort(t)
	manager := NewNATPortManager("127.0.0.1", func(conn net.Conn, nat *model.NAT) {
		defer conn.Close()
		_, _ = conn.Write([]byte(nat.Host))
	})
	defer manager.StopAll()

	err := manager.Upsert(&model.NAT{
		Common:   model.Common{ID: 1},
		Enabled:  true,
		Name:     "ssh",
		ServerID: 1,
		Host:     "first-target:22",
		Port:     port,
	})
	if err != nil {
		t.Fatalf("Upsert first NAT: %v", err)
	}
	if got := readFromNATPort(t, port); got != "first-target:22" {
		t.Fatalf("read first NAT = %q, want %q", got, "first-target:22")
	}

	err = manager.Upsert(&model.NAT{
		Common:   model.Common{ID: 1},
		Enabled:  true,
		Name:     "ssh",
		ServerID: 1,
		Host:     "second-target:22",
		Port:     port,
	})
	if err != nil {
		t.Fatalf("Upsert updated NAT: %v", err)
	}
	if got := readFromNATPort(t, port); got != "second-target:22" {
		t.Fatalf("read updated NAT = %q, want %q", got, "second-target:22")
	}

	manager.Delete(1)
	_, err = net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoaPort(port)), 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected NAT listener to be closed")
	}
}

func TestNATPortManagerRejectsOccupiedPort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen occupied port: %v", err)
	}
	defer l.Close()

	port := uint16(l.Addr().(*net.TCPAddr).Port)
	manager := NewNATPortManager("127.0.0.1", func(conn net.Conn, nat *model.NAT) {
		conn.Close()
	})
	defer manager.StopAll()

	err = manager.Upsert(&model.NAT{
		Common:   model.Common{ID: 1},
		Enabled:  true,
		Name:     "ssh",
		ServerID: 1,
		Host:     "127.0.0.1:22",
		Port:     port,
	})
	if err == nil {
		t.Fatal("expected occupied port to be rejected")
	}
}

func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free port: %v", err)
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

func readFromNATPort(t *testing.T, port uint16) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoaPort(port)), time.Second)
	if err != nil {
		t.Fatalf("dial NAT port: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read NAT port: %v", err)
	}
	return string(buf[:n])
}

func itoaPort(port uint16) string {
	return strconv.Itoa(int(port))
}
