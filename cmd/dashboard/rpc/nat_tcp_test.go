package rpc

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/nezhahq/nezha/model"
	pb "github.com/nezhahq/nezha/proto"
	rpcService "github.com/nezhahq/nezha/service/rpc"
	"github.com/nezhahq/nezha/service/singleton"
	"google.golang.org/grpc/metadata"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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
	assertNATPortClosed(t, port)
}

func TestNATPortManagerPortChangeClosesOldListener(t *testing.T) {
	firstPort := freeTCPPort(t)
	secondPort := freeTCPPort(t)
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
		Port:     firstPort,
	})
	if err != nil {
		t.Fatalf("Upsert first NAT: %v", err)
	}

	err = manager.Upsert(&model.NAT{
		Common:   model.Common{ID: 1},
		Enabled:  true,
		Name:     "ssh",
		ServerID: 1,
		Host:     "second-target:22",
		Port:     secondPort,
	})
	if err != nil {
		t.Fatalf("Upsert moved NAT: %v", err)
	}
	assertNATPortClosed(t, firstPort)
	if got := readFromNATPort(t, secondPort); got != "second-target:22" {
		t.Fatalf("read moved NAT = %q, want %q", got, "second-target:22")
	}
}

func TestNATPortManagerSyncRemovesStaleListeners(t *testing.T) {
	firstPort := freeTCPPort(t)
	secondPort := freeTCPPort(t)
	manager := NewNATPortManager("127.0.0.1", func(conn net.Conn, nat *model.NAT) {
		defer conn.Close()
		_, _ = conn.Write([]byte(nat.Host))
	})
	defer manager.StopAll()

	err := manager.Sync([]*model.NAT{
		{
			Common:   model.Common{ID: 1},
			Enabled:  true,
			Name:     "ssh",
			ServerID: 1,
			Host:     "first-target:22",
			Port:     firstPort,
		},
		{
			Common:   model.Common{ID: 2},
			Enabled:  true,
			Name:     "web",
			ServerID: 2,
			Host:     "second-target:80",
			Port:     secondPort,
		},
	})
	if err != nil {
		t.Fatalf("initial Sync: %v", err)
	}

	err = manager.Sync([]*model.NAT{
		{
			Common:   model.Common{ID: 2},
			Enabled:  true,
			Name:     "web",
			ServerID: 2,
			Host:     "second-target:80",
			Port:     secondPort,
		},
	})
	if err != nil {
		t.Fatalf("second Sync: %v", err)
	}
	assertNATPortClosed(t, firstPort)
	if got := readFromNATPort(t, secondPort); got != "second-target:80" {
		t.Fatalf("read retained NAT = %q, want %q", got, "second-target:80")
	}
}

func TestNATPortManagerDoesNotListenWhenDisabled(t *testing.T) {
	port := freeTCPPort(t)
	manager := NewNATPortManager("127.0.0.1", func(conn net.Conn, nat *model.NAT) {
		conn.Close()
	})
	defer manager.StopAll()

	err := manager.Upsert(&model.NAT{
		Common:   model.Common{ID: 1},
		Enabled:  false,
		Name:     "ssh",
		ServerID: 1,
		Host:     "127.0.0.1:22",
		Port:     port,
	})
	if err != nil {
		t.Fatalf("Upsert disabled NAT: %v", err)
	}
	assertNATPortClosed(t, port)
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

func TestNATPortManagerForwardsThroughDashboardIOStream(t *testing.T) {
	port := freeTCPPort(t)
	taskStream := newNATCaptureTaskStream()
	setupNATForwardingFixture(t, taskStream)
	manager := NewNATPortManager("127.0.0.1", nil)
	defer manager.StopAll()

	err := manager.Upsert(&model.NAT{
		Common:   model.Common{ID: 42},
		Enabled:  true,
		Name:     "web",
		ServerID: 1,
		Host:     "127.0.0.1:8080",
		Port:     port,
	})
	if err != nil {
		t.Fatalf("Upsert NAT: %v", err)
	}

	publicConn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoaPort(port)), time.Second)
	if err != nil {
		t.Fatalf("dial public NAT port: %v", err)
	}
	defer publicConn.Close()
	_ = publicConn.SetDeadline(time.Now().Add(3 * time.Second))

	task := taskStream.nextTask(t)
	if task.GetType() != model.TaskTypeNAT {
		t.Fatalf("task type = %d, want NAT", task.GetType())
	}
	var natTask model.TaskNAT
	if err := json.Unmarshal([]byte(task.GetData()), &natTask); err != nil {
		t.Fatalf("decode NAT task: %v", err)
	}
	if natTask.Host != "127.0.0.1:8080" {
		t.Fatalf("nat host = %q, want 127.0.0.1:8080", natTask.Host)
	}
	if natTask.StreamID == "" {
		t.Fatal("NAT task must include stream id")
	}

	agentStream := newNATIOStreamServer()
	agentStream.sendToDashboard(&pb.IOStreamData{Data: append([]byte{0xff, 0x05, 0xff, 0x05}, []byte(natTask.StreamID)...)})
	errCh := make(chan error, 1)
	go func() {
		errCh <- rpcService.NezhaHandlerSingleton.IOStream(agentStream)
	}()
	defer agentStream.close()

	if _, err := publicConn.Write([]byte("from-public")); err != nil {
		t.Fatalf("write public connection: %v", err)
	}
	if got := string(agentStream.nextDataFromDashboard(t)); got != "from-public" {
		t.Fatalf("agent side read = %q, want from-public", got)
	}

	agentStream.sendToDashboard(&pb.IOStreamData{Data: []byte("from-agent")})
	if got := readExactString(t, publicConn, len("from-agent")); got != "from-agent" {
		t.Fatalf("public side read = %q, want from-agent", got)
	}

	_ = publicConn.Close()
	agentStream.close()
	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Fatalf("IOStream returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("IOStream did not exit after NAT connection closed")
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

func assertNATPortClosed(t *testing.T, port uint16) {
	t.Helper()
	_, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoaPort(port)), 100*time.Millisecond)
	if err == nil {
		t.Fatalf("expected NAT listener on port %d to be closed", port)
	}
}

func itoaPort(port uint16) string {
	return strconv.Itoa(int(port))
}

type natCaptureTaskStream struct {
	tasks chan *pb.Task
}

func newNATCaptureTaskStream() *natCaptureTaskStream {
	return &natCaptureTaskStream{tasks: make(chan *pb.Task, 4)}
}

func (s *natCaptureTaskStream) Send(task *pb.Task) error {
	s.tasks <- task
	return nil
}

func (s *natCaptureTaskStream) Recv() (*pb.TaskResult, error) { return nil, context.Canceled }
func (s *natCaptureTaskStream) SetHeader(metadata.MD) error   { return nil }
func (s *natCaptureTaskStream) SendHeader(metadata.MD) error  { return nil }
func (s *natCaptureTaskStream) SetTrailer(metadata.MD)        {}
func (s *natCaptureTaskStream) Context() context.Context      { return context.Background() }
func (s *natCaptureTaskStream) SendMsg(any) error             { return nil }
func (s *natCaptureTaskStream) RecvMsg(any) error             { return context.Canceled }

func (s *natCaptureTaskStream) nextTask(t *testing.T) *pb.Task {
	t.Helper()

	select {
	case task := <-s.tasks:
		return task
	case <-time.After(time.Second):
		t.Fatal("expected NAT task to be dispatched")
		return nil
	}
}

type natIOStreamServer struct {
	ctx      context.Context
	incoming chan *pb.IOStreamData
	outgoing chan *pb.IOStreamData
	done     chan struct{}
}

func newNATIOStreamServer() *natIOStreamServer {
	return &natIOStreamServer{
		ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs(
			"client_secret", "nat-secret",
			"client_uuid", "11111111-1111-1111-1111-111111111111",
		)),
		incoming: make(chan *pb.IOStreamData, 8),
		outgoing: make(chan *pb.IOStreamData, 8),
		done:     make(chan struct{}),
	}
}

func (s *natIOStreamServer) Send(data *pb.IOStreamData) error {
	select {
	case <-s.done:
		return context.Canceled
	case s.outgoing <- data:
		return nil
	}
}

func (s *natIOStreamServer) Recv() (*pb.IOStreamData, error) {
	select {
	case <-s.done:
		return nil, context.Canceled
	case data := <-s.incoming:
		return data, nil
	}
}

func (s *natIOStreamServer) SetHeader(metadata.MD) error  { return nil }
func (s *natIOStreamServer) SendHeader(metadata.MD) error { return nil }
func (s *natIOStreamServer) SetTrailer(metadata.MD)       {}
func (s *natIOStreamServer) Context() context.Context     { return s.ctx }
func (s *natIOStreamServer) SendMsg(any) error            { return nil }
func (s *natIOStreamServer) RecvMsg(any) error            { return context.Canceled }

func (s *natIOStreamServer) sendToDashboard(data *pb.IOStreamData) {
	select {
	case <-s.done:
	case s.incoming <- data:
	}
}

func (s *natIOStreamServer) nextDataFromDashboard(t *testing.T) []byte {
	t.Helper()

	deadline := time.After(3 * time.Second)
	for {
		select {
		case data := <-s.outgoing:
			if len(data.GetData()) == 0 {
				continue
			}
			return data.GetData()
		case <-deadline:
			t.Fatal("expected data from dashboard")
			return nil
		}
	}
}

func (s *natIOStreamServer) close() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

func setupNATForwardingFixture(t *testing.T, stream pb.NezhaService_RequestTaskServer) {
	t.Helper()

	originalDB := singleton.DB
	originalServerShared := singleton.ServerShared
	originalServerTransferShared := singleton.ServerTransferShared
	originalUserInfoMap := singleton.UserInfoMap
	originalAgentSecretToUserID := singleton.AgentSecretToUserId
	originalHandler := rpcService.NezhaHandlerSingleton

	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db handle: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)

	singleton.DB = db
	if err := singleton.DB.AutoMigrate(&model.Server{}); err != nil {
		t.Fatalf("migrate server: %v", err)
	}
	if err := singleton.DB.Create(&model.Server{
		Common: model.Common{ID: 1, UserID: 100},
		UUID:   "11111111-1111-1111-1111-111111111111",
		Name:   "nat-target",
	}).Error; err != nil {
		t.Fatalf("create server: %v", err)
	}
	singleton.ServerShared = singleton.NewServerClass()
	server, ok := singleton.ServerShared.Get(1)
	if !ok {
		t.Fatal("server 1 not found")
	}
	server.SetTaskStream(stream)
	singleton.ServerTransferShared = nil
	singleton.UserLock.Lock()
	singleton.UserInfoMap = map[uint64]model.UserInfo{
		100: {Role: model.RoleMember, AgentSecret: "nat-secret"},
	}
	singleton.AgentSecretToUserId = map[string]uint64{
		"nat-secret": 100,
	}
	singleton.UserLock.Unlock()
	rpcService.NezhaHandlerSingleton = rpcService.NewNezhaHandler()

	t.Cleanup(func() {
		_ = sqlDB.Close()
		singleton.DB = originalDB
		singleton.ServerShared = originalServerShared
		singleton.ServerTransferShared = originalServerTransferShared
		singleton.UserLock.Lock()
		singleton.UserInfoMap = originalUserInfoMap
		singleton.AgentSecretToUserId = originalAgentSecretToUserID
		singleton.UserLock.Unlock()
		rpcService.NezhaHandlerSingleton = originalHandler
	})
}

func readExactString(t *testing.T, conn net.Conn, size int) string {
	t.Helper()

	buf := make([]byte, size)
	read := 0
	for read < size {
		n, err := conn.Read(buf[read:])
		if err != nil {
			t.Fatalf("read %d bytes: %v", size, err)
		}
		read += n
	}
	return string(buf)
}
