package rpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	"github.com/nezhahq/nezha/model"
	pb "github.com/nezhahq/nezha/proto"
)

func TestVPNRelayAuthorizesOnlyBoundRoleServers(t *testing.T) {
	h := NewNezhaHandler()
	h.CreateVPNRelay("vpn-session-1", "entry-stream", 10, "exit-stream", 20)

	if !h.IsVPNStreamAuthorizedForAgent("entry-stream", 10) {
		t.Fatal("entry stream must authorize the bound entry server")
	}
	if h.IsVPNStreamAuthorizedForAgent("entry-stream", 20) {
		t.Fatal("entry stream must reject the exit server")
	}
	if !h.IsVPNStreamAuthorizedForAgent("exit-stream", 20) {
		t.Fatal("exit stream must authorize the bound exit server")
	}
	if h.IsVPNStreamAuthorizedForAgent("exit-stream", 10) {
		t.Fatal("exit stream must reject the entry server")
	}
	if h.IsVPNStreamAuthorizedForAgent("unknown-stream", 10) {
		t.Fatal("unknown stream must reject every agent")
	}
}

func TestCreateVPNRelayReplacesExistingSessionAndClosesOldStreams(t *testing.T) {
	h := NewNezhaHandler()
	h.CreateVPNRelay("vpn-session-1", "entry-stream-old", 10, "exit-stream-old", 20)
	oldEntry := newRecordingReadWriteCloser()
	oldExit := newRecordingReadWriteCloser()
	if err := h.VPNAgentConnected("entry-stream-old", 10, oldEntry); err != nil {
		t.Fatalf("connect old entry: %v", err)
	}
	if err := h.VPNAgentConnected("exit-stream-old", 20, oldExit); err != nil {
		t.Fatalf("connect old exit: %v", err)
	}

	h.CreateVPNRelay("vpn-session-1", "entry-stream-new", 11, "exit-stream-new", 21)

	if oldEntry.closeCalls != 1 || oldExit.closeCalls != 1 {
		t.Fatalf("replacing a relay must close old IO streams, entry=%d exit=%d", oldEntry.closeCalls, oldExit.closeCalls)
	}
	if h.IsVPNStreamAuthorizedForAgent("entry-stream-old", 10) || h.IsVPNStreamAuthorizedForAgent("exit-stream-old", 20) {
		t.Fatal("replacing a relay must remove old stream authorization")
	}
	if !h.IsVPNStreamAuthorizedForAgent("entry-stream-new", 11) || !h.IsVPNStreamAuthorizedForAgent("exit-stream-new", 21) {
		t.Fatal("replacing a relay must authorize the new stream bindings")
	}
	if _, ok := h.VPNRelaySessionForStream("entry-stream-old"); ok {
		t.Fatal("old entry stream must no longer map to the session")
	}
	if sessionID, ok := h.VPNRelaySessionForStream("entry-stream-new"); !ok || sessionID != "vpn-session-1" {
		t.Fatalf("new entry stream must map to the session, got session=%q ok=%v", sessionID, ok)
	}
}

func TestVPNRelayTransfersBytesBothDirectionsAndCountsTraffic(t *testing.T) {
	h := NewNezhaHandler()
	h.CreateVPNRelay("vpn-session-1", "entry-stream", 10, "exit-stream", 20)

	entryAgent, entryDashboard := net.Pipe()
	exitAgent, exitDashboard := net.Pipe()
	defer entryAgent.Close()
	defer entryDashboard.Close()
	defer exitAgent.Close()
	defer exitDashboard.Close()

	if err := h.VPNAgentConnected("entry-stream", 10, entryDashboard); err != nil {
		t.Fatalf("connect entry: %v", err)
	}
	if err := h.VPNAgentConnected("exit-stream", 20, exitDashboard); err != nil {
		t.Fatalf("connect exit: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- h.StartVPNRelay("vpn-session-1", time.Second)
	}()

	entryToExit := []byte{1, 2, 3, 4}
	if _, err := entryAgent.Write(entryToExit); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	gotFromEntry := make([]byte, len(entryToExit))
	if _, err := io.ReadFull(exitAgent, gotFromEntry); err != nil {
		t.Fatalf("read exit: %v", err)
	}
	if !reflect.DeepEqual(entryToExit, gotFromEntry) {
		t.Fatalf("entry -> exit mismatch: want %v got %v", entryToExit, gotFromEntry)
	}

	exitToEntry := []byte{9, 8, 7}
	if _, err := exitAgent.Write(exitToEntry); err != nil {
		t.Fatalf("write exit: %v", err)
	}
	gotFromExit := make([]byte, len(exitToEntry))
	if _, err := io.ReadFull(entryAgent, gotFromExit); err != nil {
		t.Fatalf("read entry: %v", err)
	}
	if !reflect.DeepEqual(exitToEntry, gotFromExit) {
		t.Fatalf("exit -> entry mismatch: want %v got %v", exitToEntry, gotFromExit)
	}

	waitForVPNRelayTraffic(t, h, "vpn-session-1", uint64(len(entryToExit)), uint64(len(exitToEntry)))

	if err := h.CloseVPNRelay("vpn-session-1"); err != nil {
		t.Fatalf("close relay: %v", err)
	}
	if err := <-done; err != nil && err != io.ErrClosedPipe {
		t.Fatalf("relay returned unexpected error: %v", err)
	}
}

func TestVPNRelayReportsFinalTrafficWhenClosed(t *testing.T) {
	h := NewNezhaHandler()
	reports := make(chan VPNRelayReport, 8)
	h.vpnRelayReporter = func(report VPNRelayReport) bool {
		reports <- report
		return false
	}
	h.CreateVPNRelay("vpn-session-1", "entry-stream", 10, "exit-stream", 20)

	entryAgent, entryDashboard := net.Pipe()
	exitAgent, exitDashboard := net.Pipe()
	defer entryAgent.Close()
	defer exitAgent.Close()

	if err := h.VPNAgentConnected("entry-stream", 10, entryDashboard); err != nil {
		t.Fatalf("connect entry: %v", err)
	}
	if err := h.VPNAgentConnected("exit-stream", 20, exitDashboard); err != nil {
		t.Fatalf("connect exit: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- h.StartVPNRelay("vpn-session-1", time.Second)
	}()

	if _, err := entryAgent.Write([]byte("abc")); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	got := make([]byte, 3)
	if _, err := io.ReadFull(exitAgent, got); err != nil {
		t.Fatalf("read exit: %v", err)
	}
	waitForVPNRelayTraffic(t, h, "vpn-session-1", 3, 0)
	if err := h.CloseVPNRelay("vpn-session-1"); err != nil {
		t.Fatalf("close relay: %v", err)
	}
	_ = <-done

	var sawTraffic bool
	var sawClosed bool
	deadline := time.After(time.Second)
	for !sawTraffic || !sawClosed {
		select {
		case report := <-reports:
			if report.SessionID != "vpn-session-1" {
				t.Fatalf("unexpected relay report session: %#v", report)
			}
			if report.UploadBytes == 3 && report.DownloadBytes == 0 && !report.Closed {
				sawTraffic = true
			}
			if report.UploadBytes == 3 && report.DownloadBytes == 0 && report.Closed {
				sawClosed = true
			}
		case <-deadline:
			t.Fatalf("timed out waiting for traffic and closed reports, sawTraffic=%v sawClosed=%v", sawTraffic, sawClosed)
		}
	}
}

func TestVPNRelayReporterCanCloseRelayOnTrafficLimit(t *testing.T) {
	h := NewNezhaHandler()
	reports := make(chan VPNRelayReport, 8)
	h.vpnRelayReporter = func(report VPNRelayReport) bool {
		reports <- report
		return !report.Closed && report.UploadBytes >= 3
	}
	h.CreateVPNRelay("vpn-session-1", "entry-stream", 10, "exit-stream", 20)

	entryAgent, entryDashboard := net.Pipe()
	exitAgent, exitDashboard := net.Pipe()
	defer entryAgent.Close()
	defer exitAgent.Close()

	if err := h.VPNAgentConnected("entry-stream", 10, entryDashboard); err != nil {
		t.Fatalf("connect entry: %v", err)
	}
	if err := h.VPNAgentConnected("exit-stream", 20, exitDashboard); err != nil {
		t.Fatalf("connect exit: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- h.StartVPNRelay("vpn-session-1", time.Second)
	}()

	if _, err := entryAgent.Write([]byte("abc")); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	got := make([]byte, 3)
	if _, err := io.ReadFull(exitAgent, got); err != nil {
		t.Fatalf("read exit: %v", err)
	}
	report := waitForVPNRelayTrafficReport(t, reports, 3, 0)
	if report.SessionID != "vpn-session-1" || report.Closed {
		t.Fatalf("unexpected traffic-limit report: %#v", report)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "traffic policy") {
			t.Fatalf("relay must stop with traffic policy error, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay did not stop after reporter requested close")
	}
}

func TestVPNRelayReportsEndpointAndLifecycleEvents(t *testing.T) {
	h := NewNezhaHandler()
	reports := make(chan VPNRelayReport, 8)
	h.vpnRelayReporter = func(report VPNRelayReport) bool {
		reports <- report
		return false
	}
	h.CreateVPNRelay("vpn-session-1", "entry-stream", 10, "exit-stream", 20)

	entryAgent, entryDashboard := net.Pipe()
	exitAgent, exitDashboard := net.Pipe()
	defer entryAgent.Close()
	defer exitAgent.Close()

	if err := h.VPNAgentConnected("entry-stream", 10, entryDashboard); err != nil {
		t.Fatalf("connect entry: %v", err)
	}
	assertVPNRelayEvent(t, reports, "entry_connected")
	if err := h.VPNAgentConnected("exit-stream", 20, exitDashboard); err != nil {
		t.Fatalf("connect exit: %v", err)
	}
	assertVPNRelayEvent(t, reports, "exit_connected")

	done := make(chan error, 1)
	go func() {
		done <- h.StartVPNRelay("vpn-session-1", time.Second)
	}()
	assertVPNRelayEvent(t, reports, "relay_started")

	if err := h.CloseVPNRelay("vpn-session-1"); err != nil {
		t.Fatalf("close relay: %v", err)
	}
	_ = <-done
	assertVPNRelayEvent(t, reports, "relay_closed")
}

func TestVPNRelayReportsActiveConnectionsFromMuxFrames(t *testing.T) {
	h := NewNezhaHandler()
	reports := make(chan VPNRelayReport, 16)
	h.vpnRelayReporter = func(report VPNRelayReport) bool {
		if report.Event == "" {
			reports <- report
		}
		return false
	}
	h.CreateVPNRelay("vpn-session-1", "entry-stream", 10, "exit-stream", 20)

	entryAgent, entryDashboard := net.Pipe()
	exitAgent, exitDashboard := net.Pipe()
	defer entryAgent.Close()
	defer exitAgent.Close()

	if err := h.VPNAgentConnected("entry-stream", 10, entryDashboard); err != nil {
		t.Fatalf("connect entry: %v", err)
	}
	if err := h.VPNAgentConnected("exit-stream", 20, exitDashboard); err != nil {
		t.Fatalf("connect exit: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- h.StartVPNRelay("vpn-session-1", time.Second)
	}()

	open1 := encodeVPNRelayMuxFrameForTest(t, 1, 101, nil)
	if _, err := entryAgent.Write(open1); err != nil {
		t.Fatalf("write first open: %v", err)
	}
	assertVPNRelayForwardedBytes(t, exitAgent, open1)
	waitForVPNRelayActiveConnectionsReport(t, reports, 1)

	open2 := encodeVPNRelayMuxFrameForTest(t, 1, 202, nil)
	if _, err := entryAgent.Write(open2[:5]); err != nil {
		t.Fatalf("write split open header: %v", err)
	}
	assertVPNRelayForwardedBytes(t, exitAgent, open2[:5])
	if _, err := entryAgent.Write(open2[5:]); err != nil {
		t.Fatalf("write split open tail: %v", err)
	}
	assertVPNRelayForwardedBytes(t, exitAgent, open2[5:])
	waitForVPNRelayActiveConnectionsReport(t, reports, 2)

	close1 := encodeVPNRelayMuxFrameForTest(t, 3, 101, nil)
	if _, err := exitAgent.Write(close1); err != nil {
		t.Fatalf("write first close: %v", err)
	}
	assertVPNRelayForwardedBytes(t, entryAgent, close1)
	waitForVPNRelayActiveConnectionsReport(t, reports, 1)

	close2 := encodeVPNRelayMuxFrameForTest(t, 3, 202, nil)
	if _, err := entryAgent.Write(close2); err != nil {
		t.Fatalf("write second close: %v", err)
	}
	assertVPNRelayForwardedBytes(t, exitAgent, close2)
	waitForVPNRelayActiveConnectionsReport(t, reports, 0)

	if err := h.CloseVPNRelay("vpn-session-1"); err != nil {
		t.Fatalf("close relay: %v", err)
	}
	_ = <-done
}

func TestVPNRelayRejectsForeignAgentConnection(t *testing.T) {
	h := NewNezhaHandler()
	h.CreateVPNRelay("vpn-session-1", "entry-stream", 10, "exit-stream", 20)

	if err := h.VPNAgentConnected("entry-stream", 20, newPipeReadWriter()); err == nil {
		t.Fatal("foreign agent must not attach to entry stream")
	}
}

func TestIOStreamAllowsVPNRelayStreamForBoundAgent(t *testing.T) {
	entry := requestTaskSecurityServer(10, 200, "10101010-1010-1010-1010-101010101010")
	setupRequestTaskSecurityFixture(t, []*model.Server{entry}, nil, map[uint64]model.UserInfo{
		200: {Role: model.RoleMember},
	}, map[string]uint64{"vpn-agent-secret": 200})
	h := NewNezhaHandler()
	h.CreateVPNRelay("vpn-session-1", "entry-stream", entry.ID, "exit-stream", 20)

	stream := &vpnIOStreamTestStream{
		ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs(
			"client_secret", "vpn-agent-secret",
			"client_uuid", entry.UUID,
		)),
		recv: []*pb.IOStreamData{{
			Data: append([]byte{0xff, 0x05, 0xff, 0x05}, []byte("entry-stream")...),
		}},
	}

	done := make(chan error, 1)
	go func() {
		done <- h.IOStream(stream)
	}()
	waitForVPNRelayEndpoint(t, h, "vpn-session-1", "entry")
	if err := h.CloseVPNRelay("vpn-session-1"); err != nil {
		t.Fatalf("close relay: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("bound VPN relay stream must pass IOStream authorization, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("IOStream did not exit after closing VPN relay")
	}
}

func TestIOStreamAutoStartsVPNRelayWhenBothAgentsConnect(t *testing.T) {
	entry := requestTaskSecurityServer(10, 200, "10101010-1010-1010-1010-101010101010")
	exit := requestTaskSecurityServer(20, 200, "20202020-2020-2020-2020-202020202020")
	setupRequestTaskSecurityFixture(t, []*model.Server{entry, exit}, nil, map[uint64]model.UserInfo{
		200: {Role: model.RoleMember},
	}, map[string]uint64{"vpn-agent-secret": 200})
	h := NewNezhaHandler()
	h.CreateVPNRelay("vpn-session-1", "entry-stream", entry.ID, "exit-stream", exit.ID)

	entryStream := newVPNBlockingIOStreamTestStream(entry, "vpn-agent-secret", "entry-stream")
	exitStream := newVPNBlockingIOStreamTestStream(exit, "vpn-agent-secret", "exit-stream")

	entryDone := make(chan error, 1)
	go func() {
		entryDone <- h.IOStream(entryStream)
	}()
	waitForVPNRelayEndpoint(t, h, "vpn-session-1", "entry")

	exitDone := make(chan error, 1)
	go func() {
		exitDone <- h.IOStream(exitStream)
	}()
	waitForVPNRelayEndpoint(t, h, "vpn-session-1", "exit")

	entryToExit := []byte("entry-to-exit")
	entryStream.recv <- &pb.IOStreamData{Data: entryToExit}
	assertVPNStreamSent(t, exitStream, entryToExit)

	exitToEntry := []byte("exit-to-entry")
	exitStream.recv <- &pb.IOStreamData{Data: exitToEntry}
	assertVPNStreamSent(t, entryStream, exitToEntry)
	waitForVPNRelayTraffic(t, h, "vpn-session-1", uint64(len(entryToExit)), uint64(len(exitToEntry)))

	if err := h.CloseVPNRelay("vpn-session-1"); err != nil {
		t.Fatalf("close relay: %v", err)
	}
	entryStream.closeRecv()
	exitStream.closeRecv()
	assertVPNIOStreamDone(t, entryDone)
	assertVPNIOStreamDone(t, exitDone)
}

type vpnIOStreamTestStream struct {
	ctx  context.Context
	recv []*pb.IOStreamData
}

func (s *vpnIOStreamTestStream) Send(*pb.IOStreamData) error { return nil }
func (s *vpnIOStreamTestStream) Recv() (*pb.IOStreamData, error) {
	if len(s.recv) == 0 {
		return nil, context.Canceled
	}
	msg := s.recv[0]
	s.recv = s.recv[1:]
	return msg, nil
}
func (s *vpnIOStreamTestStream) SetHeader(metadata.MD) error  { return nil }
func (s *vpnIOStreamTestStream) SendHeader(metadata.MD) error { return nil }
func (s *vpnIOStreamTestStream) SetTrailer(metadata.MD)       {}
func (s *vpnIOStreamTestStream) Context() context.Context     { return s.ctx }
func (s *vpnIOStreamTestStream) SendMsg(any) error            { return nil }
func (s *vpnIOStreamTestStream) RecvMsg(any) error            { return context.Canceled }

type vpnBlockingIOStreamTestStream struct {
	ctx  context.Context
	recv chan *pb.IOStreamData
	sent chan []byte
}

type recordingReadWriteCloser struct {
	closeCalls int
}

func newRecordingReadWriteCloser() *recordingReadWriteCloser {
	return &recordingReadWriteCloser{}
}

func (c *recordingReadWriteCloser) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (c *recordingReadWriteCloser) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *recordingReadWriteCloser) Close() error {
	c.closeCalls++
	return nil
}

func newVPNBlockingIOStreamTestStream(server *model.Server, secret string, streamID string) *vpnBlockingIOStreamTestStream {
	stream := &vpnBlockingIOStreamTestStream{
		ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs(
			"client_secret", secret,
			"client_uuid", server.UUID,
		)),
		recv: make(chan *pb.IOStreamData, 8),
		sent: make(chan []byte, 8),
	}
	stream.recv <- &pb.IOStreamData{Data: append([]byte{0xff, 0x05, 0xff, 0x05}, []byte(streamID)...)}
	return stream
}

func (s *vpnBlockingIOStreamTestStream) Send(data *pb.IOStreamData) error {
	s.sent <- append([]byte(nil), data.GetData()...)
	return nil
}

func (s *vpnBlockingIOStreamTestStream) Recv() (*pb.IOStreamData, error) {
	data, ok := <-s.recv
	if !ok {
		return nil, io.ErrClosedPipe
	}
	return data, nil
}

func (s *vpnBlockingIOStreamTestStream) closeRecv() {
	close(s.recv)
}

func (s *vpnBlockingIOStreamTestStream) SetHeader(metadata.MD) error  { return nil }
func (s *vpnBlockingIOStreamTestStream) SendHeader(metadata.MD) error { return nil }
func (s *vpnBlockingIOStreamTestStream) SetTrailer(metadata.MD)       {}
func (s *vpnBlockingIOStreamTestStream) Context() context.Context     { return s.ctx }
func (s *vpnBlockingIOStreamTestStream) SendMsg(any) error            { return nil }
func (s *vpnBlockingIOStreamTestStream) RecvMsg(any) error            { return context.Canceled }

func assertVPNStreamSent(t *testing.T, stream *vpnBlockingIOStreamTestStream, want []byte) {
	t.Helper()

	select {
	case got := <-stream.sent:
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("stream sent mismatch: want %v got %v", want, got)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for stream to send %q", string(want))
	}
}

func assertVPNIOStreamDone(t *testing.T, done <-chan error) {
	t.Helper()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("IOStream returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("IOStream did not exit after closing VPN relay")
	}
}

func assertVPNRelayEvent(t *testing.T, reports <-chan VPNRelayReport, wantEvent string) {
	t.Helper()

	deadline := time.After(time.Second)
	for {
		select {
		case report := <-reports:
			if report.Event == wantEvent {
				if report.SessionID != "vpn-session-1" {
					t.Fatalf("unexpected relay event session: %#v", report)
				}
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for relay event %q", wantEvent)
		}
	}
}

func waitForVPNRelayTrafficReport(t *testing.T, reports <-chan VPNRelayReport, wantUpload uint64, wantDownload uint64) VPNRelayReport {
	t.Helper()

	deadline := time.After(time.Second)
	for {
		select {
		case report := <-reports:
			if report.Event == "" && report.UploadBytes == wantUpload && report.DownloadBytes == wantDownload {
				return report
			}
		case <-deadline:
			t.Fatalf("timed out waiting for relay traffic report upload=%d download=%d", wantUpload, wantDownload)
		}
	}
}

func waitForVPNRelayActiveConnectionsReport(t *testing.T, reports <-chan VPNRelayReport, want uint32) VPNRelayReport {
	t.Helper()

	deadline := time.After(time.Second)
	for {
		select {
		case report := <-reports:
			if report.ActiveConnections == want {
				return report
			}
		case <-deadline:
			t.Fatalf("timed out waiting for relay active connections report active=%d", want)
		}
	}
}

func assertVPNRelayForwardedBytes(t *testing.T, reader io.Reader, want []byte) {
	t.Helper()

	got := make([]byte, len(want))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("read forwarded mux bytes: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("forwarded mux bytes mismatch: want %v got %v", want, got)
	}
}

func encodeVPNRelayMuxFrameForTest(t *testing.T, frameType byte, connID uint64, payload []byte) []byte {
	t.Helper()

	header := make([]byte, 17)
	copy(header[:4], []byte{'N', 'Z', 'V', 'M'})
	header[4] = frameType
	binary.BigEndian.PutUint64(header[5:13], connID)
	binary.BigEndian.PutUint32(header[13:17], uint32(len(payload)))
	return append(header, payload...)
}

func waitForVPNRelayTraffic(t *testing.T, h *NezhaHandler, sessionID string, wantUpload uint64, wantDownload uint64) {
	t.Helper()

	deadline := time.After(time.Second)
	for {
		upload, download, ok := h.VPNRelayTraffic(sessionID)
		if !ok {
			t.Fatal("expected VPN relay traffic to be tracked")
		}
		if upload == wantUpload && download == wantDownload {
			return
		}
		if upload > wantUpload || download > wantDownload {
			t.Fatalf("unexpected traffic counters upload=%d download=%d", upload, download)
		}
		select {
		case <-deadline:
			t.Fatalf("traffic counters did not reach expected values: upload=%d/%d download=%d/%d", upload, wantUpload, download, wantDownload)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func waitForVPNRelayEndpoint(t *testing.T, h *NezhaHandler, sessionID string, role string) {
	t.Helper()

	deadline := time.After(time.Second)
	for {
		ctx := h.vpnRelayForSession(sessionID)
		if ctx == nil {
			t.Fatal("expected VPN relay to be tracked")
		}
		if role == "entry" && ctx.entryIo != nil {
			return
		}
		if role == "exit" && ctx.exitIo != nil {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("vpn relay endpoint %s did not connect", role)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}
