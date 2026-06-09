package rpc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

type vpnRelayContext struct {
	sessionID string
	startOnce sync.Once

	entryStreamID string
	entryServerID uint64
	entryIo       io.ReadWriteCloser
	entryReady    chan struct{}
	entryOnce     sync.Once

	exitStreamID string
	exitServerID uint64
	exitIo       io.ReadWriteCloser
	exitReady    chan struct{}
	exitOnce     sync.Once

	uploadBytes   atomic.Uint64
	downloadBytes atomic.Uint64

	activeMu          sync.Mutex
	activeConnections map[uint64]struct{}
	parserMu          sync.Mutex
	frameParsers      map[*atomic.Uint64]*vpnRelayMuxFrameParser
}

type VPNRelayReport struct {
	SessionID         string
	Event             string
	UploadBytes       uint64
	DownloadBytes     uint64
	ActiveConnections uint32
	Closed            bool
	Error             error
}

func (s *NezhaHandler) SetVPNRelayReporter(reporter func(VPNRelayReport) bool) {
	s.ioStreamMutex.Lock()
	defer s.ioStreamMutex.Unlock()

	s.vpnRelayReporter = reporter
}

func (s *NezhaHandler) CreateVPNRelay(sessionID string, entryStreamID string, entryServerID uint64, exitStreamID string, exitServerID uint64) {
	s.ioStreamMutex.Lock()
	defer s.ioStreamMutex.Unlock()

	if s.vpnRelays == nil {
		s.vpnRelays = make(map[string]*vpnRelayContext)
	}
	if s.vpnRelayByStream == nil {
		s.vpnRelayByStream = make(map[string]string)
	}
	if existing := s.vpnRelays[sessionID]; existing != nil {
		if existing.entryIo != nil {
			_ = existing.entryIo.Close()
		}
		if existing.exitIo != nil {
			_ = existing.exitIo.Close()
		}
		delete(s.vpnRelayByStream, existing.entryStreamID)
		delete(s.vpnRelayByStream, existing.exitStreamID)
	}

	ctx := &vpnRelayContext{
		sessionID:         sessionID,
		entryStreamID:     entryStreamID,
		entryServerID:     entryServerID,
		entryReady:        make(chan struct{}),
		exitStreamID:      exitStreamID,
		exitServerID:      exitServerID,
		exitReady:         make(chan struct{}),
		activeConnections: make(map[uint64]struct{}),
		frameParsers:      make(map[*atomic.Uint64]*vpnRelayMuxFrameParser),
	}
	s.vpnRelays[sessionID] = ctx
	s.vpnRelayByStream[entryStreamID] = sessionID
	s.vpnRelayByStream[exitStreamID] = sessionID
}

func (s *NezhaHandler) IsVPNStreamAuthorizedForAgent(streamID string, agentServerID uint64) bool {
	s.ioStreamMutex.RLock()
	defer s.ioStreamMutex.RUnlock()

	ctx := s.vpnRelayForStreamLocked(streamID)
	if ctx == nil {
		return false
	}
	switch streamID {
	case ctx.entryStreamID:
		return agentServerID == ctx.entryServerID
	case ctx.exitStreamID:
		return agentServerID == ctx.exitServerID
	default:
		return false
	}
}

func (s *NezhaHandler) VPNAgentConnected(streamID string, agentServerID uint64, agentIo io.ReadWriteCloser) error {
	s.ioStreamMutex.RLock()
	ctx := s.vpnRelayForStreamLocked(streamID)
	s.ioStreamMutex.RUnlock()
	if ctx == nil {
		return errors.New("vpn relay stream not found")
	}
	if !s.IsVPNStreamAuthorizedForAgent(streamID, agentServerID) {
		return fmt.Errorf("vpn stream %s is not authorized for agent %d", streamID, agentServerID)
	}

	switch streamID {
	case ctx.entryStreamID:
		ctx.entryIo = agentIo
		ctx.entryOnce.Do(func() { close(ctx.entryReady) })
		s.reportVPNRelayEvent(ctx, "entry_connected", nil)
	case ctx.exitStreamID:
		ctx.exitIo = agentIo
		ctx.exitOnce.Do(func() { close(ctx.exitReady) })
		s.reportVPNRelayEvent(ctx, "exit_connected", nil)
	default:
		return errors.New("vpn relay role not found")
	}
	return nil
}

func (s *NezhaHandler) MaybeStartVPNRelay(sessionID string) {
	ctx := s.vpnRelayForSession(sessionID)
	if ctx == nil || ctx.entryIo == nil || ctx.exitIo == nil {
		return
	}
	ctx.startOnce.Do(func() {
		go func() {
			_ = s.StartVPNRelay(sessionID, time.Second*10)
		}()
	})
}

func (s *NezhaHandler) StartVPNRelay(sessionID string, timeout time.Duration) error {
	ctx := s.vpnRelayForSession(sessionID)
	if ctx == nil {
		return errors.New("vpn relay not found")
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	entryReady := ctx.entryReady
	exitReady := ctx.exitReady
	for ctx.entryIo == nil || ctx.exitIo == nil {
		select {
		case <-entryReady:
			entryReady = nil
		case <-exitReady:
			exitReady = nil
		case <-timer.C:
			if ctx.entryIo == nil && ctx.exitIo == nil {
				return errors.New("timeout: no vpn relay connection established")
			}
			if ctx.entryIo == nil {
				return errors.New("timeout: entry vpn relay connection not established")
			}
			return errors.New("timeout: exit vpn relay connection not established")
		}
	}

	s.reportVPNRelayEvent(ctx, "relay_started", nil)

	errCh := make(chan error, 2)
	go s.vpnRelayCopy(ctx, ctx.exitIo, ctx.entryIo, &ctx.uploadBytes, errCh)
	go s.vpnRelayCopy(ctx, ctx.entryIo, ctx.exitIo, &ctx.downloadBytes, errCh)

	err := <-errCh
	_ = s.CloseVPNRelay(sessionID)
	s.reportVPNRelayEvent(ctx, "relay_closed", err)
	s.reportVPNRelay(ctx, true, err)
	return err
}

func (s *NezhaHandler) VPNRelayTraffic(sessionID string) (uint64, uint64, bool) {
	ctx := s.vpnRelayForSession(sessionID)
	if ctx == nil {
		return 0, 0, false
	}
	return ctx.uploadBytes.Load(), ctx.downloadBytes.Load(), true
}

func (s *NezhaHandler) VPNRelayActiveConnections(sessionID string) (uint32, bool) {
	ctx := s.vpnRelayForSession(sessionID)
	if ctx == nil {
		return 0, false
	}
	return ctx.activeConnectionCount(), true
}

func (s *NezhaHandler) VPNRelaySessionForStream(streamID string) (string, bool) {
	s.ioStreamMutex.RLock()
	defer s.ioStreamMutex.RUnlock()

	sessionID := s.vpnRelayByStream[streamID]
	return sessionID, sessionID != ""
}

func (s *NezhaHandler) CloseVPNRelay(sessionID string) error {
	s.ioStreamMutex.Lock()
	defer s.ioStreamMutex.Unlock()

	ctx := s.vpnRelays[sessionID]
	if ctx == nil {
		return nil
	}
	if ctx.entryIo != nil {
		_ = ctx.entryIo.Close()
	}
	if ctx.exitIo != nil {
		_ = ctx.exitIo.Close()
	}
	delete(s.vpnRelays, sessionID)
	delete(s.vpnRelayByStream, ctx.entryStreamID)
	delete(s.vpnRelayByStream, ctx.exitStreamID)
	return nil
}

func (s *NezhaHandler) reportVPNRelay(ctx *vpnRelayContext, closed bool, err error) bool {
	if ctx == nil {
		return false
	}
	s.ioStreamMutex.RLock()
	reporter := s.vpnRelayReporter
	s.ioStreamMutex.RUnlock()
	if reporter == nil {
		return false
	}
	return reporter(VPNRelayReport{
		SessionID:         ctx.sessionID,
		UploadBytes:       ctx.uploadBytes.Load(),
		DownloadBytes:     ctx.downloadBytes.Load(),
		ActiveConnections: ctx.activeConnectionCount(),
		Closed:            closed,
		Error:             err,
	})
}

func (s *NezhaHandler) reportVPNRelayEvent(ctx *vpnRelayContext, event string, err error) bool {
	if ctx == nil || event == "" {
		return false
	}
	s.ioStreamMutex.RLock()
	reporter := s.vpnRelayReporter
	s.ioStreamMutex.RUnlock()
	if reporter == nil {
		return false
	}
	return reporter(VPNRelayReport{
		SessionID:         ctx.sessionID,
		Event:             event,
		UploadBytes:       ctx.uploadBytes.Load(),
		DownloadBytes:     ctx.downloadBytes.Load(),
		ActiveConnections: ctx.activeConnectionCount(),
		Error:             err,
	})
}

func (s *NezhaHandler) vpnRelayForSession(sessionID string) *vpnRelayContext {
	s.ioStreamMutex.RLock()
	defer s.ioStreamMutex.RUnlock()

	return s.vpnRelays[sessionID]
}

func (s *NezhaHandler) vpnRelayForStreamLocked(streamID string) *vpnRelayContext {
	sessionID := s.vpnRelayByStream[streamID]
	if sessionID == "" {
		return nil
	}
	return s.vpnRelays[sessionID]
}

func (ctx *vpnRelayContext) activeConnectionCount() uint32 {
	if ctx == nil {
		return 0
	}
	ctx.activeMu.Lock()
	defer ctx.activeMu.Unlock()
	return uint32(len(ctx.activeConnections))
}

func (ctx *vpnRelayContext) frameParser(counter *atomic.Uint64) *vpnRelayMuxFrameParser {
	ctx.parserMu.Lock()
	defer ctx.parserMu.Unlock()

	parser := ctx.frameParsers[counter]
	if parser == nil {
		parser = &vpnRelayMuxFrameParser{}
		ctx.frameParsers[counter] = parser
	}
	return parser
}

func (ctx *vpnRelayContext) observeMuxFrames(counter *atomic.Uint64, data []byte) bool {
	if ctx == nil || len(data) == 0 {
		return false
	}
	frames := ctx.frameParser(counter).append(data)
	if len(frames) == 0 {
		return false
	}

	changed := false
	ctx.activeMu.Lock()
	defer ctx.activeMu.Unlock()
	for _, frame := range frames {
		switch frame.Type {
		case vpnRelayMuxFrameTypeOpen:
			if _, exists := ctx.activeConnections[frame.ConnID]; !exists {
				ctx.activeConnections[frame.ConnID] = struct{}{}
				changed = true
			}
		case vpnRelayMuxFrameTypeClose:
			if _, exists := ctx.activeConnections[frame.ConnID]; exists {
				delete(ctx.activeConnections, frame.ConnID)
				changed = true
			}
		}
	}
	return changed
}

const vpnRelayMuxFrameHeaderSize = 17
const vpnRelayMuxFrameMaxPayloadSize = 64 * 1024 * 1024
const vpnRelayMuxFrameTypeOpen byte = 1
const vpnRelayMuxFrameTypeClose byte = 3

var vpnRelayMuxFrameMagic = []byte{'N', 'Z', 'V', 'M'}

type vpnRelayMuxFrame struct {
	Type   byte
	ConnID uint64
}

type vpnRelayMuxFrameParser struct {
	buffer []byte
}

func (p *vpnRelayMuxFrameParser) append(data []byte) []vpnRelayMuxFrame {
	p.buffer = append(p.buffer, data...)
	frames := make([]vpnRelayMuxFrame, 0)
	for {
		if len(p.buffer) < len(vpnRelayMuxFrameMagic) {
			return frames
		}
		magicIndex := bytes.Index(p.buffer, vpnRelayMuxFrameMagic)
		if magicIndex < 0 {
			p.keepPossibleMagicPrefix()
			return frames
		}
		if magicIndex > 0 {
			p.buffer = p.buffer[magicIndex:]
		}
		if len(p.buffer) < vpnRelayMuxFrameHeaderSize {
			return frames
		}
		payloadLen := binary.BigEndian.Uint32(p.buffer[13:17])
		if payloadLen > vpnRelayMuxFrameMaxPayloadSize {
			p.buffer = p.buffer[1:]
			continue
		}
		frameSize := vpnRelayMuxFrameHeaderSize + int(payloadLen)
		if len(p.buffer) < frameSize {
			return frames
		}
		frames = append(frames, vpnRelayMuxFrame{
			Type:   p.buffer[4],
			ConnID: binary.BigEndian.Uint64(p.buffer[5:13]),
		})
		p.buffer = p.buffer[frameSize:]
	}
}

func (p *vpnRelayMuxFrameParser) keepPossibleMagicPrefix() {
	if len(p.buffer) < len(vpnRelayMuxFrameMagic) {
		return
	}
	keep := len(vpnRelayMuxFrameMagic) - 1
	p.buffer = append([]byte(nil), p.buffer[len(p.buffer)-keep:]...)
}

func (s *NezhaHandler) vpnRelayCopy(ctx *vpnRelayContext, dst io.Writer, src io.Reader, counter *atomic.Uint64, errCh chan<- error) {
	bp := bufPool.Get().(*bp)
	defer bufPool.Put(bp)

	for {
		nr, er := src.Read(bp.buf)
		if nr > 0 {
			nw, ew := dst.Write(bp.buf[:nr])
			if nw > 0 {
				counter.Add(uint64(nw))
				ctx.observeMuxFrames(counter, bp.buf[:nw])
				if s.reportVPNRelay(ctx, false, nil) {
					errCh <- errors.New("vpn relay closed by traffic policy")
					return
				}
			}
			if ew != nil {
				errCh <- ew
				return
			}
			if nr != nw {
				errCh <- io.ErrShortWrite
				return
			}
		}
		if er != nil {
			errCh <- er
			return
		}
	}
}
