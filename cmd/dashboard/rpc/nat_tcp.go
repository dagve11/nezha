package rpc

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"

	"github.com/nezhahq/nezha/model"
)

type NATPortHandler func(net.Conn, *model.NAT)

type NATPortManager struct {
	mu         sync.Mutex
	listenHost string
	handler    NATPortHandler
	byID       map[uint64]*natPortListener
	byPort     map[uint16]uint64
}

type natPortListener struct {
	listener net.Listener
	nat      *model.NAT
}

var NATPortManagerShared = NewNATPortManager("", nil)

func NewNATPortManager(listenHost string, handler NATPortHandler) *NATPortManager {
	if handler == nil {
		handler = ServeNATConn
	}
	return &NATPortManager{
		listenHost: listenHost,
		handler:    handler,
		byID:       make(map[uint64]*natPortListener),
		byPort:     make(map[uint16]uint64),
	}
}

func (m *NATPortManager) SetListenHost(listenHost string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listenHost = listenHost
}

func (m *NATPortManager) Sync(list []*model.NAT) error {
	seen := make(map[uint64]struct{}, len(list))
	for _, nat := range list {
		if nat == nil {
			continue
		}
		seen[nat.ID] = struct{}{}
		if err := m.Upsert(nat); err != nil {
			return fmt.Errorf("nat %d port %d: %w", nat.ID, nat.Port, err)
		}
	}

	var stale []uint64
	m.mu.Lock()
	for id := range m.byID {
		if _, ok := seen[id]; !ok {
			stale = append(stale, id)
		}
	}
	m.mu.Unlock()

	for _, id := range stale {
		m.Delete(id)
	}
	return nil
}

func (m *NATPortManager) Upsert(nat *model.NAT) error {
	if nat == nil {
		return nil
	}
	if nat.ID == 0 {
		return fmt.Errorf("nat id is required")
	}
	if !nat.Enabled || nat.Port == 0 {
		m.Delete(nat.ID)
		return nil
	}

	natCopy := cloneNAT(nat)

	m.mu.Lock()
	if ownerID, ok := m.byPort[natCopy.Port]; ok && ownerID != natCopy.ID {
		m.mu.Unlock()
		return fmt.Errorf("port %d is already used by nat %d", natCopy.Port, ownerID)
	}
	if current := m.byID[natCopy.ID]; current != nil && current.nat.Port == natCopy.Port {
		current.nat = natCopy
		m.mu.Unlock()
		return nil
	}
	listenHost := m.listenHost
	m.mu.Unlock()

	listener, err := net.Listen("tcp", listenAddress(listenHost, natCopy.Port))
	if err != nil {
		return err
	}

	var old *natPortListener
	entry := &natPortListener{
		listener: listener,
		nat:      natCopy,
	}

	m.mu.Lock()
	if ownerID, ok := m.byPort[natCopy.Port]; ok && ownerID != natCopy.ID {
		m.mu.Unlock()
		_ = listener.Close()
		return fmt.Errorf("port %d is already used by nat %d", natCopy.Port, ownerID)
	}
	if current := m.byID[natCopy.ID]; current != nil {
		if current.nat.Port == natCopy.Port {
			current.nat = natCopy
			m.mu.Unlock()
			_ = listener.Close()
			return nil
		}
		old = current
		delete(m.byPort, current.nat.Port)
	}
	m.byID[natCopy.ID] = entry
	m.byPort[natCopy.Port] = natCopy.ID
	m.mu.Unlock()

	if old != nil {
		_ = old.listener.Close()
	}

	go m.acceptLoop(entry)
	log.Printf("NEZHA>> NAT::START ON %s -> server %d %s", listener.Addr(), natCopy.ServerID, natCopy.Host)
	return nil
}

func (m *NATPortManager) Delete(id uint64) {
	m.mu.Lock()
	entry := m.byID[id]
	if entry == nil {
		m.mu.Unlock()
		return
	}
	delete(m.byID, id)
	delete(m.byPort, entry.nat.Port)
	m.mu.Unlock()

	_ = entry.listener.Close()
	log.Printf("NEZHA>> NAT::STOP %s", entry.listener.Addr())
}

func (m *NATPortManager) StopAll() {
	var entries []*natPortListener
	m.mu.Lock()
	for _, entry := range m.byID {
		entries = append(entries, entry)
	}
	m.byID = make(map[uint64]*natPortListener)
	m.byPort = make(map[uint16]uint64)
	m.mu.Unlock()

	for _, entry := range entries {
		_ = entry.listener.Close()
	}
}

func (m *NATPortManager) acceptLoop(entry *natPortListener) {
	for {
		conn, err := entry.listener.Accept()
		if err != nil {
			if m.isActive(entry) {
				log.Printf("NEZHA>> NAT::ACCEPT ERROR ON %s: %v", entry.listener.Addr(), err)
			}
			return
		}

		nat := m.snapshot(entry)
		if nat == nil {
			_ = conn.Close()
			continue
		}
		go m.handler(conn, nat)
	}
}

func (m *NATPortManager) isActive(entry *natPortListener) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	current := m.byID[entry.nat.ID]
	return current == entry
}

func (m *NATPortManager) snapshot(entry *natPortListener) *model.NAT {
	m.mu.Lock()
	defer m.mu.Unlock()

	current := m.byID[entry.nat.ID]
	if current != entry {
		return nil
	}
	return cloneNAT(entry.nat)
}

func ServeNATConn(conn net.Conn, natConfig *model.NAT) {
	defer conn.Close()
	if err := serveNATIO(conn, natConfig); err != nil {
		log.Printf("NEZHA>> NAT::CONNECT ERROR ON %d -> server %d %s: %v", natConfig.Port, natConfig.ServerID, natConfig.Host, err)
	}
}

func listenAddress(host string, port uint16) string {
	if host == "" {
		return ":" + strconv.Itoa(int(port))
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

func cloneNAT(nat *model.NAT) *model.NAT {
	if nat == nil {
		return nil
	}
	n := *nat
	return &n
}
