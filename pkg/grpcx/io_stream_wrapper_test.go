package grpcx

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/nezhahq/nezha/proto"
)

type concurrencyTrackingIOStream struct {
	active      int
	maxInFlight int
	mu          sync.Mutex
}

func (s *concurrencyTrackingIOStream) Send(*proto.IOStreamData) error {
	s.mu.Lock()
	s.active++
	if s.active > s.maxInFlight {
		s.maxInFlight = s.active
	}
	s.mu.Unlock()

	time.Sleep(10 * time.Millisecond)

	s.mu.Lock()
	s.active--
	s.mu.Unlock()
	return nil
}

func (s *concurrencyTrackingIOStream) Recv() (*proto.IOStreamData, error) {
	return &proto.IOStreamData{}, nil
}

func (s *concurrencyTrackingIOStream) Context() context.Context {
	return context.Background()
}

func TestIOStreamWrapperSerializesConcurrentWrites(t *testing.T) {
	raw := &concurrencyTrackingIOStream{}
	wrapper := NewIOStreamWrapper(raw)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := wrapper.Write([]byte("frame")); err != nil {
				t.Errorf("Write failed: %v", err)
			}
		}()
	}
	wg.Wait()

	if raw.maxInFlight > 1 {
		t.Fatalf("IOStreamWrapper must serialize Send; observed max-in-flight=%d", raw.maxInFlight)
	}
}
