package singleton

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goccy/go-json"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/bestip"
	pb "github.com/nezhahq/nezha/proto"
)

const (
	bestIPFissionRemoteAckTimeout = 20 * time.Second
	bestIPFissionRemoteTimeout    = 30 * time.Minute
)

var (
	bestIPFissionTaskSeq atomic.Uint64
	bestIPFissionWaiters = struct {
		sync.Mutex
		items map[string]chan model.BestIPFissionTaskResult
	}{items: make(map[string]chan model.BestIPFissionTaskResult)}
)

var BestIPFissionLocalRunner = func(ctx context.Context, config bestip.FissionConfig, progress func(bestip.FissionProgressEvent)) (*bestip.FissionRunResult, error) {
	service := bestip.NewFissionService(config)
	service.Progress = progress
	return service.Run(ctx)
}

func RunBestIPFission(ctx context.Context, userID uint64, form model.BestIPFissionForm, progress func(bestip.FissionProgressEvent)) (*bestip.FissionRunResult, error) {
	probeServerID := form.ProbeServerID
	config := form
	config.ProbeServerID = 0

	config, err := bestip.NormalizeFissionConfig(config)
	if err != nil {
		if progress != nil {
			progress(bestip.FissionProgressEvent{Type: bestip.FissionProgressError, Error: err.Error()})
		}
		return nil, err
	}

	if probeServerID == 0 {
		return BestIPFissionLocalRunner(ctx, config, progress)
	}
	return runRemoteBestIPFission(ctx, userID, probeServerID, config, progress)
}

func runRemoteBestIPFission(ctx context.Context, userID, probeServerID uint64, config bestip.FissionConfig, progress func(bestip.FissionProgressEvent)) (*bestip.FissionRunResult, error) {
	if err := canUseBestIPProbeServer(userID, probeServerID); err != nil {
		return nil, err
	}
	server, _ := ServerShared.Get(probeServerID)
	stream := server.GetTaskStream()
	if stream == nil {
		return nil, bestIPErrorf("probe server is offline")
	}

	taskID := bestIPFissionTaskSeq.Add(1)
	waiter := registerBestIPFissionWaiter(probeServerID, taskID)
	defer unregisterBestIPFissionWaiter(probeServerID, taskID)

	payload, err := json.Marshal(model.BestIPFissionTaskRequest{Config: config})
	if err != nil {
		return nil, err
	}
	if err := stream.Send(&pb.Task{
		Id:   taskID,
		Type: model.TaskTypeBestIPFission,
		Data: string(payload),
	}); err != nil {
		return nil, err
	}

	acknowledged := false
	ackTimeout := time.NewTimer(bestIPFissionRemoteAckTimeout)
	defer ackTimeout.Stop()
	timeout := time.NewTimer(bestIPFissionRemoteTimeout)
	defer timeout.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ackTimeout.C:
			if !acknowledged {
				return nil, bestIPErrorf("probe server did not acknowledge BestIP fission task; update the agent and try again")
			}
		case <-timeout.C:
			return nil, bestIPErrorf("operation timeout")
		case result := <-waiter:
			if !acknowledged {
				acknowledged = true
				if !ackTimeout.Stop() {
					select {
					case <-ackTimeout.C:
					default:
					}
				}
			}
			switch result.Kind {
			case model.BestIPFissionTaskResultProgress:
				if result.Event != nil && progress != nil {
					progress(*result.Event)
				}
			case model.BestIPFissionTaskResultDone:
				if result.Result == nil {
					return nil, bestIPErrorf("bestip fission returned empty result")
				}
				return result.Result, nil
			case model.BestIPFissionTaskResultError:
				if result.Error == "" {
					result.Error = "bestip fission failed"
				}
				return nil, fmt.Errorf("%s", result.Error)
			}
		}
	}
}

func HandleBestIPFissionTaskResult(serverID uint64, result *pb.TaskResult) {
	if result == nil {
		return
	}
	key := bestIPFissionWaiterKey(serverID, result.GetId())
	bestIPFissionWaiters.Lock()
	waiter := bestIPFissionWaiters.items[key]
	bestIPFissionWaiters.Unlock()
	if waiter == nil {
		return
	}

	payload := model.BestIPFissionTaskResult{}
	if err := json.Unmarshal([]byte(result.GetData()), &payload); err != nil {
		payload.Kind = model.BestIPFissionTaskResultError
		payload.Error = result.GetData()
		if payload.Error == "" {
			payload.Error = err.Error()
		}
	}
	if payload.Kind == "" {
		if result.GetSuccessful() {
			payload.Kind = model.BestIPFissionTaskResultDone
		} else {
			payload.Kind = model.BestIPFissionTaskResultError
			payload.Error = result.GetData()
		}
	}

	if payload.Kind == model.BestIPFissionTaskResultProgress {
		select {
		case waiter <- payload:
		default:
			log.Printf("NEZHA>> BestIP fission progress dropped: server=%d task=%d", serverID, result.GetId())
		}
		return
	}

	select {
	case waiter <- payload:
	case <-time.After(5 * time.Second):
		log.Printf("NEZHA>> BestIP fission final result delivery timed out: server=%d task=%d", serverID, result.GetId())
	}
}

func registerBestIPFissionWaiter(serverID, taskID uint64) chan model.BestIPFissionTaskResult {
	waiter := make(chan model.BestIPFissionTaskResult, 1024)
	bestIPFissionWaiters.Lock()
	bestIPFissionWaiters.items[bestIPFissionWaiterKey(serverID, taskID)] = waiter
	bestIPFissionWaiters.Unlock()
	return waiter
}

func unregisterBestIPFissionWaiter(serverID, taskID uint64) {
	bestIPFissionWaiters.Lock()
	delete(bestIPFissionWaiters.items, bestIPFissionWaiterKey(serverID, taskID))
	bestIPFissionWaiters.Unlock()
}

func bestIPFissionWaiterKey(serverID, taskID uint64) string {
	return fmt.Sprintf("%d:%d", serverID, taskID)
}

func canUseBestIPProbeServer(userID, serverID uint64) error {
	if serverID == 0 {
		return nil
	}
	if ServerShared == nil {
		return bestIPErrorf("server list is not initialized")
	}
	server, ok := ServerShared.Get(serverID)
	if !ok || server == nil {
		return bestIPErrorf("server id %d does not exist", serverID)
	}
	if server.GetUserID() != userID && !userIsAdmin(userID) {
		return bestIPErrorf("permission denied")
	}
	return nil
}

func bestIPErrorf(format string, args ...any) error {
	if Localizer != nil {
		return Localizer.ErrorT(format, args...)
	}
	return fmt.Errorf(format, args...)
}
