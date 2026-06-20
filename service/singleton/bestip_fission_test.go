package singleton

import (
	"context"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/bestip"
	"github.com/nezhahq/nezha/pkg/i18n"
	pb "github.com/nezhahq/nezha/proto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestRunBestIPFissionDispatchesToProbeServer(t *testing.T) {
	originalServerShared := ServerShared
	originalLocalizer := Localizer
	originalUserInfoMap := UserInfoMap
	t.Cleanup(func() {
		ServerShared = originalServerShared
		Localizer = originalLocalizer
		UserLock.Lock()
		UserInfoMap = originalUserInfoMap
		UserLock.Unlock()
	})

	Localizer = i18n.NewLocalizer("en_US", "nezha", "translations", i18n.Translations)
	UserLock.Lock()
	UserInfoMap = map[uint64]model.UserInfo{200: {Role: model.RoleMember}}
	UserLock.Unlock()

	server := &model.Server{Common: model.Common{ID: 22, UserID: 200}, Name: "cn-probe"}
	model.InitServer(server)
	stream := &bestIPFissionCaptureStream{tasks: make(chan *pb.Task, 1)}
	server.SetTaskStream(stream)
	ServerShared = &ServerClass{
		class: class[uint64, *model.Server]{
			list: map[uint64]*model.Server{server.ID: server},
		},
		uuidToID: map[string]uint64{},
	}

	resultCh := make(chan *bestip.FissionRunResult, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := RunBestIPFission(context.Background(), 200, bestip.FissionConfig{
			ProbeServerID: 22,
			SeedIPs:       []string{"1.1.1.1"},
			Rounds:        1,
			Concurrency:   1,
			TimeoutMS:     1000,
			Families:      []string{"ipv4"},
		}, nil)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()

	var task *pb.Task
	select {
	case task = <-stream.tasks:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for BestIP task dispatch")
	}
	require.Equal(t, uint64(model.TaskTypeBestIPFission), task.GetType())

	var req model.BestIPFissionTaskRequest
	require.NoError(t, json.Unmarshal([]byte(task.GetData()), &req))
	require.Equal(t, uint64(0), req.Config.ProbeServerID)
	require.Equal(t, []string{"1.1.1.1"}, req.Config.SeedIPs)

	payload, err := json.Marshal(model.BestIPFissionTaskResult{
		Kind: model.BestIPFissionTaskResultDone,
		Result: &bestip.FissionRunResult{
			IPs: []string{"1.1.1.1", "1.0.0.1"},
		},
	})
	require.NoError(t, err)
	HandleBestIPFissionTaskResult(server.ID, &pb.TaskResult{
		Id:         task.GetId(),
		Type:       model.TaskTypeBestIPFission,
		Successful: true,
		Data:       string(payload),
	})

	select {
	case err := <-errCh:
		t.Fatalf("RunBestIPFission returned error: %v", err)
	case result := <-resultCh:
		require.Equal(t, []string{"1.1.1.1", "1.0.0.1"}, result.IPs)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for BestIP result")
	}
}

type bestIPFissionCaptureStream struct {
	pb.NezhaService_RequestTaskServer
	tasks chan *pb.Task
}

func (s *bestIPFissionCaptureStream) Send(task *pb.Task) error {
	s.tasks <- task
	return nil
}

func (s *bestIPFissionCaptureStream) Recv() (*pb.TaskResult, error) { return nil, context.Canceled }
func (s *bestIPFissionCaptureStream) SetHeader(metadata.MD) error   { return nil }
func (s *bestIPFissionCaptureStream) SendHeader(metadata.MD) error  { return nil }
func (s *bestIPFissionCaptureStream) SetTrailer(metadata.MD)        {}
func (s *bestIPFissionCaptureStream) Context() context.Context      { return context.Background() }
func (s *bestIPFissionCaptureStream) SendMsg(any) error             { return nil }
func (s *bestIPFissionCaptureStream) RecvMsg(any) error             { return context.Canceled }
