package rpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"google.golang.org/grpc/metadata"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/nezhahq/nezha/model"
	pb "github.com/nezhahq/nezha/proto"
	"github.com/nezhahq/nezha/service/singleton"
)

type requestTaskSecurityStream struct {
	ctx     context.Context
	results []*pb.TaskResult
	onRecv  func()
	onSend  func(*pb.Task)
	sendErr error
	recvN   int
}

type reportStateSecurityStream struct {
	ctx      context.Context
	states   []*pb.State
	receipts []*pb.Receipt
}

func (s *requestTaskSecurityStream) Send(task *pb.Task) error {
	if s.onSend != nil {
		s.onSend(task)
	}
	return s.sendErr
}

func (s *requestTaskSecurityStream) Recv() (*pb.TaskResult, error) {
	s.recvN++
	if s.onRecv != nil {
		s.onRecv()
	}
	if len(s.results) == 0 {
		return nil, context.Canceled
	}
	result := s.results[0]
	s.results = s.results[1:]
	return result, nil
}

func (s *requestTaskSecurityStream) SetHeader(metadata.MD) error  { return nil }
func (s *requestTaskSecurityStream) SendHeader(metadata.MD) error { return nil }
func (s *requestTaskSecurityStream) SetTrailer(metadata.MD)       {}
func (s *requestTaskSecurityStream) Context() context.Context     { return s.ctx }
func (s *requestTaskSecurityStream) SendMsg(any) error            { return nil }
func (s *requestTaskSecurityStream) RecvMsg(any) error            { return context.Canceled }

func (s *reportStateSecurityStream) Send(receipt *pb.Receipt) error {
	s.receipts = append(s.receipts, receipt)
	return nil
}

func (s *reportStateSecurityStream) Recv() (*pb.State, error) {
	if len(s.states) == 0 {
		return nil, context.Canceled
	}
	state := s.states[0]
	s.states = s.states[1:]
	return state, nil
}

func (s *reportStateSecurityStream) SetHeader(metadata.MD) error  { return nil }
func (s *reportStateSecurityStream) SendHeader(metadata.MD) error { return nil }
func (s *reportStateSecurityStream) SetTrailer(metadata.MD)       {}
func (s *reportStateSecurityStream) Context() context.Context     { return s.ctx }
func (s *reportStateSecurityStream) SendMsg(any) error            { return nil }
func (s *reportStateSecurityStream) RecvMsg(any) error            { return context.Canceled }

func TestRequestTaskSkipsCronResultOwnedByAnotherUser(t *testing.T) {
	reporter := requestTaskSecurityServer(7, 200, "11111111-1111-1111-1111-111111111111")
	victimCron := requestTaskSecurityCron(42, 100, model.CronCoverAll, nil)
	setupRequestTaskSecurityFixture(t, []*model.Server{reporter}, []*model.Cron{victimCron}, map[uint64]model.UserInfo{
		100: {Role: model.RoleMember},
		200: {Role: model.RoleMember},
	}, map[string]uint64{"reporter-secret": 200})

	runRequestTaskSecurityResult(t, "reporter-secret", reporter.UUID, cronTaskResult(victimCron.ID, true))

	if cronLastResult(t, victimCron.ID) {
		t.Fatal("foreign cron result must not update victim cron status")
	}
}

func TestRequestTaskSkipsCronResultOutsideReporterCover(t *testing.T) {
	reporter := requestTaskSecurityServer(7, 200, "22222222-2222-2222-2222-222222222222")
	coveredServerID := uint64(8)
	cronTask := requestTaskSecurityCron(42, 200, model.CronCoverIgnoreAll, []uint64{coveredServerID})
	setupRequestTaskSecurityFixture(t, []*model.Server{reporter}, []*model.Cron{cronTask}, map[uint64]model.UserInfo{
		200: {Role: model.RoleMember},
	}, map[string]uint64{"reporter-secret": 200})

	runRequestTaskSecurityResult(t, "reporter-secret", reporter.UUID, cronTaskResult(cronTask.ID, true))

	if cronLastResult(t, cronTask.ID) {
		t.Fatal("cron result from a server outside cron cover must not update cron status")
	}
}

func TestRequestTaskSkipsCronCoverAllExcludedReporter(t *testing.T) {
	reporter := requestTaskSecurityServer(7, 200, "88888888-8888-8888-8888-888888888888")
	cronTask := requestTaskSecurityCron(42, 200, model.CronCoverAll, []uint64{reporter.ID})
	setupRequestTaskSecurityFixture(t, []*model.Server{reporter}, []*model.Cron{cronTask}, map[uint64]model.UserInfo{
		200: {Role: model.RoleMember},
	}, map[string]uint64{"reporter-secret": 200})

	runRequestTaskSecurityResult(t, "reporter-secret", reporter.UUID, cronTaskResult(cronTask.ID, true))

	if cronLastResult(t, cronTask.ID) {
		t.Fatal("cron result from a server excluded by CronCoverAll must not update cron status")
	}
}

func TestRequestTaskAllowsCronCoverAllReporter(t *testing.T) {
	reporter := requestTaskSecurityServer(7, 200, "99999999-9999-9999-9999-999999999999")
	cronTask := requestTaskSecurityCron(42, 200, model.CronCoverAll, []uint64{8})
	setupRequestTaskSecurityFixture(t, []*model.Server{reporter}, []*model.Cron{cronTask}, map[uint64]model.UserInfo{
		200: {Role: model.RoleMember},
	}, map[string]uint64{"reporter-secret": 200})

	runRequestTaskSecurityResult(t, "reporter-secret", reporter.UUID, cronTaskResult(cronTask.ID, true))

	if !cronLastResult(t, cronTask.ID) {
		t.Fatal("CronCoverAll reporter not in the exclusion list must update cron status")
	}
}

func TestRequestTaskAllowsCronResultForCoveredOwnerServer(t *testing.T) {
	reporter := requestTaskSecurityServer(7, 200, "33333333-3333-3333-3333-333333333333")
	cronTask := requestTaskSecurityCron(42, 200, model.CronCoverIgnoreAll, []uint64{reporter.ID})
	setupRequestTaskSecurityFixture(t, []*model.Server{reporter}, []*model.Cron{cronTask}, map[uint64]model.UserInfo{
		200: {Role: model.RoleMember},
	}, map[string]uint64{"reporter-secret": 200})

	runRequestTaskSecurityResult(t, "reporter-secret", reporter.UUID, cronTaskResult(cronTask.ID, true))

	if !cronLastResult(t, cronTask.ID) {
		t.Fatal("covered owner cron result must update cron status")
	}
}

func TestRequestTaskAllowsCronResultForCoveredAdminOwnedCron(t *testing.T) {
	reporter := requestTaskSecurityServer(7, 200, "44444444-4444-4444-4444-444444444444")
	cronTask := requestTaskSecurityCron(42, 1, model.CronCoverIgnoreAll, []uint64{reporter.ID})
	setupRequestTaskSecurityFixture(t, []*model.Server{reporter}, []*model.Cron{cronTask}, map[uint64]model.UserInfo{
		1:   {Role: model.RoleAdmin},
		200: {Role: model.RoleMember},
	}, map[string]uint64{"reporter-secret": 200})

	runRequestTaskSecurityResult(t, "reporter-secret", reporter.UUID, cronTaskResult(cronTask.ID, true))

	if !cronLastResult(t, cronTask.ID) {
		t.Fatal("covered admin-owned cron result must update cron status")
	}
}

func TestRequestTaskSkipsAlertTriggerCronResultFromUntriggeredReporter(t *testing.T) {
	reporter := requestTaskSecurityServer(7, 200, "55555555-5555-5555-5555-555555555555")
	triggerServer := requestTaskSecurityServer(8, 200, "66666666-6666-6666-6666-666666666666")
	cronTask := requestTaskSecurityCron(42, 200, model.CronCoverAlertTrigger, nil)
	setupRequestTaskSecurityFixture(t, []*model.Server{reporter, triggerServer}, []*model.Cron{cronTask}, map[uint64]model.UserInfo{
		200: {Role: model.RoleMember},
	}, map[string]uint64{"reporter-secret": 200, "trigger-secret": 200})
	connectRequestTaskSecurityTaskStream(t, triggerServer.ID)
	singleton.CronTrigger(cronTask, triggerServer.ID)()

	runRequestTaskSecurityResult(t, "reporter-secret", reporter.UUID, cronTaskResult(cronTask.ID, true))

	if cronLastResult(t, cronTask.ID) {
		t.Fatal("alert-trigger cron result from a non-triggered server must not update cron status")
	}
}

func TestRequestTaskAllowsAlertTriggerCronResultForTriggeredReporter(t *testing.T) {
	reporter := requestTaskSecurityServer(7, 200, "77777777-7777-7777-7777-777777777777")
	cronTask := requestTaskSecurityCron(42, 200, model.CronCoverAlertTrigger, nil)
	setupRequestTaskSecurityFixture(t, []*model.Server{reporter}, []*model.Cron{cronTask}, map[uint64]model.UserInfo{
		200: {Role: model.RoleMember},
	}, map[string]uint64{"reporter-secret": 200})
	connectRequestTaskSecurityTaskStream(t, reporter.ID)
	singleton.CronTrigger(cronTask, reporter.ID)()

	runRequestTaskSecurityResult(t, "reporter-secret", reporter.UUID, cronTaskResult(cronTask.ID, true))

	if !cronLastResult(t, cronTask.ID) {
		t.Fatal("alert-trigger cron result from the triggered server must update cron status")
	}
}

func TestRequestTaskAllowsAlertTriggerCronResultReportedDuringSend(t *testing.T) {
	reporter := requestTaskSecurityServer(7, 200, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	cronTask := requestTaskSecurityCron(42, 200, model.CronCoverAlertTrigger, nil)
	setupRequestTaskSecurityFixture(t, []*model.Server{reporter}, []*model.Cron{cronTask}, map[uint64]model.UserInfo{
		200: {Role: model.RoleMember},
	}, map[string]uint64{"reporter-secret": 200})
	connectRequestTaskSecurityTaskStreamWithSendHook(t, reporter.ID, nil, func(task *pb.Task) {
		if task.GetId() != cronTask.ID {
			t.Fatalf("expected alert-trigger task %d, got %d", cronTask.ID, task.GetId())
		}
		runRequestTaskSecurityResult(t, "reporter-secret", reporter.UUID, cronTaskResult(cronTask.ID, true))
	})

	singleton.CronTrigger(cronTask, reporter.ID)()

	if !cronLastResult(t, cronTask.ID) {
		t.Fatal("alert-trigger cron result reported during Send must update cron status")
	}
}

func TestRequestTaskSkipsAlertTriggerCronResultAfterSendFailure(t *testing.T) {
	reporter := requestTaskSecurityServer(7, 200, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	cronTask := requestTaskSecurityCron(42, 200, model.CronCoverAlertTrigger, nil)
	setupRequestTaskSecurityFixture(t, []*model.Server{reporter}, []*model.Cron{cronTask}, map[uint64]model.UserInfo{
		200: {Role: model.RoleMember},
	}, map[string]uint64{"reporter-secret": 200})
	connectRequestTaskSecurityTaskStreamWithSendHook(t, reporter.ID, errors.New("send failed"), nil)
	singleton.CronTrigger(cronTask, reporter.ID)()

	runRequestTaskSecurityResult(t, "reporter-secret", reporter.UUID, cronTaskResult(cronTask.ID, true))

	if cronLastResult(t, cronTask.ID) {
		t.Fatal("alert-trigger cron result after failed dispatch must not update cron status")
	}
}

func TestRequestTaskClearsTaskStreamOnRecvError(t *testing.T) {
	reporter := requestTaskSecurityServer(7, 200, "cccccccc-cccc-cccc-cccc-cccccccccccc")
	setupRequestTaskSecurityFixture(t, []*model.Server{reporter}, nil, map[uint64]model.UserInfo{
		200: {Role: model.RoleMember},
	}, map[string]uint64{"reporter-secret": 200})

	stream := requestTaskSecurityAuthedStream("reporter-secret", reporter.UUID)
	err := NewNezhaHandler().RequestTask(stream)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected RequestTask to finish after Recv error, got %v", err)
	}

	server, ok := singleton.ServerShared.Get(reporter.ID)
	if !ok {
		t.Fatalf("server %d not found", reporter.ID)
	}
	if got := server.GetTaskStream(); got != nil {
		t.Fatalf("dead RequestTask stream must be cleared, got %T", got)
	}
}

func TestRequestTaskKeepsNewerTaskStreamOnOldRecvError(t *testing.T) {
	reporter := requestTaskSecurityServer(7, 200, "dddddddd-dddd-dddd-dddd-dddddddddddd")
	setupRequestTaskSecurityFixture(t, []*model.Server{reporter}, nil, map[uint64]model.UserInfo{
		200: {Role: model.RoleMember},
	}, map[string]uint64{"reporter-secret": 200})

	server, ok := singleton.ServerShared.Get(reporter.ID)
	if !ok {
		t.Fatalf("server %d not found", reporter.ID)
	}
	newer := &requestTaskSecurityStream{ctx: context.Background()}
	old := requestTaskSecurityAuthedStream("reporter-secret", reporter.UUID)
	old.onRecv = func() {
		server.SetTaskStream(newer)
	}

	err := NewNezhaHandler().RequestTask(old)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected RequestTask to finish after Recv error, got %v", err)
	}
	if got := server.GetTaskStream(); got != newer {
		t.Fatalf("old stream cleanup must keep newer stream, got %T", got)
	}
}

func TestRequestTaskDispatchesVPNControlResult(t *testing.T) {
	entry := requestTaskSecurityServer(1, 200, "11111111-2222-3333-4444-555555555555")
	exit := requestTaskSecurityServer(2, 200, "22222222-3333-4444-5555-666666666666")
	setupRequestTaskSecurityFixture(t, []*model.Server{entry, exit}, nil, map[uint64]model.UserInfo{
		200: {Role: model.RoleMember},
	}, map[string]uint64{"agent-secret": 200})
	setRequestTaskSecurityServerVPNCapability(t, entry.ID)
	setRequestTaskSecurityServerVPNCapability(t, exit.ID)

	originalTokenGenerator := singleton.VPNTokenGenerator
	originalIDGenerator := singleton.VPNIDGenerator
	originalNotificationSender := singleton.VPNNotificationSender
	singleton.VPNTokenGenerator = func() (string, error) { return "rpc-vpn-token", nil }
	ids := []string{"rpc_session", "rpc_entry_stream", "rpc_exit_stream"}
	idIndex := 0
	singleton.VPNIDGenerator = func(prefix string) (string, error) {
		id := ids[idIndex%len(ids)]
		idIndex++
		return id, nil
	}
	singleton.VPNNotificationSender = func(uint64, string, string) {}
	t.Cleanup(func() {
		singleton.VPNTokenGenerator = originalTokenGenerator
		singleton.VPNIDGenerator = originalIDGenerator
		singleton.VPNNotificationSender = originalNotificationSender
	})

	entrySent := make(chan *pb.Task, 1)
	connectRequestTaskSecurityTaskStreamWithSendHook(t, entry.ID, nil, func(task *pb.Task) {
		entrySent <- task
	})
	connectRequestTaskSecurityTaskStream(t, exit.ID)
	policy, err := singleton.VPNShared.SavePolicy(singleton.VPNActor{UserID: 200, Role: model.RoleMember}, model.AgentVPNPolicyForm{
		Name:           "rpc vpn",
		EntryServerID:  entry.ID,
		ExitServerID:   exit.ID,
		Mode:           model.VPNModeSystemProxy,
		RuleMode:       model.VPNRuleModeGlobal,
		ListenSOCKS:    "127.0.0.1:1080",
		ExpiresSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("save vpn policy: %v", err)
	}
	session, err := singleton.VPNShared.StartSession(singleton.VPNActor{UserID: 200, Role: model.RoleMember}, policy.ID)
	if err != nil {
		t.Fatalf("start vpn session: %v", err)
	}

	resultData, err := json.Marshal(model.VPNControlResult{
		SessionID: session.SessionID,
		Action:    model.VPNActionStart,
		Role:      model.VPNRoleExit,
		State:     model.VPNStateRunning,
	})
	if err != nil {
		t.Fatal(err)
	}
	runRequestTaskSecurityResult(t, "agent-secret", exit.UUID, &pb.TaskResult{
		Id:         session.ID,
		Type:       model.TaskTypeVPNControl,
		Data:       string(resultData),
		Successful: true,
	})

	select {
	case task := <-entrySent:
		if task.GetType() != model.TaskTypeVPNControl {
			t.Fatalf("expected VPN control task, got %d", task.GetType())
		}
		var req model.VPNControlRequest
		if err := json.Unmarshal([]byte(task.GetData()), &req); err != nil {
			t.Fatalf("decode entry start request: %v", err)
		}
		if req.SessionID != session.SessionID || req.Role != model.VPNRoleEntry || req.Action != model.VPNActionStart {
			t.Fatalf("unexpected entry task: %+v", req)
		}
	case <-time.After(time.Second):
		t.Fatal("exit running result must dispatch entry start task")
	}
}

func TestRequestTaskQueriesVPNStatusOnAgentReconnect(t *testing.T) {
	entry := requestTaskSecurityServer(1, 200, "31313131-3131-3131-3131-313131313131")
	exit := requestTaskSecurityServer(2, 200, "41414141-4141-4141-4141-414141414141")
	setupRequestTaskSecurityFixture(t, []*model.Server{entry, exit}, nil, map[uint64]model.UserInfo{
		200: {Role: model.RoleMember},
	}, map[string]uint64{"entry-secret": 200})
	setRequestTaskSecurityServerVPNCapability(t, entry.ID)
	setRequestTaskSecurityServerVPNCapability(t, exit.ID)

	if err := singleton.DB.Create(&model.AgentVPNPolicy{
		Common:         model.Common{ID: 7, UserID: 200},
		Name:           "reconnect vpn",
		EntryServerID:  entry.ID,
		ExitServerID:   exit.ID,
		Mode:           model.VPNModeSystemProxy,
		RuleMode:       model.VPNRuleModeGlobal,
		ListenSOCKS:    "127.0.0.1:1080",
		ExpiresSeconds: 3600,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := singleton.DB.Create(&model.AgentVPNSession{
		Common:        model.Common{ID: 9, UserID: 200},
		PolicyID:      7,
		EntryServerID: entry.ID,
		ExitServerID:  exit.ID,
		SessionID:     "vpn_reconnect_session",
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		State:         model.VPNStateRunning,
		EntryState:    model.VPNStateRunning,
		ExitState:     model.VPNStateRunning,
		EntryStreamID: "vpn_reconnect_entry_stream",
		ExitStreamID:  "vpn_reconnect_exit_stream",
		StartedAt:     time.Now().Add(-time.Minute),
		ExpiresAt:     time.Now().Add(time.Hour),
	}).Error; err != nil {
		t.Fatal(err)
	}

	var sent []*pb.Task
	stream := requestTaskSecurityAuthedStream("entry-secret", entry.UUID)
	stream.onSend = func(task *pb.Task) {
		sent = append(sent, task)
	}

	err := NewNezhaHandler().RequestTask(stream)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected RequestTask to finish after reconnect status send, got %v", err)
	}
	if len(sent) != 1 {
		t.Fatalf("agent reconnect must receive one VPN status task, got %d", len(sent))
	}
	var req model.VPNControlRequest
	if err := json.Unmarshal([]byte(sent[0].GetData()), &req); err != nil {
		t.Fatalf("decode VPN status task: %v", err)
	}
	if sent[0].GetType() != model.TaskTypeVPNControl || req.Action != model.VPNActionStatus || req.Role != model.VPNRoleEntry || req.SessionID != "vpn_reconnect_session" {
		t.Fatalf("unexpected VPN reconnect status task: type=%d req=%+v", sent[0].GetType(), req)
	}
}

func TestRequestTaskDeletedUUIDReceivesDestroyTask(t *testing.T) {
	const deletedUUID = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
	setupRequestTaskSecurityFixture(t, nil, nil, map[uint64]model.UserInfo{
		200: {Role: model.RoleMember},
	}, map[string]uint64{"reporter-secret": 200})

	if err := singleton.DB.Create(&model.DeletedServer{
		Common:   model.Common{UserID: 200},
		ServerID: 7,
		UUID:     deletedUUID,
		Name:     "deleted-server",
	}).Error; err != nil {
		t.Fatalf("create deleted server tombstone: %v", err)
	}

	var sent []*pb.Task
	stream := requestTaskSecurityAuthedStream("reporter-secret", deletedUUID)
	stream.onSend = func(task *pb.Task) {
		sent = append(sent, task)
	}

	err := NewNezhaHandler().RequestTask(stream)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected RequestTask to close after destroy task for deleted UUID, got %v", err)
	}
	if len(sent) != 1 {
		t.Fatalf("deleted UUID RequestTask must receive exactly one destroy task, got %d", len(sent))
	}
	if sent[0].GetType() != model.TaskTypeDestroyAgent {
		t.Fatalf("deleted UUID RequestTask must receive destroy task, got type=%d", sent[0].GetType())
	}
}

func TestRequestTaskDeletedUUIDWaitsForDestroyTaskResult(t *testing.T) {
	const deletedUUID = "edededed-eded-eded-eded-edededededed"
	setupRequestTaskSecurityFixture(t, nil, nil, map[uint64]model.UserInfo{
		200: {Role: model.RoleMember},
	}, map[string]uint64{"reporter-secret": 200})

	if err := singleton.DB.Create(&model.DeletedServer{
		Common:   model.Common{UserID: 200},
		ServerID: 7,
		UUID:     deletedUUID,
		Name:     "deleted-server",
	}).Error; err != nil {
		t.Fatalf("create deleted server tombstone: %v", err)
	}

	stream := requestTaskSecurityAuthedStream("reporter-secret", deletedUUID)
	stream.results = []*pb.TaskResult{{
		Type:       model.TaskTypeDestroyAgent,
		Successful: true,
		Data:       "agent self-removal scheduled",
	}}

	err := NewNezhaHandler().RequestTask(stream)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected RequestTask to close after destroy task result, got %v", err)
	}
	if stream.recvN == 0 {
		t.Fatal("deleted UUID RequestTask must wait for the agent to receive and report the destroy task before closing the stream")
	}
}

func TestReportSystemInfo2AllowsDeletedUUIDToReachDestroyTask(t *testing.T) {
	const deletedUUID = "abababab-abab-abab-abab-abababababab"
	setupRequestTaskSecurityFixture(t, nil, nil, map[uint64]model.UserInfo{
		200: {Role: model.RoleMember},
	}, map[string]uint64{"reporter-secret": 200})

	if err := singleton.DB.Create(&model.DeletedServer{
		Common:   model.Common{UserID: 200},
		ServerID: 7,
		UUID:     deletedUUID,
		Name:     "deleted-server",
	}).Error; err != nil {
		t.Fatalf("create deleted server tombstone: %v", err)
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"client_secret", "reporter-secret",
		"client_uuid", deletedUUID,
	))
	if _, err := NewNezhaHandler().ReportSystemInfo2(ctx, &pb.Host{}); err != nil {
		t.Fatalf("deleted UUID ReportSystemInfo2 must succeed so agent can open RequestTask and receive destroy task, got %v", err)
	}

	var count int64
	if err := singleton.DB.Model(&model.Server{}).Where("uuid = ?", deletedUUID).Count(&count).Error; err != nil {
		t.Fatalf("count server rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("deleted UUID ReportSystemInfo2 must not recreate server row, got count=%d", count)
	}
}

func TestReportSystemStateAllowsDeletedUUIDDuringDestroy(t *testing.T) {
	const deletedUUID = "12121212-1212-1212-1212-121212121212"
	setupRequestTaskSecurityFixture(t, nil, nil, map[uint64]model.UserInfo{
		200: {Role: model.RoleMember},
	}, map[string]uint64{"reporter-secret": 200})

	if err := singleton.DB.Create(&model.DeletedServer{
		Common:   model.Common{UserID: 200},
		ServerID: 7,
		UUID:     deletedUUID,
		Name:     "deleted-server",
	}).Error; err != nil {
		t.Fatalf("create deleted server tombstone: %v", err)
	}

	stream := &reportStateSecurityStream{
		ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs(
			"client_secret", "reporter-secret",
			"client_uuid", deletedUUID,
		)),
		states: []*pb.State{{Cpu: 1}},
	}

	err := NewNezhaHandler().ReportSystemState(stream)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("deleted UUID ReportSystemState must drain until the agent disconnects, got %v", err)
	}
	if len(stream.receipts) != 1 || !stream.receipts[0].GetProced() {
		t.Fatalf("deleted UUID ReportSystemState must acknowledge state while destroy task is delivered, got %#v", stream.receipts)
	}

	var count int64
	if err := singleton.DB.Model(&model.Server{}).Where("uuid = ?", deletedUUID).Count(&count).Error; err != nil {
		t.Fatalf("count server rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("deleted UUID ReportSystemState must not recreate server row, got count=%d", count)
	}
}

func setupRequestTaskSecurityFixture(t *testing.T, servers []*model.Server, crons []*model.Cron, users map[uint64]model.UserInfo, agentSecrets map[string]uint64) {
	t.Helper()

	originalDB := singleton.DB
	originalConf := singleton.Conf
	originalLoc := singleton.Loc
	originalServerShared := singleton.ServerShared
	originalCronShared := singleton.CronShared
	originalVPNShared := singleton.VPNShared
	originalUserInfoMap := singleton.UserInfoMap
	originalAgentSecretToUserID := singleton.AgentSecretToUserId

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)

	singleton.DB = db
	singleton.Conf = &singleton.ConfigClass{Config: &model.Config{}}
	singleton.Loc = time.UTC
	if err := singleton.DB.AutoMigrate(model.Server{}, model.Cron{}, model.DeletedServer{}, model.AgentVPNPolicy{}, model.AgentVPNSession{}, model.AgentVPNAuditLog{}); err != nil {
		t.Fatal(err)
	}
	for _, server := range servers {
		if err := singleton.DB.Create(server).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, cronTask := range crons {
		if err := singleton.DB.Create(cronTask).Error; err != nil {
			t.Fatal(err)
		}
	}

	singleton.UserLock.Lock()
	singleton.UserInfoMap = users
	singleton.AgentSecretToUserId = agentSecrets
	singleton.UserLock.Unlock()
	singleton.ServerShared = singleton.NewServerClass()
	singleton.CronShared = singleton.NewCronClass()
	singleton.VPNShared = singleton.NewVPNClass()

	t.Cleanup(func() {
		if singleton.CronShared != nil && singleton.CronShared.Cron != nil {
			singleton.CronShared.Stop()
		}
		sqlDB.Close()
		singleton.DB = originalDB
		singleton.Conf = originalConf
		singleton.Loc = originalLoc
		singleton.ServerShared = originalServerShared
		singleton.CronShared = originalCronShared
		singleton.VPNShared = originalVPNShared
		singleton.UserLock.Lock()
		singleton.UserInfoMap = originalUserInfoMap
		singleton.AgentSecretToUserId = originalAgentSecretToUserID
		singleton.UserLock.Unlock()
	})
}

func requestTaskSecurityServer(id, userID uint64, uuid string) *model.Server {
	return &model.Server{
		Common: model.Common{ID: id, UserID: userID},
		UUID:   uuid,
		Name:   "request-task-security-server",
	}
}

func setRequestTaskSecurityServerVPNCapability(t *testing.T, serverID uint64) {
	t.Helper()
	server, ok := singleton.ServerShared.Get(serverID)
	if !ok || server == nil {
		t.Fatalf("server %d not found", serverID)
	}
	server.Host = &model.Host{
		VPNEnabled:          true,
		VPNAllowSystemProxy: true,
		VPNAllowTun:         true,
		VPNCoreVersion:      "1.12.0",
	}
}

func requestTaskSecurityCron(id, userID uint64, cover uint8, servers []uint64) *model.Cron {
	return &model.Cron{
		Common:    model.Common{ID: id, UserID: userID},
		Name:      "request-task-security-cron",
		Command:   "id",
		Scheduler: "@every 1h",
		Cover:     cover,
		Servers:   servers,
	}
}

func cronTaskResult(cronID uint64, successful bool) *pb.TaskResult {
	return &pb.TaskResult{
		Id:         cronID,
		Type:       model.TaskTypeCommand,
		Delay:      1,
		Data:       "cron result",
		Successful: successful,
	}
}

func connectRequestTaskSecurityTaskStream(t *testing.T, serverID uint64) {
	t.Helper()

	connectRequestTaskSecurityTaskStreamWithSendHook(t, serverID, nil, nil)
}

func connectRequestTaskSecurityTaskStreamWithSendHook(t *testing.T, serverID uint64, sendErr error, onSend func(*pb.Task)) {
	t.Helper()

	server, ok := singleton.ServerShared.Get(serverID)
	if !ok {
		t.Fatalf("server %d not found", serverID)
	}
	server.SetTaskStream(&requestTaskSecurityStream{ctx: context.Background(), sendErr: sendErr, onSend: onSend})
}

func runRequestTaskSecurityResult(t *testing.T, secret string, uuid string, result *pb.TaskResult) {
	t.Helper()

	stream := requestTaskSecurityAuthedStream(secret, uuid)
	stream.results = []*pb.TaskResult{result}
	err := NewNezhaHandler().RequestTask(stream)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected RequestTask to finish after test result, got %v", err)
	}
}

func requestTaskSecurityAuthedStream(secret string, uuid string) *requestTaskSecurityStream {
	return &requestTaskSecurityStream{
		ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs(
			"client_secret", secret,
			"client_uuid", uuid,
		)),
	}
}

func cronLastResult(t *testing.T, cronID uint64) bool {
	t.Helper()

	var cronTask model.Cron
	if err := singleton.DB.First(&cronTask, cronID).Error; err != nil {
		t.Fatal(err)
	}
	return cronTask.LastResult
}
