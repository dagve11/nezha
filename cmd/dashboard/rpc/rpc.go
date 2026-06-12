package rpc

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/netip"
	"time"

	"github.com/goccy/go-json"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/hashicorp/go-uuid"
	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/utils"
	"github.com/nezhahq/nezha/proto"
	rpcService "github.com/nezhahq/nezha/service/rpc"
	"github.com/nezhahq/nezha/service/singleton"
)

func ServeRPC() *grpc.Server {
	server := grpc.NewServer(
		grpc.ChainUnaryInterceptor(getRealIp, waf),
		// Server 端 Keepalive 配置：防止空闲连接占用资源
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 15 * time.Minute, // 15 分钟空闲后关闭连接
			Time:              10 * time.Second, // 每 10 秒发送 keepalive ping
			Timeout:           3 * time.Second,  // 3 秒无响应视为客户端死亡
		}),
		// Keepalive 强制策略：防止客户端发送过于频繁的 keepalive
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second, // 客户端 keepalive 最小间隔
			PermitWithoutStream: true,            // 允许没有活跃 stream 时发送 keepalive
		}),
	)
	rpcService.NezhaHandlerSingleton = rpcService.NewNezhaHandler()
	handler := rpcService.NezhaHandlerSingleton
	// Install the IOStream revocation hook so ServerTransferShared can tear
	// down terminal/FM/NAT sessions held by the previous owner on every
	// ownership rotation (Register/revertTransition/OnServersDeleted).
	singleton.ServerTransferStreamRevocationHook = handler.RevokeStreamsForServer
	singleton.VPNRelayCreator = handler.CreateVPNRelay
	singleton.VPNRelayCloser = func(sessionID string) {
		_ = handler.CloseVPNRelay(sessionID)
	}
	handler.SetVPNRelayReporter(reportVPNRelayToSingleton)
	proto.RegisterNezhaServiceServer(server, handler)
	return server
}

func reportVPNRelayToSingleton(report rpcService.VPNRelayReport) bool {
	if singleton.VPNShared == nil {
		return false
	}
	if report.Event != "" {
		detail := ""
		if report.Error != nil {
			detail = report.Error.Error()
		}
		singleton.VPNShared.HandleRelayEvent(report.SessionID, report.Event, detail)
	}
	shouldClose, reason := singleton.VPNShared.HandleRelayTraffic(
		report.SessionID,
		report.UploadBytes,
		report.DownloadBytes,
		report.ActiveConnections,
	)
	if shouldClose && reason != "" {
		singleton.VPNShared.HandleRelayEvent(report.SessionID, "relay_policy_close", reason)
	}
	if report.Closed {
		singleton.VPNShared.HandleRelayClosed(report.SessionID, report.UploadBytes, report.DownloadBytes, report.Error)
	}
	return shouldClose
}

func waf(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	realip, _ := ctx.Value(model.CtxKeyRealIP{}).(string)
	if err := model.CheckIP(singleton.DB, realip); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func getRealIp(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	var ip, connectingIp string
	p, ok := peer.FromContext(ctx)
	if ok {
		addrPort, err := netip.ParseAddrPort(p.Addr.String())
		if err == nil {
			connectingIp = addrPort.Addr().String()
		}
	}
	ctx = context.WithValue(ctx, model.CtxKeyConnectingIP{}, connectingIp)

	if singleton.Conf.AgentRealIPHeader == "" {
		return handler(ctx, req)
	}

	if singleton.Conf.AgentRealIPHeader == model.ConfigUsePeerIP {
		if connectingIp == "" {
			return nil, fmt.Errorf("connecting ip not found")
		}
	} else {
		vals := metadata.ValueFromIncomingContext(ctx, singleton.Conf.AgentRealIPHeader)
		if len(vals) == 0 {
			return nil, fmt.Errorf("real ip header not found")
		}
		var err error
		ip, err = utils.GetIPFromHeader(vals[0])
		if err != nil {
			return nil, err
		}
	}

	if singleton.Conf.Debug {
		log.Printf("NEZHA>> gRPC Agent Real IP: %s, connecting IP: %s\n", ip, connectingIp)
	}

	ctx = context.WithValue(ctx, model.CtxKeyRealIP{}, ip)
	return handler(ctx, req)
}

func DispatchTask(serviceSentinelDispatchBus <-chan *model.Service) {
	for task := range serviceSentinelDispatchBus {
		if task == nil {
			continue
		}

		switch task.Cover {
		case model.ServiceCoverIgnoreAll:
			for id, enabled := range task.SkipServers {
				if !enabled {
					continue
				}

				server, _ := singleton.ServerShared.Get(id)
				if server == nil {
					continue
				}
				stream := server.GetTaskStream()
				if stream == nil {
					continue
				}

				if canSendTaskToServer(task, server) {
					stream.Send(task.PB())
				}
			}
		case model.ServiceCoverAll:
			for id, server := range singleton.ServerShared.Range {
				if server == nil || task.SkipServers[id] {
					continue
				}
				stream := server.GetTaskStream()
				if stream == nil {
					continue
				}

				if canSendTaskToServer(task, server) {
					stream.Send(task.PB())
				}
			}
		}
	}
}

func DispatchKeepalive() {
	singleton.CronShared.AddFunc("@every 20s", func() {
		list := singleton.ServerShared.GetSortedList()
		for _, s := range list {
			if s == nil {
				continue
			}
			stream := s.GetTaskStream()
			if stream == nil {
				continue
			}
			stream.Send(&proto.Task{Type: model.TaskTypeKeepalive})
		}
	})
}

func serveNATIO(userIO io.ReadWriteCloser, natConfig *model.NAT) error {
	streamId, cleanup, err := prepareNATStream(natConfig)
	if err != nil {
		return err
	}
	defer cleanup()

	return attachNATStream(streamId, userIO)
}

func prepareNATStream(natConfig *model.NAT) (string, func(), error) {
	server, _ := singleton.ServerShared.Get(natConfig.ServerID)
	if server == nil {
		return "", nil, fmt.Errorf("server not found or not connected")
	}
	stream := server.GetTaskStream()
	if stream == nil {
		return "", nil, fmt.Errorf("server not found or not connected")
	}

	streamId, err := uuid.GenerateUUID()
	if err != nil {
		return "", nil, fmt.Errorf("stream id error: %w", err)
	}

	// NAT streams are anonymous TCP-facing tunnels; they are NOT reachable
	// via /ws/terminal or /ws/file (which check stream ownership), so the
	// creator user ID does not need to identify a real user. The targetServerID
	// IS required though — the receiving agent must prove it is the server the
	// NAT config addressed, otherwise any agent that snoops the streamId can
	// answer NAT traffic on behalf of an unrelated host.
	rpcService.NezhaHandlerSingleton.CreateStream(streamId, 0, server.ID)
	cleanup := func() {
		rpcService.NezhaHandlerSingleton.CloseStream(streamId)
	}

	taskData, err := json.Marshal(model.TaskNAT{
		StreamID: streamId,
		Host:     natConfig.Host,
	})
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("task data error: %w", err)
	}

	if err := stream.Send(&proto.Task{
		Type: model.TaskTypeNAT,
		Data: string(taskData),
	}); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("send task error: %w", err)
	}

	return streamId, cleanup, nil
}

func attachNATStream(streamId string, userIO io.ReadWriteCloser) error {
	if err := rpcService.NezhaHandlerSingleton.UserConnected(streamId, userIO); err != nil {
		return fmt.Errorf("user connected error: %w", err)
	}

	return rpcService.NezhaHandlerSingleton.StartStream(streamId, time.Second*10)
}

func canSendTaskToServer(task *model.Service, server *model.Server) bool {
	var role model.Role
	singleton.UserLock.RLock()
	if u, ok := singleton.UserInfoMap[task.UserID]; !ok {
		role = model.RoleMember
	} else {
		role = u.Role
	}
	singleton.UserLock.RUnlock()

	return task.UserID == server.GetUserID() || role.IsAdmin()
}
