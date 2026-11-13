package swu

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/kimoju/vowifi-go/engine/swu/ikev2"
)

type kernelTunnelSessionConfig struct {
	Result                TunnelResult
	Tunnel                TunnelConfig
	TransportCfg          IKETransportConfig
	Transport             ikev2.InitTransport
	Init                  ikev2.InitResult
	ChildSA               ikev2.ChildSAResult
	XFRMConfig            KernelXFRMConfig
	XFRMManager           KernelXFRMManager
	XFRMState             KernelXFRMState
	Liveness              *IKELivenessState
	RekeyPolicy           ChildSARekeyPolicy
	IKERekeyPolicy        ChildSARekeyPolicy
	MOBIKEHandler         func(context.Context, MOBIKERequest) (MOBIKEResult, error)
	RekeyHandler          ChildSARekeyHandler
	IKERekeyHandler       IKESARekeyHandler
	ChildSADeleteHandler  func(context.Context, []byte) error
	DPDHandler            func(context.Context) error
	PeerIKERequestHandler PeerIKERequestHandler
	CloseHandler          func(context.Context) error
	BackgroundMaintenance bool
	MaintenanceInterval   time.Duration
}

type kernelTunnelSession struct {
	mu                   sync.Mutex
	result               TunnelResult
	tunnel               TunnelConfig
	transportCfg         IKETransportConfig
	transport            ikev2.InitTransport
	init                 ikev2.InitResult
	child                ikev2.ChildSAResult
	xfrmConfig           KernelXFRMConfig
	xfrmManager          KernelXFRMManager
	xfrmState            KernelXFRMState
	liveness             *IKELivenessState
	rekeyState           *ChildSARekeyState
	ikeRekeyState        *ChildSARekeyState
	mobikeHandler        func(context.Context, MOBIKERequest) (MOBIKEResult, error)
	rekeyHandler         ChildSARekeyHandler
	ikeRekeyHandler      IKESARekeyHandler
	childSADeleteHandler func(context.Context, []byte) error
	dpdHandler           func(context.Context) error
	peerIKEHandler       PeerIKERequestHandler
	closeHandler         func(context.Context) error
	maintCancel          context.CancelFunc
	maintDone            chan struct{}
	ikeReqCancel         context.CancelFunc
	ikeReqDone           chan struct{}
	closed               bool
}

var (
	_ TunnelSession          = (*kernelTunnelSession)(nil)
	_ IKELivenessController  = (*kernelTunnelSession)(nil)
	_ ChildSARekeyController = (*kernelTunnelSession)(nil)
	_ ChildSARekeyScheduler  = (*kernelTunnelSession)(nil)
	_ IKESARekeyController   = (*kernelTunnelSession)(nil)
)

func newKernelTunnelSession(result TunnelResult, xfrmManager KernelXFRMManager, state KernelXFRMState, closeHandler func(context.Context) error) (*kernelTunnelSession, error) {
	return newKernelTunnelSessionWithControl(kernelTunnelSessionConfig{
		Result:       result,
		XFRMManager:  xfrmManager,
		XFRMState:    state,
		CloseHandler: closeHandler,
	})
}

func newKernelTunnelSessionWithControl(cfg kernelTunnelSessionConfig) (*kernelTunnelSession, error) {
	if cfg.XFRMManager == nil {
		return nil, fmtInvalidKernelSession("xfrm manager is nil")
	}
	result := cfg.Result
	if result.Mode == "" {
		result.Mode = DataplaneModeKernel
	}
	if result.Reason == "" {
		result.Reason = "kernel ipsec tunnel ready"
	}
	if result.EstablishedAt.IsZero() {
		result.EstablishedAt = time.Now()
	}
	rekeyState, err := NewChildSARekeyState(cfg.RekeyPolicy, result.EstablishedAt)
	if err != nil {
		return nil, err
	}
	ikeRekeyState, err := NewChildSARekeyState(cfg.IKERekeyPolicy, result.EstablishedAt)
	if err != nil {
		return nil, err
	}
	s := &kernelTunnelSession{
		result:               result,
		tunnel:               cfg.Tunnel,
		transportCfg:         cfg.TransportCfg,
		transport:            cfg.Transport,
		init:                 cfg.Init,
		child:                cfg.ChildSA,
		xfrmConfig:           cfg.XFRMConfig,
		xfrmManager:          cfg.XFRMManager,
		xfrmState:            cfg.XFRMState,
		liveness:             cfg.Liveness,
		rekeyState:           rekeyState,
		ikeRekeyState:        ikeRekeyState,
		mobikeHandler:        cfg.MOBIKEHandler,
		rekeyHandler:         cfg.RekeyHandler,
		ikeRekeyHandler:      cfg.IKERekeyHandler,
		childSADeleteHandler: cfg.ChildSADeleteHandler,
		dpdHandler:           cfg.DPDHandler,
		peerIKEHandler:       cfg.PeerIKERequestHandler,
		closeHandler:         cfg.CloseHandler,
	}
	if s.peerIKEHandler != nil && cfg.Transport != nil {
		if reqReceiver, ok := cfg.Transport.(ikeRequestReceiver); ok {
			if msgSender, ok := cfg.Transport.(ikeMessageSender); ok {
				reqCtx, cancelReq := context.WithCancel(context.Background())
				s.ikeReqCancel = cancelReq
				s.ikeReqDone = make(chan struct{})
				go s.inboundIKERequestLoop(reqCtx, reqReceiver, msgSender)
			}
		}
	}
	if cfg.BackgroundMaintenance {
		interval := cfg.MaintenanceInterval
		if interval <= 0 {
			interval = defaultPacketMaintInterval
		}
		maintCtx, cancelMaint := context.WithCancel(context.Background())
		s.maintCancel = cancelMaint
		s.maintDone = make(chan struct{})
		go s.maintenanceLoop(maintCtx, interval)
	}
	return s, nil
}

func (s *kernelTunnelSession) inboundIKERequestLoop(ctx context.Context, receiver ikeRequestReceiver, sender ikeMessageSender) {
	defer close(s.ikeReqDone)
	for {
		raw, err := receiver.ReadIKERequest(ctx)
		if err != nil {
			return
		}
		s.mu.Lock()
		closed := s.closed
		handler := s.peerIKEHandler
		s.mu.Unlock()
		if closed || handler == nil {
			return
		}
		outcome, err := handler(ctx, raw)
		if err != nil {
			continue
		}
		now := time.Now()
		if outcome.NewChildSA != nil {
			if _, applyErr := s.applyRekeyedChildSA(ctx, *outcome.NewChildSA, "peer child sa rekeyed", now, false); applyErr != nil {
				continue
			}
		}
		if outcome.NewIKEInit != nil {
			s.mu.Lock()
			if !s.closed {
				s.init = *outcome.NewIKEInit
				s.result.IKEEstablished = true
				s.result.Ready = s.result.IPsecEstablished
				s.result.Reason = "peer ike sa rekeyed"
				if s.ikeRekeyState != nil {
					s.ikeRekeyState.RecordRekey(now)
				}
			}
			s.mu.Unlock()
		}
		s.RecordIKELivenessInbound(now)
		if len(outcome.Response) > 0 {
			sendCtx, cancelSend := context.WithTimeout(context.Background(), 5*time.Second)
			_ = sender.SendIKEMessage(sendCtx, outcome.Response)
			cancelSend()
		}
		if outcome.CloseReason != "" {
			s.handlePeerDelete(outcome.CloseReason)
			return
		}
	}
}

func (s *kernelTunnelSession) handlePeerDelete(reason string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.result.Ready = false
	s.result.IKEEstablished = false
	s.result.IPsecEstablished = false
	s.result.Reason = firstPacketNonEmpty(reason, "peer deleted tunnel")
	maintCancel := s.maintCancel
	xfrmManager := s.xfrmManager
	xfrmState := s.xfrmState
	transport := s.transport
	s.mu.Unlock()

	if maintCancel != nil {
		maintCancel()
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), defaultSWUCleanupTimeout)
	defer cancel()
	if xfrmManager != nil {
		_ = xfrmManager.Cleanup(cleanupCtx, xfrmState)
	}
	_ = closeIKETransport(transport)
}

func (s *kernelTunnelSession) maintenanceLoop(ctx context.Context, interval time.Duration) {
	defer close(s.maintDone)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			_, _ = s.AdvanceIKELiveness(ctx, now)
			_, _ = s.RunChildSARekeyDue(ctx, now)
			_, _ = s.RunIKESARekeyDue(ctx, now)
		}
	}
}

func (s *kernelTunnelSession) Result() TunnelResult {
	if s == nil {
		return TunnelResult{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneTunnelResult(s.result)
}

func (s *kernelTunnelSession) MOBIKE(ctx context.Context, req MOBIKERequest) (MOBIKEResult, error) {
	if s == nil {
		return MOBIKEResult{}, ErrTunnelNotReady
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		return MOBIKEResult{}, err
	}
	s.mu.Lock()
	closed := s.closed
	handler := s.mobikeHandler
	result := cloneTunnelResult(s.result)
	s.mu.Unlock()
	if closed {
		return MOBIKEResult{}, ErrPacketTunnelClosed
	}
	if handler == nil {
		return completeMOBIKEResult(MOBIKEResult{Reason: "mobike unsupported"}, req, result, "mobike unsupported"), nil
	}
	res, err := handler(ctx, req)
	if err != nil {
		return MOBIKEResult{}, err
	}
	res = completeMOBIKEResult(res, req, result, "mobike updated")

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return MOBIKEResult{}, ErrPacketTunnelClosed
	}
	nextCfg := s.xfrmConfig
	xfrmManager := s.xfrmManager
	oldState := s.xfrmState
	transport := s.transport
	s.mu.Unlock()

	if strings.TrimSpace(res.OuterLocalIP) != "" && xfrmManager != nil && nextCfg.OuterRemoteIP != "" {
		nextCfg.OuterLocalIP = strings.TrimSpace(res.OuterLocalIP)
		if nextCfg.XFRMInterface.Name != "" {
			nextCfg.XFRMInterface.SkipCreateLink = true
		}
		if nextCfg.NATTraversal.Enabled && transport != nil {
			if provider, ok := transport.(interface{ underlyingUDPConn() *net.UDPConn }); ok {
				if u := provider.underlyingUDPConn(); u != nil {
					if ua, ok := u.LocalAddr().(*net.UDPAddr); ok && ua.Port > 0 && ua.Port <= 65535 {
						nextCfg.NATTraversal.LocalPort = uint16(ua.Port)
					}
				}
			}
		}
		newState, applyErr := xfrmManager.Apply(ctx, nextCfg)
		if applyErr != nil {
			return MOBIKEResult{}, applyErr
		}
		mergedState, oldStateCleanup := mergeRekeyedXFRMStates(oldState, newState)
		s.mu.Lock()
		if !s.closed {
			s.xfrmConfig = nextCfg
			s.xfrmState = mergedState
		}
		s.mu.Unlock()
		if len(oldStateCleanup.undo) > 0 {
			cleanupCtx, cancel := independentCleanupContext(ctx)
			_ = xfrmManager.Cleanup(cleanupCtx, oldStateCleanup)
			cancel()
		}
	}

	s.mu.Lock()
	if !s.closed {
		s.result.LocalInnerIP = res.LocalInnerIP
		s.result.RemoteInnerIP = res.RemoteInnerIP
		s.result.DNSServers = append([]string(nil), res.DNSServers...)
		s.result.IKEEstablished = res.IKEEstablished
		s.result.IPsecEstablished = res.IPsecEstablished
		s.result.Ready = res.IKEEstablished && res.IPsecEstablished
		if res.Reason != "" {
			s.result.Reason = res.Reason
		}
	}
	s.mu.Unlock()
	return res, nil
}

func (s *kernelTunnelSession) RekeyChildSA(ctx context.Context) (TunnelResult, error) {
	return s.rekeyChildSA(ctx, time.Time{})
}

func (s *kernelTunnelSession) rekeyChildSA(ctx context.Context, rekeyedAt time.Time) (TunnelResult, error) {
	if s == nil {
		return TunnelResult{}, ErrInvalidIKETunnelManager
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		return TunnelResult{}, err
	}
	s.mu.Lock()
	closed := s.closed
	handler := s.rekeyHandler
	s.mu.Unlock()
	if closed {
		return TunnelResult{}, ErrPacketTunnelClosed
	}
	if handler == nil {
		return TunnelResult{}, fmtInvalidKernelSession("child sa rekey handler is nil")
	}
	newChild, err := handler(ctx)
	if err != nil {
		return TunnelResult{}, err
	}
	return s.applyRekeyedChildSA(ctx, newChild, "child sa rekeyed", rekeyedAt, true)
}

func (s *kernelTunnelSession) applyRekeyedChildSA(ctx context.Context, newChild ikev2.ChildSAResult, reason string, rekeyedAt time.Time, sendDelete bool) (TunnelResult, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return TunnelResult{}, ErrPacketTunnelClosed
	}
	oldChild := s.child
	oldState := s.xfrmState
	nextCfg := s.xfrmConfig
	xfrmManager := s.xfrmManager
	deleteHandler := s.childSADeleteHandler
	s.mu.Unlock()

	var oldLocalSPI []byte
	if len(oldChild.LocalSPI) == 4 && !bytesEqual4(oldChild.LocalSPI, newChild.LocalSPI) {
		oldLocalSPI = append([]byte(nil), oldChild.LocalSPI...)
	}

	if xfrmManager != nil && nextCfg.OuterLocalIP != "" && nextCfg.OuterRemoteIP != "" {
		nextCfg.ChildSA = newChild
		if nextCfg.XFRMInterface.Name != "" {
			nextCfg.XFRMInterface.SkipCreateLink = true
		}
		newState, err := xfrmManager.Apply(ctx, nextCfg)
		if err != nil {
			return TunnelResult{}, err
		}
		mergedState, oldStateCleanup := mergeRekeyedXFRMStates(oldState, newState)
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			cleanupCtx, cancel := independentCleanupContext(ctx)
			_ = xfrmManager.Cleanup(cleanupCtx, newState)
			cancel()
			return TunnelResult{}, ErrPacketTunnelClosed
		}
		s.child = newChild
		s.xfrmConfig = nextCfg
		s.xfrmState = mergedState
		s.result.IKEEstablished = true
		s.result.IPsecEstablished = true
		s.result.Ready = true
		s.result.ChildSAIdentifier = childSAIdentifier(newChild)
		s.result.Reason = reason
		if s.rekeyState != nil {
			s.rekeyState.RecordRekey(rekeyedAt)
		}
		updated := cloneTunnelResult(s.result)
		s.mu.Unlock()

		if sendDelete && deleteHandler != nil && len(oldLocalSPI) == 4 {
			_ = deleteHandler(ctx, oldLocalSPI)
		}
		if len(oldStateCleanup.undo) > 0 {
			cleanupCtx, cancel := independentCleanupContext(ctx)
			_ = xfrmManager.Cleanup(cleanupCtx, oldStateCleanup)
			cancel()
		}
		return updated, nil
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return TunnelResult{}, ErrPacketTunnelClosed
	}
	s.child = newChild
	s.result.IKEEstablished = true
	s.result.IPsecEstablished = true
	s.result.Ready = true
	s.result.ChildSAIdentifier = childSAIdentifier(newChild)
	s.result.Reason = reason
	if s.rekeyState != nil {
		s.rekeyState.RecordRekey(rekeyedAt)
	}
	updated := cloneTunnelResult(s.result)
	s.mu.Unlock()
	if sendDelete && deleteHandler != nil && len(oldLocalSPI) == 4 {
		_ = deleteHandler(ctx, oldLocalSPI)
	}
	return updated, nil
}

func mergeRekeyedXFRMStates(oldState, newState KernelXFRMState) (merged KernelXFRMState, oldCleanup KernelXFRMState) {
	newUndoKeys := make(map[string]bool, len(newState.undo))
	for _, cmd := range newState.undo {
		newUndoKeys[strings.Join(cmd.args, "\x00")] = true
	}
	merged.undo = append([]ipCommand(nil), newState.undo...)
	for _, cmd := range oldState.undo {
		key := strings.Join(cmd.args, "\x00")
		if len(cmd.args) >= 2 && cmd.args[0] == "link" && cmd.args[1] == "del" {
			if !newUndoKeys[key] {
				// Keep interface deletion at the bottom (executed last on reverse-order Cleanup).
				merged.undo = append([]ipCommand{cmd}, merged.undo...)
			}
			continue
		}
		if len(cmd.args) >= 3 && cmd.args[0] == "xfrm" && cmd.args[1] == "state" && cmd.args[2] == "delete" && !newUndoKeys[key] {
			oldCleanup.undo = append(oldCleanup.undo, cmd)
		}
	}
	return merged, oldCleanup
}

func bytesEqual4(a, b []byte) bool {
	return len(a) == 4 && len(b) == 4 && binary.BigEndian.Uint32(a) == binary.BigEndian.Uint32(b)
}

func (s *kernelTunnelSession) AdvanceChildSARekey(ctx context.Context, now time.Time) (ChildSARekeyDecision, error) {
	if s == nil {
		return ChildSARekeyDecision{}, ErrInvalidIKETunnelManager
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		return ChildSARekeyDecision{}, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ChildSARekeyDecision{}, ErrPacketTunnelClosed
	}
	var decision ChildSARekeyDecision
	if s.rekeyState != nil && s.rekeyHandler != nil {
		decision = s.rekeyState.Advance(now)
	} else {
		decision = ChildSARekeyDecision{Action: ChildSARekeyNoAction, Reason: "rekey disabled"}
	}
	s.mu.Unlock()
	if decision.Action != ChildSARekeyDue {
		return decision, nil
	}
	_, err := s.rekeyChildSA(ctx, now)
	return decision, err
}

func (s *kernelTunnelSession) RunChildSARekeyDue(ctx context.Context, now time.Time) (ChildSARekeyDecision, error) {
	decision, err := s.AdvanceChildSARekey(ctx, now)
	if err != nil || decision.Action != ChildSARekeyDue {
		return decision, err
	}
	if nextDue, ok := s.NextChildSARekeyDue(); ok {
		decision.NextDue = nextDue
	}
	return decision, nil
}

func (s *kernelTunnelSession) NextChildSARekeyDue() (time.Time, bool) {
	if s == nil {
		return time.Time{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.rekeyState == nil {
		return time.Time{}, false
	}
	return s.rekeyState.NextDue()
}

func (s *kernelTunnelSession) ChildSARekeySnapshot() ChildSARekeySnapshot {
	if s == nil {
		return ChildSARekeySnapshot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rekeyState == nil {
		return ChildSARekeySnapshot{}
	}
	return s.rekeyState.Snapshot()
}

func (s *kernelTunnelSession) RekeyIKESA(ctx context.Context) (TunnelResult, error) {
	return s.rekeyIKESA(ctx, time.Time{})
}

func (s *kernelTunnelSession) rekeyIKESA(ctx context.Context, rekeyedAt time.Time) (TunnelResult, error) {
	if s == nil {
		return TunnelResult{}, ErrInvalidIKETunnelManager
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		return TunnelResult{}, err
	}
	s.mu.Lock()
	closed := s.closed
	handler := s.ikeRekeyHandler
	s.mu.Unlock()
	if closed {
		return TunnelResult{}, ErrPacketTunnelClosed
	}
	if handler == nil {
		return TunnelResult{}, fmtInvalidKernelSession("ike sa rekey handler is nil")
	}
	newInit, err := handler(ctx)
	if err != nil {
		return TunnelResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return TunnelResult{}, ErrPacketTunnelClosed
	}
	s.init = newInit
	s.result.IKEEstablished = true
	s.result.Ready = s.result.IPsecEstablished
	s.result.Reason = "ike sa rekeyed"
	if s.ikeRekeyState != nil {
		s.ikeRekeyState.RecordRekey(rekeyedAt)
	}
	return cloneTunnelResult(s.result), nil
}

func (s *kernelTunnelSession) RunIKESARekeyDue(ctx context.Context, now time.Time) (ChildSARekeyDecision, error) {
	if s == nil {
		return ChildSARekeyDecision{}, ErrInvalidIKETunnelManager
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		return ChildSARekeyDecision{}, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ChildSARekeyDecision{}, ErrPacketTunnelClosed
	}
	var decision ChildSARekeyDecision
	if s.ikeRekeyState != nil && s.ikeRekeyHandler != nil {
		decision = s.ikeRekeyState.Advance(now)
	} else {
		decision = ChildSARekeyDecision{Action: ChildSARekeyNoAction, Reason: "ike rekey disabled"}
	}
	s.mu.Unlock()
	if decision.Action != ChildSARekeyDue {
		return decision, nil
	}
	_, err := s.rekeyIKESA(ctx, now)
	return decision, err
}

func (s *kernelTunnelSession) AdvanceIKELiveness(ctx context.Context, now time.Time) (IKELivenessDecision, error) {
	if s == nil {
		return IKELivenessDecision{}, ErrInvalidIKETunnelManager
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		return IKELivenessDecision{}, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return IKELivenessDecision{}, ErrPacketTunnelClosed
	}
	if s.liveness == nil {
		cfg := IKELivenessConfig{}
		if s.dpdHandler == nil {
			cfg.DisableDPD = true
		}
		liveness, err := NewIKELivenessState(cfg, s.result.EstablishedAt)
		if err != nil {
			s.mu.Unlock()
			return IKELivenessDecision{}, err
		}
		s.liveness = liveness
	}
	decision := s.liveness.Advance(now)
	transport := s.transport
	nattEnabled := s.xfrmConfig.NATTraversal.Enabled || s.init.NATDetected || s.transportCfg.UseNonESPMarker
	dpdHandler := s.dpdHandler
	s.mu.Unlock()

	switch decision.Action {
	case IKELivenessSendKeepalive:
		if !nattEnabled {
			return decision, nil
		}
		if sender, ok := transport.(NATTKeepaliveSender); ok {
			if err := sender.SendNATTKeepalive(ctx); err != nil {
				return decision, err
			}
			return decision, nil
		}
		if provider, ok := transport.(sharedNATTESPProvider); ok {
			if espTr := provider.sharedESPTransport(); espTr != nil {
				if sender, ok := espTr.(NATTKeepaliveSender); ok {
					if err := sender.SendNATTKeepalive(ctx); err != nil {
						return decision, err
					}
					return decision, nil
				}
			}
		}
		return decision, nil
	case IKELivenessSendDPD:
		if dpdHandler == nil {
			return decision, fmtInvalidKernelSession("DPD handler is nil")
		}
		err := dpdHandler(ctx)
		s.RecordIKELivenessResult(now, err == nil)
		if err != nil {
			if snapshot := s.IKELivenessSnapshot(); snapshot.Dead {
				decision.Dead = true
				decision.MissedDPDProbes = snapshot.MissedDPDProbes
				decision.Reason = firstPacketNonEmpty(err.Error(), "dpd probe failed")
				s.markTunnelNotReady(ikeLivenessDeadReason(decision))
			}
		}
		return decision, err
	case IKELivenessDeclareDead:
		s.markTunnelNotReady(ikeLivenessDeadReason(decision))
	}
	return decision, nil
}

func (s *kernelTunnelSession) RecordIKELivenessInbound(at time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.liveness != nil {
		s.liveness.RecordInbound(at)
	}
}

func (s *kernelTunnelSession) RecordIKELivenessOutbound(at time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.liveness != nil {
		s.liveness.RecordOutbound(at)
	}
}

func (s *kernelTunnelSession) RecordIKELivenessResult(at time.Time, ok bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.liveness != nil {
		s.liveness.RecordLivenessResult(at, ok)
	}
}

func (s *kernelTunnelSession) IKELivenessSnapshot() IKELivenessSnapshot {
	if s == nil {
		return IKELivenessSnapshot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.liveness == nil {
		return IKELivenessSnapshot{}
	}
	return s.liveness.Snapshot()
}

func (s *kernelTunnelSession) markTunnelNotReady(reason string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.result.Ready = false
	s.result.IKEEstablished = false
	s.result.IPsecEstablished = false
	s.result.Reason = firstPacketNonEmpty(reason, "ike liveness dead")
}

func (s *kernelTunnelSession) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	maintCancel := s.maintCancel
	maintDone := s.maintDone
	ikeReqCancel := s.ikeReqCancel
	ikeReqDone := s.ikeReqDone
	xfrmManager := s.xfrmManager
	xfrmState := s.xfrmState
	closeHandler := s.closeHandler
	s.mu.Unlock()

	if maintCancel != nil {
		maintCancel()
	}
	if maintDone != nil {
		<-maintDone
	}
	if ikeReqCancel != nil {
		ikeReqCancel()
	}
	if ikeReqDone != nil {
		<-ikeReqDone
	}

	cleanupCtx, cancel := context.WithTimeout(context.Background(), defaultSWUCleanupTimeout)
	defer cancel()
	if ctx != nil && ctx.Err() == nil {
		cleanupCtx = ctx
	}

	var err error
	if closeHandler != nil {
		err = closeHandler(cleanupCtx)
	}
	if xfrmManager != nil {
		err = errors.Join(err, xfrmManager.Cleanup(cleanupCtx, xfrmState))
	}
	return err
}

func fmtInvalidKernelSession(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidIKETunnelManager, reason)
}
