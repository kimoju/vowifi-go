package swu

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kimoju/vowifi-go/engine/swu/esp"
	"github.com/kimoju/vowifi-go/engine/swu/ikev2"
)

const (
	defaultChildSARekeyGracePeriod = 15 * time.Second
	defaultPacketMaintInterval     = 5 * time.Second
	espSequenceRekeyThreshold      = uint32(0xE0000000)
)

var (
	ErrInvalidPacketTunnel       = errors.New("invalid swu packet tunnel")
	ErrPacketTunnelClosed        = errors.New("swu packet tunnel closed")
	ErrUnsupportedInnerPacket    = errors.New("unsupported inner packet")
	ErrInvalidChildSARekeyPolicy = errors.New("invalid swu child sa rekey policy")
)

type ESPPacketTransport interface {
	SendESPPacket(context.Context, []byte) error
}

type ESPPacketReceiver interface {
	ReadESPPacket(context.Context) ([]byte, error)
}

type ESPPacketReadWriteTransport interface {
	ESPPacketTransport
	ESPPacketReceiver
}

type ESPPacketTransportFunc func(context.Context, []byte) error

func (f ESPPacketTransportFunc) SendESPPacket(ctx context.Context, packet []byte) error {
	if f == nil {
		return fmt.Errorf("%w: transport is nil", ErrInvalidPacketTunnel)
	}
	return f(ctx, packet)
}

type ChildSARekeyHandler func(context.Context) (ikev2.ChildSAResult, error)

type IKESARekeyHandler func(context.Context) (ikev2.InitResult, error)

type ChildSARekeyScheduler interface {
	RekeyChildSA(context.Context) (TunnelResult, error)
	NextChildSARekeyDue() (time.Time, bool)
	RunChildSARekeyDue(context.Context, time.Time) (ChildSARekeyDecision, error)
	ChildSARekeySnapshot() ChildSARekeySnapshot
}

type ChildSARekeyAction uint8

const (
	ChildSARekeyNoAction ChildSARekeyAction = iota
	ChildSARekeyDue
)

func (a ChildSARekeyAction) String() string {
	switch a {
	case ChildSARekeyNoAction:
		return "none"
	case ChildSARekeyDue:
		return "rekey"
	default:
		return fmt.Sprintf("child sa rekey action %d", a)
	}
}

type ChildSARekeyPolicy struct {
	Lifetime time.Duration
	LeadTime time.Duration
	Disabled bool
}

type ChildSARekeyDecision struct {
	Action        ChildSARekeyAction
	EstablishedAt time.Time
	DueAt         time.Time
	ExpiresAt     time.Time
	NextDue       time.Time
	Age           time.Duration
	TimeToExpire  time.Duration
	Lifetime      time.Duration
	LeadTime      time.Duration
	Expired       bool
	Reason        string
}

type ChildSARekeySnapshot struct {
	Enabled       bool
	EstablishedAt time.Time
	DueAt         time.Time
	ExpiresAt     time.Time
	Lifetime      time.Duration
	LeadTime      time.Duration
}

type ChildSARekeyWindow struct {
	Enabled       bool
	Due           bool
	Expired       bool
	EstablishedAt time.Time
	DueAt         time.Time
	ExpiresAt     time.Time
	Age           time.Duration
	TimeToRekey   time.Duration
	TimeToExpire  time.Duration
	Lifetime      time.Duration
	LeadTime      time.Duration
}

type ChildSARekeyState struct {
	policy        ChildSARekeyPolicy
	establishedAt time.Time
	enabled       bool
}

func NewChildSARekeyState(policy ChildSARekeyPolicy, establishedAt time.Time) (*ChildSARekeyState, error) {
	normalized, enabled, err := normalizeChildSARekeyPolicy(policy)
	if err != nil {
		return nil, err
	}
	if establishedAt.IsZero() {
		establishedAt = time.Now()
	}
	return &ChildSARekeyState{
		policy:        normalized,
		establishedAt: establishedAt,
		enabled:       enabled,
	}, nil
}

func (s *ChildSARekeyState) Advance(now time.Time) ChildSARekeyDecision {
	if now.IsZero() {
		now = time.Now()
	}
	if s == nil || !s.enabled {
		return ChildSARekeyDecision{
			Action: ChildSARekeyNoAction,
			Reason: "rekey disabled",
		}
	}
	decision := s.decision(now, ChildSARekeyNoAction, "child sa rekey not due")
	if decision.Expired {
		decision.Action = ChildSARekeyDue
		decision.Reason = "child sa lifetime expired"
	} else if !now.Before(decision.DueAt) {
		decision.Action = ChildSARekeyDue
		decision.Reason = "child sa rekey due"
	}
	return decision
}

func (s *ChildSARekeyState) RecordRekey(at time.Time) {
	if s == nil || !s.enabled {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	s.establishedAt = at
}

func (s *ChildSARekeyState) Snapshot() ChildSARekeySnapshot {
	if s == nil || !s.enabled {
		return ChildSARekeySnapshot{}
	}
	return ChildSARekeySnapshot{
		Enabled:       true,
		EstablishedAt: s.establishedAt,
		DueAt:         s.dueAt(),
		ExpiresAt:     s.expiresAt(),
		Lifetime:      s.policy.Lifetime,
		LeadTime:      s.policy.LeadTime,
	}
}

func (s *ChildSARekeyState) NextDue() (time.Time, bool) {
	if s == nil || !s.enabled {
		return time.Time{}, false
	}
	return s.dueAt(), true
}

func (s *ChildSARekeyState) decision(now time.Time, action ChildSARekeyAction, reason string) ChildSARekeyDecision {
	window := s.window(now)
	return ChildSARekeyDecision{
		Action:        action,
		EstablishedAt: s.establishedAt,
		DueAt:         window.DueAt,
		ExpiresAt:     window.ExpiresAt,
		NextDue:       window.DueAt,
		Age:           window.Age,
		TimeToExpire:  window.TimeToExpire,
		Lifetime:      s.policy.Lifetime,
		LeadTime:      s.policy.LeadTime,
		Expired:       window.Expired,
		Reason:        reason,
	}
}

func (s *ChildSARekeyState) dueAt() time.Time {
	return s.establishedAt.Add(s.policy.Lifetime - s.policy.LeadTime)
}

func (s *ChildSARekeyState) expiresAt() time.Time {
	return s.establishedAt.Add(s.policy.Lifetime)
}

func (s *ChildSARekeyState) window(now time.Time) ChildSARekeyWindow {
	window, _ := ChildSARekeyWindowFor(s.policy, s.establishedAt, now)
	return window
}

func ChildSARekeyWindowFor(policy ChildSARekeyPolicy, establishedAt, now time.Time) (ChildSARekeyWindow, error) {
	normalized, enabled, err := normalizeChildSARekeyPolicy(policy)
	if err != nil {
		return ChildSARekeyWindow{}, err
	}
	if !enabled {
		return ChildSARekeyWindow{}, nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	if establishedAt.IsZero() {
		establishedAt = now
	}
	expiresAt := establishedAt.Add(normalized.Lifetime)
	dueAt := expiresAt.Add(-normalized.LeadTime)
	age := time.Duration(0)
	if now.After(establishedAt) {
		age = now.Sub(establishedAt)
	}
	timeToRekey := time.Duration(0)
	if now.Before(dueAt) {
		timeToRekey = dueAt.Sub(now)
	}
	timeToExpire := time.Duration(0)
	if now.Before(expiresAt) {
		timeToExpire = expiresAt.Sub(now)
	}
	return ChildSARekeyWindow{
		Enabled:       true,
		Due:           !now.Before(dueAt),
		Expired:       !now.Before(expiresAt),
		EstablishedAt: establishedAt,
		DueAt:         dueAt,
		ExpiresAt:     expiresAt,
		Age:           age,
		TimeToRekey:   timeToRekey,
		TimeToExpire:  timeToExpire,
		Lifetime:      normalized.Lifetime,
		LeadTime:      normalized.LeadTime,
	}, nil
}

func normalizeChildSARekeyPolicy(policy ChildSARekeyPolicy) (ChildSARekeyPolicy, bool, error) {
	if policy.Lifetime < 0 {
		return ChildSARekeyPolicy{}, false, fmt.Errorf("%w: lifetime is negative", ErrInvalidChildSARekeyPolicy)
	}
	if policy.LeadTime < 0 {
		return ChildSARekeyPolicy{}, false, fmt.Errorf("%w: lead time is negative", ErrInvalidChildSARekeyPolicy)
	}
	if policy.Disabled || policy.Lifetime == 0 {
		return ChildSARekeyPolicy{Disabled: true}, false, nil
	}
	if policy.LeadTime >= policy.Lifetime {
		return ChildSARekeyPolicy{}, false, fmt.Errorf("%w: lead time must be less than lifetime", ErrInvalidChildSARekeyPolicy)
	}
	return policy, true, nil
}

type ESPPacketTransportCloser interface {
	ESPPacketTransport
	Close(context.Context) error
}

type NATTKeepaliveSender interface {
	SendNATTKeepalive(context.Context) error
}

type PacketTunnelStats struct {
	OutboundInnerPackets uint64
	OutboundInnerBytes   uint64
	OutboundESPPackets   uint64
	OutboundESPBytes     uint64
	OutboundErrors       uint64
	InboundInnerPackets  uint64
	InboundInnerBytes    uint64
	InboundESPPackets    uint64
	InboundESPBytes      uint64
	InboundErrors        uint64
	ReplayDrops          uint64
	InvalidDrops         uint64
	UnsupportedDrops     uint64
}

type PacketTunnelPacket struct {
	SPI        uint32
	Sequence   uint32
	NextHeader uint8
	Payload    []byte
}

type PacketTunnelSession interface {
	TunnelSession
	SendInnerPacket(context.Context, []byte) error
	SendInnerPacketWithNextHeader(context.Context, uint8, []byte) error
	ReceiveESPPacket(context.Context, []byte) (PacketTunnelPacket, error)
	PacketStats() PacketTunnelStats
}

type PacketTunnelReadSession interface {
	PacketTunnelSession
	ReadInnerPacket(context.Context) (PacketTunnelPacket, error)
}

type PeerIKERequestOutcome struct {
	Response    []byte
	CloseReason string
	NewChildSA  *ikev2.ChildSAResult
	NewIKEInit  *ikev2.InitResult
}

type PeerIKERequestHandler func(context.Context, []byte) (PeerIKERequestOutcome, error)

type PacketSessionConfig struct {
	Result                TunnelResult
	ChildSA               ikev2.ChildSAResult
	OutboundSA            *esp.SA
	InboundSA             *esp.SA
	Transport             ESPPacketTransport
	MTU                   int
	Random                io.Reader
	MOBIKEHandler         func(context.Context, MOBIKERequest) (MOBIKEResult, error)
	RekeyHandler          ChildSARekeyHandler
	IKERekeyHandler       IKESARekeyHandler
	ChildSADeleteHandler  func(context.Context, []byte) error
	PeerIKERequestHandler PeerIKERequestHandler
	IKEInit               ikev2.InitResult
	IKEKeys               ikev2.IKEKeys
	RekeyPolicy           ChildSARekeyPolicy
	IKERekeyPolicy        ChildSARekeyPolicy
	RekeyGracePeriod      time.Duration
	MOBIKENAT             *MOBIKENATState
	Liveness              *IKELivenessState
	DPDHandler            func(context.Context) error
	CloseHandler          func(context.Context) error
	BackgroundMaintenance bool
	MaintenanceInterval   time.Duration
}

type PacketSession struct {
	mu                   sync.Mutex
	result               TunnelResult
	outbound             *esp.SA
	inbound              *esp.SA
	prevInbound          *esp.SA
	prevInboundUntil     time.Time
	rekeyGracePeriod     time.Duration
	transport            ESPPacketTransport
	mtu                  int
	random               io.Reader
	mobikeHandler        func(context.Context, MOBIKERequest) (MOBIKEResult, error)
	rekeyHandler         ChildSARekeyHandler
	ikeRekeyHandler      IKESARekeyHandler
	childSADeleteHandler func(context.Context, []byte) error
	peerIKEHandler       PeerIKERequestHandler
	ikeInit              ikev2.InitResult
	ikeKeys              ikev2.IKEKeys
	prevIKEInit          *ikev2.InitResult
	prevIKEKeys          ikev2.IKEKeys
	rekeyInFlight        int
	trackedChild         ikev2.ChildSAResult
	rekeyState           *ChildSARekeyState
	ikeRekeyState        *ChildSARekeyState
	mobikeNAT            *MOBIKENATState
	liveness             *IKELivenessState
	dpdHandler           func(context.Context) error
	closeHandler         func(context.Context) error
	feedbackCh           chan PacketTunnelPacket
	feedbackWake         context.CancelFunc
	maintCancel          context.CancelFunc
	maintDone            chan struct{}
	ikeReqCancel         context.CancelFunc
	ikeReqDone           chan struct{}
	stats                PacketTunnelStats
	closed               bool
}

var (
	_ PacketTunnelSession     = (*PacketSession)(nil)
	_ PacketTunnelReadSession = (*PacketSession)(nil)
	_ MOBIKENATObserver       = (*PacketSession)(nil)
	_ IKELivenessController   = (*PacketSession)(nil)
	_ ChildSARekeyController  = (*PacketSession)(nil)
	_ ChildSARekeyScheduler   = (*PacketSession)(nil)
	_ IKESARekeyController    = (*PacketSession)(nil)
)

func NewPacketSession(cfg PacketSessionConfig) (*PacketSession, error) {
	if cfg.Transport == nil {
		return nil, fmt.Errorf("%w: transport is nil", ErrInvalidPacketTunnel)
	}
	outbound, inbound, err := packetSAs(cfg)
	if err != nil {
		return nil, err
	}
	result := cfg.Result
	if isZeroTunnelResult(result) {
		result.Ready = true
		result.IKEEstablished = true
		result.IPsecEstablished = true
	}
	if result.Mode == "" {
		result.Mode = DataplaneModeUserspace
	}
	if result.Reason == "" {
		result.Reason = "packet tunnel ready"
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
	gracePeriod := cfg.RekeyGracePeriod
	if gracePeriod <= 0 {
		gracePeriod = defaultChildSARekeyGracePeriod
	}
	session := &PacketSession{
		result:               result,
		outbound:             outbound,
		inbound:              inbound,
		rekeyGracePeriod:     gracePeriod,
		transport:            cfg.Transport,
		mtu:                  cfg.MTU,
		random:               cfg.Random,
		mobikeHandler:        cfg.MOBIKEHandler,
		rekeyHandler:         cfg.RekeyHandler,
		ikeRekeyHandler:      cfg.IKERekeyHandler,
		childSADeleteHandler: cfg.ChildSADeleteHandler,
		peerIKEHandler:       cfg.PeerIKERequestHandler,
		ikeInit:              cfg.IKEInit,
		ikeKeys:              cfg.IKEKeys,
		trackedChild:         cfg.ChildSA,
		rekeyState:           rekeyState,
		ikeRekeyState:        ikeRekeyState,
		mobikeNAT:            cfg.MOBIKENAT,
		liveness:             cfg.Liveness,
		dpdHandler:           cfg.DPDHandler,
		closeHandler:         cfg.CloseHandler,
		feedbackCh:           make(chan PacketTunnelPacket, 16),
	}
	if session.peerIKEHandler == nil && ikeKeysUsable(cfg.IKEKeys) && cfg.IKEInit.InitiatorSPI != 0 && cfg.IKEInit.ResponderSPI != 0 {
		session.peerIKEHandler = session.defaultHandlePeerIKERequest
	}
	if session.peerIKEHandler != nil {
		if reqReceiver, ok := cfg.Transport.(ikeRequestReceiver); ok {
			if msgSender, ok := cfg.Transport.(ikeMessageSender); ok {
				reqCtx, cancelReq := context.WithCancel(context.Background())
				session.ikeReqCancel = cancelReq
				session.ikeReqDone = make(chan struct{})
				go session.inboundIKERequestLoop(reqCtx, reqReceiver, msgSender)
			}
		}
	}
	if cfg.BackgroundMaintenance {
		interval := cfg.MaintenanceInterval
		if interval <= 0 {
			interval = defaultPacketMaintInterval
		}
		maintCtx, cancel := context.WithCancel(context.Background())
		session.maintCancel = cancel
		session.maintDone = make(chan struct{})
		go session.maintenanceLoop(maintCtx, interval)
	}
	return session, nil
}

func (s *PacketSession) inboundIKERequestLoop(ctx context.Context, receiver ikeRequestReceiver, sender ikeMessageSender) {
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
		if outcome.NewChildSA != nil || outcome.NewIKEInit != nil {
			if applyErr := s.applyPeerIKEOutcome(outcome); applyErr != nil {
				continue
			}
		}
		s.RecordIKELivenessInbound(time.Now())
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

func (s *PacketSession) applyPeerIKEOutcome(outcome PeerIKERequestOutcome) error {
	if s == nil {
		return ErrInvalidPacketTunnel
	}
	var outbound, inbound *esp.SA
	if outcome.NewChildSA != nil {
		var err error
		outbound, inbound, err = packetSAs(PacketSessionConfig{ChildSA: *outcome.NewChildSA})
		if err != nil {
			return err
		}
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrPacketTunnelClosed
	}
	if outcome.NewChildSA != nil {
		child := *outcome.NewChildSA
		gracePeriod := s.rekeyGracePeriod
		if gracePeriod <= 0 {
			gracePeriod = defaultChildSARekeyGracePeriod
		}
		if s.inbound != nil && s.inbound.SPI != inbound.SPI {
			s.prevInbound = s.inbound
			s.prevInboundUntil = now.Add(gracePeriod)
		}
		s.outbound = outbound
		s.inbound = inbound
		s.trackedChild = child
		s.result.IKEEstablished = true
		s.result.IPsecEstablished = true
		s.result.Ready = true
		s.result.ChildSAIdentifier = childSAIdentifier(child)
		s.result.Reason = "peer child sa rekeyed"
		if s.rekeyState != nil {
			s.rekeyState.RecordRekey(now)
		}
	}
	if outcome.NewIKEInit != nil {
		prevCopy := s.ikeInit
		s.prevIKEInit = &prevCopy
		s.prevIKEKeys = s.ikeKeys
		s.ikeInit = *outcome.NewIKEInit
		s.ikeKeys = outcome.NewIKEInit.Keys
		s.result.IKEEstablished = true
		s.result.Ready = s.result.IPsecEstablished
		s.result.Reason = "peer ike sa rekeyed"
		if s.ikeRekeyState != nil {
			s.ikeRekeyState.RecordRekey(now)
		}
	}
	return nil
}

func (s *PacketSession) defaultHandlePeerIKERequest(_ context.Context, raw []byte) (PeerIKERequestOutcome, error) {
	s.mu.Lock()
	init := s.ikeInit
	keys := s.ikeKeys
	var prevInit *ikev2.InitResult
	if s.prevIKEInit != nil {
		cp := *s.prevIKEInit
		prevInit = &cp
	}
	prevKeys := s.prevIKEKeys
	child := s.trackedChild
	rekeyInFlight := s.rekeyInFlight > 0
	random := s.random
	s.mu.Unlock()
	return processPeerIKERequest(raw, init, keys, prevInit, prevKeys, child, rekeyInFlight, random)
}

func processPeerInformationalRequest(raw []byte, init ikev2.InitResult, keys ikev2.IKEKeys, child ikev2.ChildSAResult, random io.Reader) (PeerIKERequestOutcome, error) {
	hdr, err := ikev2.ParseHeader(raw)
	if err != nil {
		return PeerIKERequestOutcome{}, err
	}
	if hdr.Flags&ikev2.FlagResponse != 0 {
		return PeerIKERequestOutcome{}, fmt.Errorf("%w: unexpected response flag", ikev2.ErrInvalidInformational)
	}
	if hdr.ExchangeType != ikev2.ExchangeINFORMATIONAL {
		return PeerIKERequestOutcome{}, fmt.Errorf("%w: unsupported peer exchange %d", ikev2.ErrInvalidInformational, hdr.ExchangeType)
	}
	return processPeerIKERequest(raw, init, keys, nil, ikev2.IKEKeys{}, child, false, random)
}

func processPeerIKERequest(raw []byte, init ikev2.InitResult, keys ikev2.IKEKeys, prevInit *ikev2.InitResult, prevKeys ikev2.IKEKeys, child ikev2.ChildSAResult, rekeyInFlight bool, random io.Reader) (PeerIKERequestOutcome, error) {
	hdr, err := ikev2.ParseHeader(raw)
	if err != nil {
		return PeerIKERequestOutcome{}, err
	}
	if hdr.Flags&ikev2.FlagResponse != 0 {
		return PeerIKERequestOutcome{}, fmt.Errorf("%w: unexpected response flag", ikev2.ErrInvalidInformational)
	}
	targetInit := init
	targetKeys := keys
	onSupersededIKESA := false
	if hdr.InitiatorSPI != init.InitiatorSPI || hdr.ResponderSPI != init.ResponderSPI {
		if prevInit != nil && hdr.InitiatorSPI == prevInit.InitiatorSPI && hdr.ResponderSPI == prevInit.ResponderSPI {
			targetInit = *prevInit
			targetKeys = prevKeys
			onSupersededIKESA = true
		} else {
			return PeerIKERequestOutcome{}, fmt.Errorf("%w: peer request SPI mismatch", ikev2.ErrInvalidInformational)
		}
	}

	switch hdr.ExchangeType {
	case ikev2.ExchangeINFORMATIONAL:
		peerFromInitiator := targetInit.LocalIsResponder
		_, content, err := ikev2.ParseInformationalRequestContentFrom(raw, targetInit, targetKeys, hdr.MessageID, peerFromInitiator)
		if err != nil {
			return PeerIKERequestOutcome{}, err
		}
		plan, err := ikev2.PlanInformationalRecovery(content, child)
		if err != nil {
			return PeerIKERequestOutcome{}, err
		}
		var iv []byte
		if targetKeys.Profile.EncryptionID != ikev2.ENCR_AES_GCM_16 {
			iv, err = ikev2.RandomIV(randomWithCryptoFallback(random), targetKeys.Profile)
			if err != nil {
				return PeerIKERequestOutcome{}, err
			}
		}
		_, respBytes, err := ikev2.BuildInformationalResponseFrom(targetInit, targetKeys, hdr.MessageID, !peerFromInitiator, plan.Response.Payloads, iv)
		if err != nil {
			return PeerIKERequestOutcome{}, err
		}
		var closeReason string
		switch {
		case plan.DeleteIKE && !onSupersededIKESA:
			closeReason = "peer deleted ike sa"
		case plan.DeleteCurrentChild:
			closeReason = "peer deleted child sa"
		}
		return PeerIKERequestOutcome{
			Response:    respBytes,
			CloseReason: closeReason,
		}, nil

	case ikev2.ExchangeCREATE_CHILD_SA:
		var activeChildren []ikev2.ChildSAResult
		if hasChildSA(child) {
			activeChildren = []ikev2.ChildSAResult{child}
		}
		res, err := ikev2.HandleResponderCreateChildSA(ikev2.ResponderCreateChildConfig{
			RawRequest:     raw,
			Init:           targetInit,
			Keys:           targetKeys,
			ActiveChildren: activeChildren,
			RekeyInFlight:  rekeyInFlight || onSupersededIKESA,
			Random:         randomWithCryptoFallback(random),
		})
		if err != nil {
			return PeerIKERequestOutcome{}, err
		}
		return PeerIKERequestOutcome{
			Response:   res.ResponseBytes,
			NewChildSA: res.ChildSA,
			NewIKEInit: res.NewInit,
		}, nil

	default:
		return PeerIKERequestOutcome{}, fmt.Errorf("%w: unsupported peer exchange %d", ikev2.ErrInvalidInformational, hdr.ExchangeType)
	}
}

func randomWithCryptoFallback(r io.Reader) io.Reader {
	if r == nil {
		return rand.Reader
	}
	return &cryptoFallbackReader{primary: r}
}

type cryptoFallbackReader struct {
	primary io.Reader
}

func (r *cryptoFallbackReader) Read(p []byte) (int, error) {
	if r != nil && r.primary != nil {
		n, err := r.primary.Read(p)
		if n == len(p) {
			return n, nil
		}
		if err == nil && n > 0 {
			rest, fillErr := io.ReadFull(rand.Reader, p[n:])
			return n + rest, fillErr
		}
	}
	return rand.Reader.Read(p)
}

func (s *PacketSession) handlePeerDelete(reason string) {
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
	transport := s.transport
	s.mu.Unlock()

	if maintCancel != nil {
		maintCancel()
	}
	if closer, ok := transport.(ESPPacketTransportCloser); ok {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = closer.Close(cleanupCtx)
		cancel()
	}
}

func (s *PacketSession) maintenanceLoop(ctx context.Context, interval time.Duration) {
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

func (s *PacketSession) SetMTU(mtu int) {
	if s == nil || mtu <= 0 {
		return
	}
	s.mu.Lock()
	s.mtu = mtu
	s.mu.Unlock()
}

func (s *PacketSession) EffectiveMTU() int {
	if s == nil {
		return DefaultTunnelInnerMTU
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.effectiveMTULocked()
}

func (s *PacketSession) effectiveMTULocked() int {
	if s.mtu > 0 {
		if resultHasInnerIPv6(s.result) && s.mtu < MinIPv6TunnelInnerMTU {
			return MinIPv6TunnelInnerMTU
		}
		if s.mtu < 576 {
			return 576
		}
		return s.mtu
	}
	return effectiveSessionMTU(0, TunnelConfig{}, s.result)
}

func (s *PacketSession) hasBackgroundMaintenance() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maintCancel != nil
}

func (s *PacketSession) proxyRouteIPs() []net.IP {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	transport := s.transport
	s.mu.Unlock()
	if provider, ok := transport.(proxyRouteIPProvider); ok {
		return provider.proxyRouteIPs()
	}
	return nil
}

func NextHeaderForInnerPacket(packet []byte) (uint8, error) {
	if len(packet) == 0 {
		return 0, fmt.Errorf("%w: packet is empty", ErrUnsupportedInnerPacket)
	}
	switch packet[0] >> 4 {
	case 4:
		return esp.NextHeaderIPv4, nil
	case 6:
		return esp.NextHeaderIPv6, nil
	default:
		return 0, fmt.Errorf("%w: ip version %d", ErrUnsupportedInnerPacket, packet[0]>>4)
	}
}

func (s *PacketSession) Result() TunnelResult {
	if s == nil {
		return TunnelResult{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneTunnelResult(s.result)
}

func (s *PacketSession) RekeyChildSA(ctx context.Context) (TunnelResult, error) {
	return s.rekeyChildSA(ctx, time.Time{})
}

func (s *PacketSession) rekeyChildSA(ctx context.Context, rekeyedAt time.Time) (TunnelResult, error) {
	if s == nil {
		return TunnelResult{}, ErrInvalidPacketTunnel
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
	if !closed && handler != nil {
		s.rekeyInFlight++
	}
	s.mu.Unlock()
	if closed {
		return TunnelResult{}, ErrPacketTunnelClosed
	}
	if handler == nil {
		return TunnelResult{}, fmt.Errorf("%w: child sa rekey handler is nil", ErrInvalidPacketTunnel)
	}
	defer func() {
		s.mu.Lock()
		s.rekeyInFlight--
		s.mu.Unlock()
	}()
	child, err := handler(ctx)
	if err != nil {
		return TunnelResult{}, err
	}
	outbound, inbound, err := packetSAs(PacketSessionConfig{ChildSA: child})
	if err != nil {
		return TunnelResult{}, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return TunnelResult{}, ErrPacketTunnelClosed
	}
	oldInbound := s.inbound
	var oldLocalSPI []byte
	if oldInbound != nil && oldInbound.SPI != 0 {
		var spiBuf [4]byte
		binary.BigEndian.PutUint32(spiBuf[:], oldInbound.SPI)
		oldLocalSPI = spiBuf[:]
	}
	gracePeriod := s.rekeyGracePeriod
	if gracePeriod <= 0 {
		gracePeriod = defaultChildSARekeyGracePeriod
	}
	if oldInbound != nil && oldInbound.SPI != inbound.SPI {
		s.prevInbound = oldInbound
		s.prevInboundUntil = time.Now().Add(gracePeriod)
	}
	deleteHandler := s.childSADeleteHandler
	s.outbound = outbound
	s.inbound = inbound
	s.trackedChild = child
	s.result.IKEEstablished = true
	s.result.IPsecEstablished = true
	s.result.Ready = true
	s.result.ChildSAIdentifier = childSAIdentifier(child)
	s.result.Reason = "child sa rekeyed"
	if s.rekeyState != nil {
		s.rekeyState.RecordRekey(rekeyedAt)
	}
	v4 := childConfigurationAddress(child, ikev2.ConfigInternalIPv4Address)
	v6 := childConfigurationAddress(child, ikev2.ConfigInternalIPv6Address)
	if v4 != "" {
		s.result.LocalInnerIPv4 = v4
	}
	if v6 != "" {
		s.result.LocalInnerIPv6 = v6
	}
	if v4 != "" || v6 != "" {
		s.result.LocalInnerIPs = mergeInnerIPStrings(s.result.LocalInnerIPv4, s.result.LocalInnerIPv6, childConfigurationIPStrings(child, ikev2.ConfigInternalIPv4Address), childConfigurationIPStrings(child, ikev2.ConfigInternalIPv6Address))
	}
	if local := firstPacketNonEmpty(v4, v6); local != "" {
		s.result.LocalInnerIP = local
	}
	if dns := childConfigurationDNS(child); len(dns) > 0 {
		s.result.DNSServers = dns
	}
	updatedResult := cloneTunnelResult(s.result)
	s.mu.Unlock()

	if deleteHandler != nil && len(oldLocalSPI) == 4 {
		_ = deleteHandler(ctx, oldLocalSPI)
	}
	return updatedResult, nil
}

func (s *PacketSession) AdvanceChildSARekey(ctx context.Context, now time.Time) (ChildSARekeyDecision, error) {
	if s == nil {
		return ChildSARekeyDecision{}, ErrInvalidPacketTunnel
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
	seqExhausting := s.outbound != nil && s.outbound.Sequence >= espSequenceRekeyThreshold && s.rekeyHandler != nil
	var decision ChildSARekeyDecision
	if s.rekeyState != nil {
		decision = s.rekeyState.Advance(now)
	} else {
		decision = ChildSARekeyDecision{Action: ChildSARekeyNoAction, Reason: "rekey disabled"}
	}
	if seqExhausting && decision.Action != ChildSARekeyDue {
		if now.IsZero() {
			now = time.Now()
		}
		decision.Action = ChildSARekeyDue
		decision.DueAt = now
		decision.Reason = "esp sequence number approaching exhaustion"
	}
	s.mu.Unlock()
	if decision.Action != ChildSARekeyDue {
		return decision, nil
	}
	_, err := s.rekeyChildSA(ctx, now)
	return decision, err
}

func (s *PacketSession) RunChildSARekeyDue(ctx context.Context, now time.Time) (ChildSARekeyDecision, error) {
	decision, err := s.AdvanceChildSARekey(ctx, now)
	if err != nil || decision.Action != ChildSARekeyDue {
		return decision, err
	}
	if nextDue, ok := s.NextChildSARekeyDue(); ok {
		decision.NextDue = nextDue
	}
	return decision, nil
}

func (s *PacketSession) NextChildSARekeyDue() (time.Time, bool) {
	if s == nil {
		return time.Time{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return time.Time{}, false
	}
	if s.outbound != nil && s.outbound.Sequence >= espSequenceRekeyThreshold && s.rekeyHandler != nil {
		return time.Now(), true
	}
	if s.rekeyState == nil {
		return time.Time{}, false
	}
	return s.rekeyState.NextDue()
}

func (s *PacketSession) ChildSARekeySnapshot() ChildSARekeySnapshot {
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

func (s *PacketSession) RekeyIKESA(ctx context.Context) (TunnelResult, error) {
	return s.rekeyIKESA(ctx, time.Time{})
}

func (s *PacketSession) rekeyIKESA(ctx context.Context, rekeyedAt time.Time) (TunnelResult, error) {
	if s == nil {
		return TunnelResult{}, ErrInvalidPacketTunnel
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
	if !closed && handler != nil {
		s.rekeyInFlight++
	}
	s.mu.Unlock()
	if closed {
		return TunnelResult{}, ErrPacketTunnelClosed
	}
	if handler == nil {
		return TunnelResult{}, fmt.Errorf("%w: ike sa rekey handler is nil", ErrInvalidPacketTunnel)
	}
	defer func() {
		s.mu.Lock()
		s.rekeyInFlight--
		s.mu.Unlock()
	}()
	newInit, err := handler(ctx)
	if err != nil {
		return TunnelResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return TunnelResult{}, ErrPacketTunnelClosed
	}
	prevCopy := s.ikeInit
	s.prevIKEInit = &prevCopy
	s.prevIKEKeys = s.ikeKeys
	s.ikeInit = newInit
	s.ikeKeys = newInit.Keys
	s.result.IKEEstablished = true
	s.result.Ready = s.result.IPsecEstablished
	s.result.Reason = "ike sa rekeyed"
	if s.ikeRekeyState != nil {
		s.ikeRekeyState.RecordRekey(rekeyedAt)
	}
	return cloneTunnelResult(s.result), nil
}

func (s *PacketSession) AdvanceIKESARekey(ctx context.Context, now time.Time) (ChildSARekeyDecision, error) {
	if s == nil {
		return ChildSARekeyDecision{}, ErrInvalidPacketTunnel
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

func (s *PacketSession) RunIKESARekeyDue(ctx context.Context, now time.Time) (ChildSARekeyDecision, error) {
	decision, err := s.AdvanceIKESARekey(ctx, now)
	if err != nil || decision.Action != ChildSARekeyDue {
		return decision, err
	}
	if s.ikeRekeyState != nil {
		s.mu.Lock()
		if nextDue, ok := s.ikeRekeyState.NextDue(); ok {
			decision.NextDue = nextDue
		}
		s.mu.Unlock()
	}
	return decision, nil
}

func (s *PacketSession) MOBIKE(ctx context.Context, req MOBIKERequest) (MOBIKEResult, error) {
	if s == nil {
		return MOBIKEResult{}, ErrInvalidPacketTunnel
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
	result := s.result
	s.mu.Unlock()
	if closed {
		return MOBIKEResult{}, ErrPacketTunnelClosed
	}
	if handler != nil {
		res, err := handler(ctx, req)
		if err != nil {
			return MOBIKEResult{}, err
		}
		res = completeMOBIKEResult(res, req, result, "mobike updated")
		s.applyMOBIKEResult(res)
		return res, nil
	}
	return MOBIKEResult{
		Rekeyed:          false,
		OuterLocalIP:     firstPacketNonEmpty(req.NewIP, req.OldIP, result.EPDGAddress),
		LocalInnerIP:     result.LocalInnerIP,
		RemoteInnerIP:    result.RemoteInnerIP,
		DNSServers:       append([]string(nil), result.DNSServers...),
		IKEEstablished:   result.IKEEstablished,
		IPsecEstablished: result.IPsecEstablished,
		Reason:           "mobike unsupported",
		UpdatedAt:        time.Now(),
	}, nil
}

func (s *PacketSession) ObserveMOBIKENAT(ctx context.Context, obs MOBIKENATObservation) (MOBIKENATChange, MOBIKEResult, error) {
	if s == nil {
		return MOBIKENATChange{}, MOBIKEResult{}, ErrInvalidPacketTunnel
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		return MOBIKENATChange{}, MOBIKEResult{}, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return MOBIKENATChange{}, MOBIKEResult{}, ErrPacketTunnelClosed
	}
	if s.mobikeNAT == nil {
		s.mobikeNAT = NewMOBIKENATState(MOBIKENATStateConfig{MOBIKESupported: s.result.MOBIKESupported})
	}
	change := s.mobikeNAT.Observe(obs)
	s.mu.Unlock()
	if !change.RequiresMOBIKEUpdate {
		return change, MOBIKEResult{}, nil
	}
	res, err := s.MOBIKE(ctx, change.Request)
	return change, res, err
}

func (s *PacketSession) MOBIKENATSnapshot() (MOBIKENATEndpoint, time.Time) {
	if s == nil {
		return MOBIKENATEndpoint{}, time.Time{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mobikeNAT == nil {
		return MOBIKENATEndpoint{}, time.Time{}
	}
	return s.mobikeNAT.Snapshot()
}

func (s *PacketSession) AdvanceIKELiveness(ctx context.Context, now time.Time) (IKELivenessDecision, error) {
	if s == nil {
		return IKELivenessDecision{}, ErrInvalidPacketTunnel
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
		establishedAt := s.result.EstablishedAt
		liveness, err := NewIKELivenessState(cfg, establishedAt)
		if err != nil {
			s.mu.Unlock()
			return IKELivenessDecision{}, err
		}
		s.liveness = liveness
	}
	decision := s.liveness.Advance(now)
	transport := s.transport
	dpdHandler := s.dpdHandler
	s.mu.Unlock()
	switch decision.Action {
	case IKELivenessSendKeepalive:
		sender, ok := transport.(NATTKeepaliveSender)
		if !ok {
			return decision, fmt.Errorf("%w: transport cannot send NAT-T keepalive", ErrInvalidPacketTunnel)
		}
		if err := sender.SendNATTKeepalive(ctx); err != nil {
			return decision, err
		}
	case IKELivenessSendDPD:
		if dpdHandler == nil {
			return decision, fmt.Errorf("%w: DPD handler is nil", ErrInvalidPacketTunnel)
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

func (s *PacketSession) RecordIKELivenessInbound(at time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.liveness != nil {
		s.liveness.RecordInbound(at)
	}
}

func (s *PacketSession) RecordIKELivenessOutbound(at time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.liveness != nil {
		s.liveness.RecordOutbound(at)
	}
}

func (s *PacketSession) RecordIKELivenessResult(at time.Time, ok bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.liveness != nil {
		s.liveness.RecordLivenessResult(at, ok)
	}
}

func (s *PacketSession) IKELivenessSnapshot() IKELivenessSnapshot {
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

func (s *PacketSession) markTunnelNotReady(reason string) {
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

func ikeLivenessDeadReason(decision IKELivenessDecision) string {
	reason := firstPacketNonEmpty(decision.Reason, "dpd timeout")
	if strings.Contains(strings.ToLower(reason), "ike liveness") {
		return reason
	}
	return "ike liveness dead: " + reason
}

func completeMOBIKEResult(res MOBIKEResult, req MOBIKERequest, current TunnelResult, fallbackReason string) MOBIKEResult {
	if res.OuterLocalIP == "" {
		res.OuterLocalIP = firstPacketNonEmpty(req.NewIP, req.OldIP, current.EPDGAddress)
	}
	if res.LocalInnerIP == "" {
		res.LocalInnerIP = current.LocalInnerIP
	}
	if res.RemoteInnerIP == "" {
		res.RemoteInnerIP = current.RemoteInnerIP
	}
	if len(res.DNSServers) == 0 {
		res.DNSServers = append([]string(nil), current.DNSServers...)
	} else {
		res.DNSServers = append([]string(nil), res.DNSServers...)
	}
	if !res.IKEEstablished {
		res.IKEEstablished = current.IKEEstablished
	}
	if !res.IPsecEstablished {
		res.IPsecEstablished = current.IPsecEstablished
	}
	if res.Reason == "" {
		res.Reason = fallbackReason
	}
	if res.UpdatedAt.IsZero() {
		res.UpdatedAt = time.Now()
	}
	return res
}

func (s *PacketSession) applyMOBIKEResult(res MOBIKEResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
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

func (s *PacketSession) Close(ctx context.Context) error {
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
	feedbackWake := s.feedbackWake
	maintCancel := s.maintCancel
	maintDone := s.maintDone
	ikeReqCancel := s.ikeReqCancel
	ikeReqDone := s.ikeReqDone
	handler := s.closeHandler
	transport := s.transport
	s.mu.Unlock()
	if feedbackWake != nil {
		feedbackWake()
	}
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
	closeCtx := ctx
	var cancel context.CancelFunc
	if closeCtx.Err() != nil {
		closeCtx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
	}
	var err error
	if handler != nil {
		err = handler(closeCtx)
	}
	if closer, ok := transport.(ESPPacketTransportCloser); ok {
		if closeErr := closer.Close(closeCtx); err == nil {
			err = closeErr
		}
	}
	return err
}

func (s *PacketSession) SendInnerPacket(ctx context.Context, inner []byte) error {
	nextHeader, err := NextHeaderForInnerPacket(inner)
	if err != nil {
		if s != nil {
			s.recordOutboundError(true)
		}
		return err
	}
	return s.SendInnerPacketWithNextHeader(ctx, nextHeader, inner)
}

func (s *PacketSession) SendInnerPacketWithNextHeader(ctx context.Context, nextHeader uint8, inner []byte) error {
	if s == nil {
		return ErrInvalidPacketTunnel
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		s.recordOutboundError(false)
		return err
	}
	innerCopy := append([]byte(nil), inner...)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrPacketTunnelClosed
	}
	if s.outbound == nil || s.transport == nil {
		s.stats.OutboundErrors++
		s.mu.Unlock()
		return fmt.Errorf("%w: outbound sa or transport is nil", ErrInvalidPacketTunnel)
	}
	parsed, err := parseAndValidateInnerIPPacket(nextHeader, innerCopy)
	if err != nil {
		s.stats.OutboundErrors++
		s.stats.UnsupportedDrops++
		s.mu.Unlock()
		return err
	}
	if err := matchPacketAgainstChildTS(parsed, s.trackedChild.TSi, s.trackedChild.TSr); err != nil {
		s.stats.OutboundErrors++
		s.stats.UnsupportedDrops++
		s.mu.Unlock()
		return err
	}
	mtu := s.effectiveMTULocked()
	trimmed := parsed.trimmed
	if nextHeader == esp.NextHeaderIPv4 && len(trimmed) > mtu && trimmed[6]&0x40 != 0 {
		if icmpPkt := synthesizeICMPv4PacketTooBig(trimmed, mtu, s.result.RemoteInnerIP); len(icmpPkt) > 0 {
			s.enqueueFeedbackLocked(PacketTunnelPacket{
				NextHeader: esp.NextHeaderIPv4,
				Payload:    icmpPkt,
			})
		}
		s.stats.OutboundErrors++
		s.mu.Unlock()
		return syscall.EMSGSIZE
	}
	if nextHeader == esp.NextHeaderIPv6 && len(trimmed) > mtu {
		if icmp6Pkt := synthesizeICMPv6PacketTooBig(trimmed, mtu); len(icmp6Pkt) > 0 {
			s.enqueueFeedbackLocked(PacketTunnelPacket{
				NextHeader: esp.NextHeaderIPv6,
				Payload:    icmp6Pkt,
			})
		}
		s.stats.OutboundErrors++
		s.mu.Unlock()
		return syscall.EMSGSIZE
	}
	trimmed = clampInnerPacketTCPMSS(trimmed, mtu)
	packet, err := s.outbound.Seal(nextHeader, trimmed, esp.SealOptions{Random: s.random})
	transport := s.transport
	remoteInnerIP := s.result.RemoteInnerIP
	if err != nil {
		s.stats.OutboundErrors++
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	if err := transport.SendESPPacket(ctx, packet); err != nil {
		if errors.Is(err, syscall.EMSGSIZE) {
			fallbackMTU := clampFallbackMTU(len(trimmed)-80, nextHeader == esp.NextHeaderIPv6)
			s.mu.Lock()
			if !s.closed {
				if fallbackMTU < s.effectiveMTULocked() {
					s.mtu = fallbackMTU
				}
				switch nextHeader {
				case esp.NextHeaderIPv4:
					if trimmed[6]&0x40 != 0 {
						if icmpPkt := synthesizeICMPv4PacketTooBig(trimmed, fallbackMTU, remoteInnerIP); len(icmpPkt) > 0 {
							s.enqueueFeedbackLocked(PacketTunnelPacket{NextHeader: esp.NextHeaderIPv4, Payload: icmpPkt})
						}
					}
				case esp.NextHeaderIPv6:
					if icmp6Pkt := synthesizeICMPv6PacketTooBig(trimmed, fallbackMTU); len(icmp6Pkt) > 0 {
						s.enqueueFeedbackLocked(PacketTunnelPacket{NextHeader: esp.NextHeaderIPv6, Payload: icmp6Pkt})
					}
				}
			}
			s.stats.OutboundErrors++
			s.mu.Unlock()
			return err
		}
		s.recordOutboundError(false)
		return err
	}
	s.mu.Lock()
	s.stats.OutboundInnerPackets++
	s.stats.OutboundInnerBytes += uint64(len(trimmed))
	s.stats.OutboundESPPackets++
	s.stats.OutboundESPBytes += uint64(len(packet))
	if s.liveness != nil {
		s.liveness.RecordOutbound(time.Now())
	}
	s.mu.Unlock()
	return nil
}

func (s *PacketSession) enqueueFeedbackLocked(pkt PacketTunnelPacket) {
	if s.feedbackCh == nil {
		return
	}
	select {
	case s.feedbackCh <- pkt:
	default:
		select {
		case <-s.feedbackCh:
		default:
		}
		select {
		case s.feedbackCh <- pkt:
		default:
		}
	}
	if s.feedbackWake != nil {
		s.feedbackWake()
	}
}

func (s *PacketSession) ReceiveESPPacket(ctx context.Context, packet []byte) (PacketTunnelPacket, error) {
	if s == nil {
		return PacketTunnelPacket{}, ErrInvalidPacketTunnel
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		s.recordInboundError(err)
		return PacketTunnelPacket{}, err
	}
	packetCopy := append([]byte(nil), packet...)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return PacketTunnelPacket{}, ErrPacketTunnelClosed
	}
	if s.inbound == nil {
		s.stats.InboundErrors++
		return PacketTunnelPacket{}, fmt.Errorf("%w: inbound sa is nil", ErrInvalidPacketTunnel)
	}
	out, err := s.inbound.Open(packetCopy)
	if err != nil && s.prevInbound != nil {
		if !s.prevInboundUntil.IsZero() && !time.Now().Before(s.prevInboundUntil) {
			s.prevInbound = nil
			s.prevInboundUntil = time.Time{}
		} else if prevOut, prevErr := s.prevInbound.Open(packetCopy); prevErr == nil {
			out = prevOut
			err = nil
		}
	}
	if err != nil {
		s.recordInboundErrorLocked(err)
		return PacketTunnelPacket{}, err
	}
	// RFC 4303 §2.6 Traffic Flow Confidentiality dummy packet (IPPROTO_NONE = 59).
	if out.NextHeader == esp.NextHeaderNoNext {
		s.stats.InboundESPPackets++
		s.stats.InboundESPBytes += uint64(len(packetCopy))
		if s.liveness != nil {
			s.liveness.RecordInbound(time.Now())
		}
		return PacketTunnelPacket{
			SPI:        out.SPI,
			Sequence:   out.Sequence,
			NextHeader: out.NextHeader,
		}, nil
	}
	parsed, err := parseAndValidateInnerIPPacket(out.NextHeader, out.Payload)
	if err != nil {
		s.recordInboundErrorLocked(err)
		return PacketTunnelPacket{}, err
	}
	if err := matchPacketAgainstChildTS(parsed, s.trackedChild.TSr, s.trackedChild.TSi); err != nil {
		s.recordInboundErrorLocked(err)
		return PacketTunnelPacket{}, err
	}
	payload := clampInnerPacketTCPMSS(parsed.trimmed, s.effectiveMTULocked())
	s.stats.InboundInnerPackets++
	s.stats.InboundInnerBytes += uint64(len(payload))
	s.stats.InboundESPPackets++
	s.stats.InboundESPBytes += uint64(len(packetCopy))
	if s.liveness != nil {
		s.liveness.RecordInbound(time.Now())
	}
	return PacketTunnelPacket{
		SPI:        out.SPI,
		Sequence:   out.Sequence,
		NextHeader: out.NextHeader,
		Payload:    payload,
	}, nil
}

func (s *PacketSession) ReadInnerPacket(ctx context.Context) (PacketTunnelPacket, error) {
	if s == nil {
		return PacketTunnelPacket{}, ErrInvalidPacketTunnel
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if err := contextReady(ctx); err != nil {
			s.recordInboundError(err)
			return PacketTunnelPacket{}, err
		}
		if s.feedbackCh != nil {
			select {
			case fb := <-s.feedbackCh:
				return fb, nil
			default:
			}
		}
		readCtx, cancelRead := context.WithCancel(ctx)
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			cancelRead()
			return PacketTunnelPacket{}, ErrPacketTunnelClosed
		}
		if s.feedbackCh != nil && len(s.feedbackCh) > 0 {
			s.mu.Unlock()
			cancelRead()
			select {
			case fb := <-s.feedbackCh:
				return fb, nil
			default:
			}
			continue
		}
		receiver, ok := s.transport.(ESPPacketReceiver)
		if ok {
			s.feedbackWake = cancelRead
		}
		s.mu.Unlock()
		if !ok {
			cancelRead()
			err := fmt.Errorf("%w: transport cannot read ESP packets", ErrInvalidPacketTunnel)
			s.recordInboundError(err)
			return PacketTunnelPacket{}, err
		}
		packet, err := receiver.ReadESPPacket(readCtx)
		s.mu.Lock()
		s.feedbackWake = nil
		s.mu.Unlock()
		cancelRead()
		if err != nil {
			if ctx.Err() == nil && s.feedbackCh != nil {
				select {
				case fb := <-s.feedbackCh:
					return fb, nil
				default:
				}
			}
			s.recordInboundError(err)
			return PacketTunnelPacket{}, err
		}
		decoded, err := s.ReceiveESPPacket(ctx, packet)
		if err != nil {
			return PacketTunnelPacket{}, err
		}
		if decoded.NextHeader == esp.NextHeaderNoNext {
			continue
		}
		return decoded, nil
	}
}

func (s *PacketSession) PacketStats() PacketTunnelStats {
	if s == nil {
		return PacketTunnelStats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

func validateInnerPacketNextHeader(nextHeader uint8, packet []byte) error {
	detected, err := NextHeaderForInnerPacket(packet)
	if err != nil {
		return err
	}
	if detected != nextHeader {
		return fmt.Errorf("%w: next header %d does not match inner packet", ErrUnsupportedInnerPacket, nextHeader)
	}
	return nil
}

func (s *PacketSession) recordOutboundError(unsupported bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.OutboundErrors++
	if unsupported {
		s.stats.UnsupportedDrops++
	}
}

func (s *PacketSession) recordInboundError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recordInboundErrorLocked(err)
}

func (s *PacketSession) recordInboundErrorLocked(err error) {
	s.stats.InboundErrors++
	switch {
	case errors.Is(err, esp.ErrReplay):
		s.stats.ReplayDrops++
	case errors.Is(err, esp.ErrInvalidPacket):
		s.stats.InvalidDrops++
	case errors.Is(err, ErrUnsupportedInnerPacket):
		s.stats.UnsupportedDrops++
	}
}

func packetSAs(cfg PacketSessionConfig) (*esp.SA, *esp.SA, error) {
	outbound := cfg.OutboundSA
	inbound := cfg.InboundSA
	if outbound == nil || inbound == nil {
		if !hasChildSA(cfg.ChildSA) {
			return nil, nil, fmt.Errorf("%w: child sa is empty", ErrInvalidPacketTunnel)
		}
		if outbound == nil {
			var err error
			outbound, err = esp.NewOutboundSAFromChild(cfg.ChildSA)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: outbound: %v", ErrInvalidPacketTunnel, err)
			}
		}
		if inbound == nil {
			var err error
			inbound, err = esp.NewInboundSAFromChild(cfg.ChildSA)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: inbound: %v", ErrInvalidPacketTunnel, err)
			}
		}
	}
	outbound, err := cloneSA(outbound)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: outbound: %v", ErrInvalidPacketTunnel, err)
	}
	inbound, err = cloneSA(inbound)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: inbound: %v", ErrInvalidPacketTunnel, err)
	}
	return outbound, inbound, nil
}

func hasChildSA(child ikev2.ChildSAResult) bool {
	return len(child.LocalSPI) > 0 || len(child.RemoteSPI) > 0 ||
		len(child.Keys.Outbound.EncryptionKey) > 0 || len(child.Keys.Inbound.EncryptionKey) > 0
}

func cloneSA(sa *esp.SA) (*esp.SA, error) {
	if sa == nil {
		return nil, ErrInvalidPacketTunnel
	}
	cp := *sa
	cp.EncryptionKey = append([]byte(nil), sa.EncryptionKey...)
	cp.IntegrityKey = append([]byte(nil), sa.IntegrityKey...)
	return esp.NewSA(cp)
}

func contextReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func firstPacketNonEmpty(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}

type parsedInnerIPPacket struct {
	version  uint8
	srcIP    net.IP
	dstIP    net.IP
	proto    uint8
	srcPort  uint16
	dstPort  uint16
	hasPorts bool
	trimmed  []byte
}

func parseAndValidateInnerIPPacket(nextHeader uint8, packet []byte) (parsedInnerIPPacket, error) {
	if err := validateInnerPacketNextHeader(nextHeader, packet); err != nil {
		return parsedInnerIPPacket{}, err
	}
	switch nextHeader {
	case esp.NextHeaderIPv4:
		if len(packet) < 20 {
			return parsedInnerIPPacket{}, fmt.Errorf("%w: ipv4 packet shorter than 20 bytes (%d)", ErrUnsupportedInnerPacket, len(packet))
		}
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || ihl > len(packet) {
			return parsedInnerIPPacket{}, fmt.Errorf("%w: invalid ipv4 header length %d", ErrUnsupportedInnerPacket, ihl)
		}
		totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
		if totalLen < ihl || totalLen > len(packet) {
			return parsedInnerIPPacket{}, fmt.Errorf("%w: invalid ipv4 total length %d (len %d)", ErrUnsupportedInnerPacket, totalLen, len(packet))
		}
		if !ipv4HeaderChecksumValid(packet[:ihl]) {
			return parsedInnerIPPacket{}, fmt.Errorf("%w: invalid ipv4 header checksum", ErrUnsupportedInnerPacket)
		}
		trimmed := append([]byte(nil), packet[:totalLen]...)
		fragWord := binary.BigEndian.Uint16(trimmed[6:8])
		fragOffset := fragWord & 0x1fff
		moreFrags := fragWord&0x2000 != 0
		proto := trimmed[9]
		upper := trimmed[ihl:]
		var srcPort, dstPort uint16
		hasPorts := false
		if fragOffset == 0 {
			if !moreFrags {
				if proto == 6 && len(upper) < 20 {
					return parsedInnerIPPacket{}, fmt.Errorf("%w: truncated ipv4 tcp header (%d)", ErrUnsupportedInnerPacket, len(upper))
				}
				if proto == 17 && len(upper) < 8 {
					return parsedInnerIPPacket{}, fmt.Errorf("%w: truncated ipv4 udp header (%d)", ErrUnsupportedInnerPacket, len(upper))
				}
			}
			if protocolUsesL4Ports(proto) && len(upper) >= 4 {
				srcPort = binary.BigEndian.Uint16(upper[0:2])
				dstPort = binary.BigEndian.Uint16(upper[2:4])
				hasPorts = true
			}
		}
		return parsedInnerIPPacket{
			version:  4,
			srcIP:    append(net.IP(nil), trimmed[12:16]...),
			dstIP:    append(net.IP(nil), trimmed[16:20]...),
			proto:    proto,
			srcPort:  srcPort,
			dstPort:  dstPort,
			hasPorts: hasPorts,
			trimmed:  trimmed,
		}, nil

	case esp.NextHeaderIPv6:
		if len(packet) < 40 {
			return parsedInnerIPPacket{}, fmt.Errorf("%w: ipv6 packet shorter than 40 bytes (%d)", ErrUnsupportedInnerPacket, len(packet))
		}
		payLen := int(binary.BigEndian.Uint16(packet[4:6]))
		if 40+payLen > len(packet) {
			return parsedInnerIPPacket{}, fmt.Errorf("%w: invalid ipv6 payload length %d (len %d)", ErrUnsupportedInnerPacket, payLen, len(packet))
		}
		trimmed := append([]byte(nil), packet[:40+payLen]...)
		proto, upperOffset, isNonFirstFrag, moreFrags, ok := walkIPv6ExtensionHeaders(trimmed)
		if !ok {
			return parsedInnerIPPacket{}, fmt.Errorf("%w: malformed ipv6 extension header chain", ErrUnsupportedInnerPacket)
		}
		upper := trimmed[upperOffset:]
		var srcPort, dstPort uint16
		hasPorts := false
		if !isNonFirstFrag {
			if !moreFrags {
				if proto == 6 && len(upper) < 20 {
					return parsedInnerIPPacket{}, fmt.Errorf("%w: truncated ipv6 tcp header (%d)", ErrUnsupportedInnerPacket, len(upper))
				}
				if proto == 17 && len(upper) < 8 {
					return parsedInnerIPPacket{}, fmt.Errorf("%w: truncated ipv6 udp header (%d)", ErrUnsupportedInnerPacket, len(upper))
				}
			}
			if protocolUsesL4Ports(proto) && len(upper) >= 4 {
				srcPort = binary.BigEndian.Uint16(upper[0:2])
				dstPort = binary.BigEndian.Uint16(upper[2:4])
				hasPorts = true
			}
		}
		return parsedInnerIPPacket{
			version:  6,
			srcIP:    append(net.IP(nil), trimmed[8:24]...),
			dstIP:    append(net.IP(nil), trimmed[24:40]...),
			proto:    proto,
			srcPort:  srcPort,
			dstPort:  dstPort,
			hasPorts: hasPorts,
			trimmed:  trimmed,
		}, nil

	default:
		return parsedInnerIPPacket{}, fmt.Errorf("%w: unsupported next header %d", ErrUnsupportedInnerPacket, nextHeader)
	}
}

func walkIPv6ExtensionHeaders(packet []byte) (proto uint8, offset int, isNonFirstFrag bool, moreFrags bool, ok bool) {
	if len(packet) < 40 {
		return 0, 0, false, false, false
	}
	next := packet[6]
	off := 40
	for steps := 0; steps < 8; steps++ {
		switch next {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			if off+2 > len(packet) {
				return 0, 0, false, false, false
			}
			extLen := (int(packet[off+1]) + 1) * 8
			if extLen <= 0 || off+extLen > len(packet) {
				return 0, 0, false, false, false
			}
			next = packet[off]
			off += extLen
		case 44: // Fragment header (8 bytes)
			if off+8 > len(packet) {
				return 0, 0, false, false, false
			}
			fragField := binary.BigEndian.Uint16(packet[off+2 : off+4])
			if fragField&0xfff8 != 0 {
				isNonFirstFrag = true
			}
			if fragField&0x0001 != 0 {
				moreFrags = true
			}
			next = packet[off]
			off += 8
			if isNonFirstFrag {
				return next, off, true, moreFrags, true
			}
		default:
			return next, off, isNonFirstFrag, moreFrags, true
		}
	}
	return next, off, isNonFirstFrag, moreFrags, true
}

func protocolUsesL4Ports(proto uint8) bool {
	return proto == 6 || proto == 17 || proto == 132 || proto == 136
}

func matchPacketAgainstChildTS(pkt parsedInnerIPPacket, srcSelectors, dstSelectors ikev2.TrafficSelectors) error {
	if len(srcSelectors.Selectors) > 0 && !endpointMatchesSelectors(pkt.srcIP, pkt.proto, pkt.srcPort, pkt.hasPorts, srcSelectors.Selectors) {
		return fmt.Errorf("%w: inner source %s (proto=%d port=%d) outside traffic selectors", ErrUnsupportedInnerPacket, pkt.srcIP, pkt.proto, pkt.srcPort)
	}
	if len(dstSelectors.Selectors) > 0 && !endpointMatchesSelectors(pkt.dstIP, pkt.proto, pkt.dstPort, pkt.hasPorts, dstSelectors.Selectors) {
		return fmt.Errorf("%w: inner destination %s (proto=%d port=%d) outside traffic selectors", ErrUnsupportedInnerPacket, pkt.dstIP, pkt.proto, pkt.dstPort)
	}
	return nil
}

func endpointMatchesSelectors(ip net.IP, proto uint8, port uint16, hasPorts bool, selectors []ikev2.TrafficSelector) bool {
	for _, ts := range selectors {
		if ts.IPProtocol != 0 && ts.IPProtocol != proto {
			continue
		}
		switch ts.Type {
		case ikev2.TSIPv4AddressRange:
			ip4 := ip.To4()
			start4 := ts.StartAddr.To4()
			end4 := ts.EndAddr.To4()
			if ip4 == nil || start4 == nil || end4 == nil {
				continue
			}
			if bytes.Compare(ip4, start4) < 0 || bytes.Compare(ip4, end4) > 0 {
				continue
			}
		case ikev2.TSIPv6AddressRange:
			if ip.To4() != nil {
				continue
			}
			ip16 := ip.To16()
			start16 := ts.StartAddr.To16()
			end16 := ts.EndAddr.To16()
			if ip16 == nil || start16 == nil || end16 == nil || ts.StartAddr.To4() != nil || ts.EndAddr.To4() != nil {
				continue
			}
			if bytes.Compare(ip16, start16) < 0 || bytes.Compare(ip16, end16) > 0 {
				continue
			}
		default:
			continue
		}
		if !portMatchesSelector(ts, port, hasPorts) {
			continue
		}
		return true
	}
	return false
}

func portMatchesSelector(ts ikev2.TrafficSelector, port uint16, hasPorts bool) bool {
	endPort := ts.EndPort
	if ts.IPProtocol == 0 && ts.StartPort == 0 && ts.EndPort == 0 {
		endPort = 65535
	}
	// RFC 7296 §3.13.1: StartPort=0, EndPort=65535 matches ANY port/protocol.
	if ts.StartPort == 0 && endPort == 65535 {
		return true
	}
	// RFC 7296 §3.13.1: StartPort=65535, EndPort=0 is OPAQUE (matches only when ports are unavailable).
	if ts.StartPort == 65535 && ts.EndPort == 0 {
		return !hasPorts
	}
	if !hasPorts {
		return false
	}
	return port >= ts.StartPort && port <= endPort
}

func ipv4HeaderChecksumValid(hdr []byte) bool {
	if len(hdr) < 20 || len(hdr)%4 != 0 {
		return false
	}
	// Accept all-zero checksum field? No: RFC 791 §3.1 mandates IPv4 header checksum!
	// Sum all 16-bit words; valid header folds to 0xffff.
	var sum uint32
	for i := 0; i < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum) == 0xffff
}

func computeOnesComplementChecksum(chunks ...[]byte) uint16 {
	var sum uint32
	var carryByte byte
	hasCarryByte := false
	for _, chunk := range chunks {
		i := 0
		if hasCarryByte && len(chunk) > 0 {
			sum += uint32(carryByte)<<8 | uint32(chunk[0])
			hasCarryByte = false
			i = 1
		}
		for ; i+1 < len(chunk); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(chunk[i : i+2]))
		}
		if i < len(chunk) {
			carryByte = chunk[i]
			hasCarryByte = true
		}
	}
	if hasCarryByte {
		sum += uint32(carryByte) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func rfc1624Update16(oldCsum, oldWord, newWord uint16) uint16 {
	sum := uint32(^oldCsum) + uint32(^oldWord) + uint32(newWord)
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func clampInnerPacketTCPMSS(packet []byte, mtu int) []byte {
	if len(packet) < 40 || mtu <= 0 {
		return packet
	}
	var tcpOffset, totalLen, maxMSS int
	switch packet[0] >> 4 {
	case 4:
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || len(packet) < ihl+20 {
			return packet
		}
		totalLen = int(binary.BigEndian.Uint16(packet[2:4]))
		if totalLen < ihl+20 || totalLen > len(packet) {
			return packet
		}
		if binary.BigEndian.Uint16(packet[6:8])&0x1fff != 0 || packet[9] != 6 {
			return packet
		}
		tcpOffset = ihl
		maxMSS = mtu - ihl - 20
		if maxMSS < 536 {
			maxMSS = 536
		}
	case 6:
		payLen := int(binary.BigEndian.Uint16(packet[4:6]))
		if 40+payLen > len(packet) {
			return packet
		}
		totalLen = 40 + payLen
		proto, off, isNonFirstFrag, _, ok := walkIPv6ExtensionHeaders(packet[:totalLen])
		if !ok || isNonFirstFrag || proto != 6 || totalLen < off+20 {
			return packet
		}
		tcpOffset = off
		maxMSS = mtu - tcpOffset - 20
		if maxMSS < 536 {
			maxMSS = 536
		}
	default:
		return packet
	}

	tcp := packet[tcpOffset:totalLen]
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 24 || dataOff > len(tcp) {
		return packet
	}
	flags := tcp[13]
	if flags&0x02 == 0 || flags&0x04 != 0 { // require SYN=1 and RST=0
		return packet
	}

	var out []byte
	opts := tcp[20:dataOff]
	for i := 0; i < len(opts); {
		kind := opts[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		optLen := int(opts[i+1])
		if optLen < 2 || i+optLen > len(opts) {
			break
		}
		if kind == 2 && optLen == 4 {
			curMSS := int(binary.BigEndian.Uint16(opts[i+2 : i+4]))
			if curMSS > maxMSS {
				if out == nil {
					out = append([]byte(nil), packet...)
					tcp = out[tcpOffset:totalLen]
					opts = tcp[20:dataOff]
				}
				pos := 20 + i + 2
				evenStart := pos &^ 1
				oldW0 := binary.BigEndian.Uint16(tcp[evenStart : evenStart+2])
				hasW1 := pos%2 == 1 && evenStart+4 <= len(tcp)
				var oldW1 uint16
				if hasW1 {
					oldW1 = binary.BigEndian.Uint16(tcp[evenStart+2 : evenStart+4])
				}
				binary.BigEndian.PutUint16(tcp[pos:pos+2], uint16(maxMSS))
				csum := binary.BigEndian.Uint16(tcp[16:18])
				newW0 := binary.BigEndian.Uint16(tcp[evenStart : evenStart+2])
				csum = rfc1624Update16(csum, oldW0, newW0)
				if hasW1 {
					newW1 := binary.BigEndian.Uint16(tcp[evenStart+2 : evenStart+4])
					csum = rfc1624Update16(csum, oldW1, newW1)
				}
				binary.BigEndian.PutUint16(tcp[16:18], csum)
			}
		}
		i += optLen
	}
	if out != nil {
		return out
	}
	return packet
}

func clampFallbackMTU(candidate int, ipv6 bool) int {
	if ipv6 {
		if candidate < MinIPv6TunnelInnerMTU {
			return MinIPv6TunnelInnerMTU
		}
		return candidate
	}
	if candidate < 576 {
		return 576
	}
	return candidate
}

func synthesizeICMPv4PacketTooBig(offending []byte, nextHopMTU int, routerHint string) []byte {
	if len(offending) < 20 || offending[0]>>4 != 4 {
		return nil
	}
	ihl := int(offending[0]&0x0f) * 4
	if ihl < 20 || len(offending) < ihl {
		return nil
	}
	// Never send ICMP error in response to non-first fragments, multicast/broadcast, or ICMP error messages.
	if binary.BigEndian.Uint16(offending[6:8])&0x1fff != 0 {
		return nil
	}
	srcIP := net.IP(offending[12:16]).To4()
	dstIP := net.IP(offending[16:20]).To4()
	if srcIP == nil || dstIP == nil || srcIP.IsUnspecified() || srcIP.IsMulticast() || dstIP.IsMulticast() || srcIP.Equal(net.IPv4bcast) {
		return nil
	}
	if offending[9] == 1 && len(offending) > ihl {
		icmpType := offending[ihl]
		if icmpType != 8 && icmpType != 0 && icmpType != 13 && icmpType != 14 {
			return nil
		}
	}
	if nextHopMTU < 68 {
		nextHopMTU = 576
	}
	routerIP := net.IPv4(169, 254, 0, 1).To4()
	if hint := net.ParseIP(strings.TrimSpace(routerHint)); hint != nil {
		if h4 := hint.To4(); h4 != nil && !h4.IsUnspecified() && !h4.IsMulticast() {
			routerIP = h4
		}
	}
	if routerIP.Equal(srcIP) {
		routerIP = net.IPv4(169, 254, 0, 2).To4()
	}

	maxQuoted := 576 - 20 - 8
	quoted := offending
	if len(quoted) > maxQuoted {
		quoted = quoted[:maxQuoted]
	}
	totalLen := 20 + 8 + len(quoted)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	pkt[1] = 0xc0
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 1 // ICMPv4
	copy(pkt[12:16], routerIP)
	copy(pkt[16:20], srcIP)
	binary.BigEndian.PutUint16(pkt[10:12], computeOnesComplementChecksum(pkt[:20]))

	icmp := pkt[20:]
	icmp[0] = 3 // Destination Unreachable
	icmp[1] = 4 // Fragmentation Needed and DF Set
	binary.BigEndian.PutUint16(icmp[6:8], uint16(nextHopMTU))
	copy(icmp[8:], quoted)
	binary.BigEndian.PutUint16(icmp[2:4], computeOnesComplementChecksum(icmp))
	return pkt
}

func synthesizeICMPv6PacketTooBig(offending []byte, mtu int) []byte {
	if len(offending) < 40 || offending[0]>>4 != 6 {
		return nil
	}
	srcIP := net.IP(offending[8:24]).To16()
	if srcIP == nil || srcIP.IsUnspecified() || srcIP.IsMulticast() {
		return nil
	}
	proto, off, isNonFirstFrag, _, ok := walkIPv6ExtensionHeaders(offending)
	if !ok || isNonFirstFrag {
		return nil
	}
	// RFC 4443 §2.4(e): never send ICMPv6 error in response to an ICMPv6 error (< 128) or redirect (137).
	if proto == 58 && off < len(offending) {
		icmp6Type := offending[off]
		if icmp6Type < 128 || icmp6Type == 137 {
			return nil
		}
	}
	if mtu < MinIPv6TunnelInnerMTU {
		mtu = MinIPv6TunnelInnerMTU
	}
	routerIP := net.ParseIP("fe80::1").To16()
	if routerIP.Equal(srcIP) {
		routerIP = net.ParseIP("fe80::2").To16()
	}

	maxQuoted := MinIPv6TunnelInnerMTU - 40 - 8
	quoted := offending
	if len(quoted) > maxQuoted {
		quoted = quoted[:maxQuoted]
	}
	icmpLen := 8 + len(quoted)
	pkt := make([]byte, 40+icmpLen)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(icmpLen))
	pkt[6] = 58 // ICMPv6
	pkt[7] = 64
	copy(pkt[8:24], routerIP)
	copy(pkt[24:40], srcIP)

	icmp6 := pkt[40:]
	icmp6[0] = 2 // Packet Too Big
	icmp6[1] = 0
	binary.BigEndian.PutUint32(icmp6[4:8], uint32(mtu))
	copy(icmp6[8:], quoted)

	var pseudo [40]byte
	copy(pseudo[0:16], routerIP)
	copy(pseudo[16:32], srcIP)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(icmpLen))
	pseudo[39] = 58
	binary.BigEndian.PutUint16(icmp6[2:4], computeOnesComplementChecksum(pseudo[:], icmp6))
	return pkt
}
