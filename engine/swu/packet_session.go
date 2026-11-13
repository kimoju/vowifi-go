package swu

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
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
}

type PeerIKERequestHandler func(context.Context, []byte) (PeerIKERequestOutcome, error)

type PacketSessionConfig struct {
	Result                TunnelResult
	ChildSA               ikev2.ChildSAResult
	OutboundSA            *esp.SA
	InboundSA             *esp.SA
	Transport             ESPPacketTransport
	Random                io.Reader
	MOBIKEHandler         func(context.Context, MOBIKERequest) (MOBIKEResult, error)
	RekeyHandler          ChildSARekeyHandler
	ChildSADeleteHandler  func(context.Context, []byte) error
	PeerIKERequestHandler PeerIKERequestHandler
	IKEInit               ikev2.InitResult
	IKEKeys               ikev2.IKEKeys
	RekeyPolicy           ChildSARekeyPolicy
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
	random               io.Reader
	mobikeHandler        func(context.Context, MOBIKERequest) (MOBIKEResult, error)
	rekeyHandler         ChildSARekeyHandler
	childSADeleteHandler func(context.Context, []byte) error
	peerIKEHandler       PeerIKERequestHandler
	ikeInit              ikev2.InitResult
	ikeKeys              ikev2.IKEKeys
	trackedChild         ikev2.ChildSAResult
	rekeyState           *ChildSARekeyState
	mobikeNAT            *MOBIKENATState
	liveness             *IKELivenessState
	dpdHandler           func(context.Context) error
	closeHandler         func(context.Context) error
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
		random:               cfg.Random,
		mobikeHandler:        cfg.MOBIKEHandler,
		rekeyHandler:         cfg.RekeyHandler,
		childSADeleteHandler: cfg.ChildSADeleteHandler,
		peerIKEHandler:       cfg.PeerIKERequestHandler,
		ikeInit:              cfg.IKEInit,
		ikeKeys:              cfg.IKEKeys,
		trackedChild:         cfg.ChildSA,
		rekeyState:           rekeyState,
		mobikeNAT:            cfg.MOBIKENAT,
		liveness:             cfg.Liveness,
		dpdHandler:           cfg.DPDHandler,
		closeHandler:         cfg.CloseHandler,
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

func (s *PacketSession) defaultHandlePeerIKERequest(_ context.Context, raw []byte) (PeerIKERequestOutcome, error) {
	s.mu.Lock()
	init := s.ikeInit
	keys := s.ikeKeys
	child := s.trackedChild
	random := s.random
	s.mu.Unlock()
	return processPeerInformationalRequest(raw, init, keys, child, random)
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
	_, content, err := ikev2.ParseInformationalRequestContentFrom(raw, init, keys, hdr.MessageID, false)
	if err != nil {
		return PeerIKERequestOutcome{}, err
	}
	plan, err := ikev2.PlanInformationalRecovery(content, child)
	if err != nil {
		return PeerIKERequestOutcome{}, err
	}
	iv, err := ikev2.RandomIV(randomWithCryptoFallback(random), keys.Profile)
	if err != nil {
		return PeerIKERequestOutcome{}, err
	}
	_, respBytes, err := ikev2.BuildInformationalResponseFrom(init, keys, hdr.MessageID, true, plan.Response.Payloads, iv)
	if err != nil {
		return PeerIKERequestOutcome{}, err
	}
	var closeReason string
	switch {
	case plan.DeleteIKE:
		closeReason = "peer deleted ike sa"
	case plan.DeleteCurrentChild:
		closeReason = "peer deleted child sa"
	}
	return PeerIKERequestOutcome{
		Response:    respBytes,
		CloseReason: closeReason,
	}, nil
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
		}
	}
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
	s.mu.Unlock()
	if closed {
		return TunnelResult{}, ErrPacketTunnelClosed
	}
	if handler == nil {
		return TunnelResult{}, fmt.Errorf("%w: child sa rekey handler is nil", ErrInvalidPacketTunnel)
	}
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
	maintCancel := s.maintCancel
	maintDone := s.maintDone
	ikeReqCancel := s.ikeReqCancel
	ikeReqDone := s.ikeReqDone
	handler := s.closeHandler
	transport := s.transport
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
	if err := validateInnerPacketNextHeader(nextHeader, innerCopy); err != nil {
		s.stats.OutboundErrors++
		s.stats.UnsupportedDrops++
		s.mu.Unlock()
		return err
	}
	packet, err := s.outbound.Seal(nextHeader, innerCopy, esp.SealOptions{Random: s.random})
	transport := s.transport
	if err != nil {
		s.stats.OutboundErrors++
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	if err := transport.SendESPPacket(ctx, packet); err != nil {
		s.recordOutboundError(false)
		return err
	}
	s.mu.Lock()
	s.stats.OutboundInnerPackets++
	s.stats.OutboundInnerBytes += uint64(len(innerCopy))
	s.stats.OutboundESPPackets++
	s.stats.OutboundESPBytes += uint64(len(packet))
	if s.liveness != nil {
		s.liveness.RecordOutbound(time.Now())
	}
	s.mu.Unlock()
	return nil
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
	if err := validateInnerPacketNextHeader(out.NextHeader, out.Payload); err != nil {
		s.recordInboundErrorLocked(err)
		return PacketTunnelPacket{}, err
	}
	payload := append([]byte(nil), out.Payload...)
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
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return PacketTunnelPacket{}, ErrPacketTunnelClosed
		}
		receiver, ok := s.transport.(ESPPacketReceiver)
		s.mu.Unlock()
		if !ok {
			err := fmt.Errorf("%w: transport cannot read ESP packets", ErrInvalidPacketTunnel)
			s.recordInboundError(err)
			return PacketTunnelPacket{}, err
		}
		packet, err := receiver.ReadESPPacket(ctx)
		if err != nil {
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
