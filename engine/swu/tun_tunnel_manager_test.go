package swu

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
)

func TestTUNTunnelManagerStartsPumpAndCleansRouting(t *testing.T) {
	baseSession := newTUNManagerPacketSession(TunnelResult{
		Ready:             true,
		Mode:              DataplaneModeUserspace,
		EPDGAddress:       "epdg.example",
		LocalInnerIP:      "10.0.0.2",
		IKEEstablished:    true,
		IPsecEstablished:  true,
		ChildSAIdentifier: "11111111/22222222",
	})
	base := &tunManagerBase{session: baseSession}
	device := newTUNManagerDevice("vohive0")
	routing := &tunManagerRouting{}
	manager := NewTUNTunnelManager(TUNTunnelManagerConfig{
		Base:           base,
		RoutingManager: routing,
		DeviceFactory: func(ctx context.Context, cfg TunnelConfig, result TunnelResult) (InnerPacketDevice, string, error) {
			if result.LocalInnerIP != "10.0.0.2" {
				t.Fatalf("device factory result=%+v", result)
			}
			return device, "", nil
		},
		MTU:    1420,
		Routes: []TUNRoute{{Destination: "default", Table: "200"}},
		Rules:  []TUNRule{{Priority: 1000, From: "10.0.0.2", Table: "200"}},
	})

	session, err := manager.EstablishTunnel(context.Background(), TunnelConfig{
		DeviceID:    "dev-1",
		Mode:        DataplaneModeUserspace,
		EPDGAddress: "epdg.example",
		IMSI:        "310280233641503",
	})
	if err != nil {
		t.Fatalf("EstablishTunnel() error = %v", err)
	}
	result := session.Result()
	if !result.IsReady() || result.LocalInnerIP != "10.0.0.2" || result.ChildSAIdentifier == "" {
		t.Fatalf("result=%+v", result)
	}
	if len(routing.applies) != 1 {
		t.Fatalf("routing applies=%d, want 1", len(routing.applies))
	}
	applied := routing.applies[0]
	if applied.InterfaceName != "vohive0" || applied.MTU != 1420 || len(applied.Addresses) != 1 || applied.Addresses[0] != "10.0.0.2" {
		t.Fatalf("routing config=%+v", applied)
	}
	if len(applied.Routes) != 1 || applied.Routes[0].Destination != "default" || len(applied.Rules) != 1 {
		t.Fatalf("routing routes/rules=%+v/%+v", applied.Routes, applied.Rules)
	}

	outbound := []byte{0x45, 0, 0, 0x14, 0xaa}
	device.reads <- outbound
	if got := readPumpBytes(t, baseSession.sent); !bytes.Equal(got, outbound) {
		t.Fatalf("sent=%x, want %x", got, outbound)
	}
	inbound := []byte{0x60, 0, 0, 0, 0xbb}
	baseSession.reads <- PacketTunnelPacket{Payload: inbound}
	if got := readPumpBytes(t, device.writes); !bytes.Equal(got, inbound) {
		t.Fatalf("written=%x, want %x", got, inbound)
	}

	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !baseSession.isClosed() || !device.isClosed() {
		t.Fatalf("closed session=%t device=%t", baseSession.isClosed(), device.isClosed())
	}
	if len(routing.cleanups) != 1 || routing.cleanups[0].InterfaceName != "vohive0" {
		t.Fatalf("routing cleanups=%+v", routing.cleanups)
	}
}

func TestTUNTunnelManagerRejectsNonPacketSession(t *testing.T) {
	plain := &tunManagerPlainSession{result: TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true}}
	manager := NewTUNTunnelManager(TUNTunnelManagerConfig{
		Base: &tunManagerBase{session: plain},
	})
	_, err := manager.EstablishTunnel(context.Background(), TunnelConfig{
		DeviceID:    "dev-1",
		Mode:        DataplaneModeUserspace,
		EPDGAddress: "epdg.example",
		IMSI:        "310280233641503",
	})
	if !errors.Is(err, ErrInvalidTUNTunnelManager) {
		t.Fatalf("EstablishTunnel() err=%v, want ErrInvalidTUNTunnelManager", err)
	}
	if !plain.closed {
		t.Fatalf("plain base session was not closed")
	}
}

func TestTUNTunnelManagerRollsBackOnRoutingFailure(t *testing.T) {
	baseSession := newTUNManagerPacketSession(TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true})
	device := newTUNManagerDevice("vohive0")
	wantErr := errors.New("ip failed")
	manager := NewTUNTunnelManager(TUNTunnelManagerConfig{
		Base: &tunManagerBase{session: baseSession},
		DeviceFactory: func(ctx context.Context, cfg TunnelConfig, result TunnelResult) (InnerPacketDevice, string, error) {
			return device, "vohive0", nil
		},
		RoutingManager: &tunManagerRouting{applyErr: wantErr},
	})
	_, err := manager.EstablishTunnel(context.Background(), TunnelConfig{
		DeviceID:    "dev-1",
		Mode:        DataplaneModeUserspace,
		EPDGAddress: "epdg.example",
		IMSI:        "310280233641503",
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("EstablishTunnel() err=%v, want routing error", err)
	}
	if !baseSession.isClosed() || !device.isClosed() {
		t.Fatalf("rollback closed session=%t device=%t", baseSession.isClosed(), device.isClosed())
	}
}

type tunManagerBase struct {
	config  TunnelConfig
	session TunnelSession
	err     error
}

func (m *tunManagerBase) EstablishTunnel(ctx context.Context, cfg TunnelConfig) (TunnelSession, error) {
	m.config = cfg
	if m.err != nil {
		return nil, m.err
	}
	return m.session, nil
}

type tunManagerRouting struct {
	applies  []TUNRoutingConfig
	cleanups []TUNRoutingState
	applyErr error
}

func (r *tunManagerRouting) Apply(ctx context.Context, cfg TUNRoutingConfig) (TUNRoutingState, error) {
	r.applies = append(r.applies, cfg)
	if r.applyErr != nil {
		return TUNRoutingState{InterfaceName: cfg.InterfaceName}, r.applyErr
	}
	return TUNRoutingState{InterfaceName: cfg.InterfaceName}, nil
}

func (r *tunManagerRouting) Cleanup(ctx context.Context, state TUNRoutingState) error {
	r.cleanups = append(r.cleanups, state)
	return nil
}

type tunManagerDevice struct {
	name    string
	reads   chan []byte
	writes  chan []byte
	close   sync.Once
	closed  chan struct{}
	closeMu sync.Mutex
}

func newTUNManagerDevice(name string) *tunManagerDevice {
	return &tunManagerDevice{
		name:   name,
		reads:  make(chan []byte, 4),
		writes: make(chan []byte, 4),
		closed: make(chan struct{}),
	}
}

func (d *tunManagerDevice) Name() string { return d.name }

func (d *tunManagerDevice) ReadInnerPacket(ctx context.Context) ([]byte, error) {
	select {
	case packet := <-d.reads:
		return append([]byte(nil), packet...), nil
	case <-d.closed:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (d *tunManagerDevice) WriteInnerPacket(ctx context.Context, packet []byte) error {
	select {
	case d.writes <- append([]byte(nil), packet...):
		return nil
	case <-d.closed:
		return io.EOF
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *tunManagerDevice) Close(ctx context.Context) error {
	d.close.Do(func() { close(d.closed) })
	return nil
}

func (d *tunManagerDevice) isClosed() bool {
	select {
	case <-d.closed:
		return true
	default:
		return false
	}
}

type tunManagerPacketSession struct {
	result  TunnelResult
	sent    chan []byte
	reads   chan PacketTunnelPacket
	close   sync.Once
	closed  chan struct{}
	mobike  MOBIKEResult
	closeMu sync.Mutex
}

func newTUNManagerPacketSession(result TunnelResult) *tunManagerPacketSession {
	return &tunManagerPacketSession{
		result: result,
		sent:   make(chan []byte, 4),
		reads:  make(chan PacketTunnelPacket, 4),
		closed: make(chan struct{}),
		mobike: MOBIKEResult{
			IKEEstablished:   result.IKEEstablished,
			IPsecEstablished: result.IPsecEstablished,
			LocalInnerIP:     result.LocalInnerIP,
			RemoteInnerIP:    result.RemoteInnerIP,
		},
	}
}

func (s *tunManagerPacketSession) Result() TunnelResult { return s.result }

func (s *tunManagerPacketSession) MOBIKE(ctx context.Context, req MOBIKERequest) (MOBIKEResult, error) {
	return s.mobike, nil
}

func (s *tunManagerPacketSession) Close(ctx context.Context) error {
	s.close.Do(func() { close(s.closed) })
	return nil
}

func (s *tunManagerPacketSession) SendInnerPacket(ctx context.Context, packet []byte) error {
	select {
	case s.sent <- append([]byte(nil), packet...):
		return nil
	case <-s.closed:
		return ErrPacketTunnelClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *tunManagerPacketSession) SendInnerPacketWithNextHeader(ctx context.Context, nextHeader uint8, packet []byte) error {
	return s.SendInnerPacket(ctx, packet)
}

func (s *tunManagerPacketSession) ReceiveESPPacket(ctx context.Context, packet []byte) (PacketTunnelPacket, error) {
	return PacketTunnelPacket{Payload: append([]byte(nil), packet...)}, nil
}

func (s *tunManagerPacketSession) PacketStats() PacketTunnelStats {
	return PacketTunnelStats{}
}

func (s *tunManagerPacketSession) ReadInnerPacket(ctx context.Context) (PacketTunnelPacket, error) {
	select {
	case packet := <-s.reads:
		packet.Payload = append([]byte(nil), packet.Payload...)
		return packet, nil
	case <-s.closed:
		return PacketTunnelPacket{}, ErrPacketTunnelClosed
	case <-ctx.Done():
		return PacketTunnelPacket{}, ctx.Err()
	}
}

func (s *tunManagerPacketSession) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

type tunManagerPlainSession struct {
	result TunnelResult
	closed bool
}

func (s *tunManagerPlainSession) Result() TunnelResult { return s.result }

func (s *tunManagerPlainSession) MOBIKE(ctx context.Context, req MOBIKERequest) (MOBIKEResult, error) {
	return MOBIKEResult{}, nil
}

func (s *tunManagerPlainSession) Close(ctx context.Context) error {
	s.closed = true
	return nil
}
