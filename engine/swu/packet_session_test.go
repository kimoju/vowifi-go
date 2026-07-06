package swu

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/boa-z/vowifi-go/engine/swu/esp"
	"github.com/boa-z/vowifi-go/engine/swu/ikev2"
)

func TestPacketSessionSendsAndReceivesIPv4AndIPv6(t *testing.T) {
	aToB := &captureESPPacketTransport{}
	a, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: aToB,
		Result:    TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true},
	})
	if err != nil {
		t.Fatalf("NewPacketSession(a) error = %v", err)
	}
	b, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(false),
		Transport: &captureESPPacketTransport{},
		Result:    TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true},
	})
	if err != nil {
		t.Fatalf("NewPacketSession(b) error = %v", err)
	}

	ipv4 := []byte{0x45, 0x00, 0x00, 0x14, 0xaa, 0xbb, 0xcc, 0xdd}
	if err := a.SendInnerPacket(context.Background(), ipv4); err != nil {
		t.Fatalf("SendInnerPacket(ipv4) error = %v", err)
	}
	if len(aToB.packets) != 1 {
		t.Fatalf("captured packets=%d, want 1", len(aToB.packets))
	}
	got4, err := b.ReceiveESPPacket(context.Background(), aToB.packets[0])
	if err != nil {
		t.Fatalf("ReceiveESPPacket(ipv4) error = %v", err)
	}
	if got4.NextHeader != esp.NextHeaderIPv4 || !bytes.Equal(got4.Payload, ipv4) || got4.Sequence != 1 {
		t.Fatalf("got4=%+v payload=%x", got4, got4.Payload)
	}

	ipv6 := []byte{0x60, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef}
	if err := a.SendInnerPacket(context.Background(), ipv6); err != nil {
		t.Fatalf("SendInnerPacket(ipv6) error = %v", err)
	}
	got6, err := b.ReceiveESPPacket(context.Background(), aToB.packets[1])
	if err != nil {
		t.Fatalf("ReceiveESPPacket(ipv6) error = %v", err)
	}
	if got6.NextHeader != esp.NextHeaderIPv6 || !bytes.Equal(got6.Payload, ipv6) || got6.Sequence != 2 {
		t.Fatalf("got6=%+v payload=%x", got6, got6.Payload)
	}

	outStats := a.PacketStats()
	if outStats.OutboundInnerPackets != 2 || outStats.OutboundInnerBytes != uint64(len(ipv4)+len(ipv6)) || outStats.OutboundESPPackets != 2 {
		t.Fatalf("out stats=%+v", outStats)
	}
	inStats := b.PacketStats()
	if inStats.InboundInnerPackets != 2 || inStats.InboundInnerBytes != uint64(len(ipv4)+len(ipv6)) || inStats.InboundESPPackets != 2 {
		t.Fatalf("in stats=%+v", inStats)
	}
}

func TestPacketSessionDefaultResultIsReady(t *testing.T) {
	session, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(true), Transport: &captureESPPacketTransport{}})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	result := session.Result()
	if !result.IsReady() || result.Mode != DataplaneModeUserspace || result.Reason == "" {
		t.Fatalf("result=%+v", result)
	}
}

func TestPacketSessionResultClonesDNSServers(t *testing.T) {
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: &captureESPPacketTransport{},
		Result: TunnelResult{
			Ready:            true,
			IKEEstablished:   true,
			IPsecEstablished: true,
			DNSServers:       []string{"10.0.0.1"},
		},
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	result := session.Result()
	result.DNSServers[0] = "198.51.100.53"
	if got := session.Result().DNSServers[0]; got != "10.0.0.1" {
		t.Fatalf("Result() DNS=%q, want original", got)
	}
}

func TestPacketSessionReadInnerPacketUsesReadableTransport(t *testing.T) {
	wire := &captureESPPacketTransport{}
	a, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(true), Transport: wire})
	if err != nil {
		t.Fatalf("NewPacketSession(a) error = %v", err)
	}
	b, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(false), Transport: wire})
	if err != nil {
		t.Fatalf("NewPacketSession(b) error = %v", err)
	}
	inner := []byte{0x45, 0x00, 0x00, 0x14, 0xde, 0xad}
	if err := a.SendInnerPacket(context.Background(), inner); err != nil {
		t.Fatalf("SendInnerPacket() error = %v", err)
	}
	got, err := b.ReadInnerPacket(context.Background())
	if err != nil {
		t.Fatalf("ReadInnerPacket() error = %v", err)
	}
	if got.NextHeader != esp.NextHeaderIPv4 || !bytes.Equal(got.Payload, inner) {
		t.Fatalf("got=%+v payload=%x", got, got.Payload)
	}
	stats := b.PacketStats()
	if stats.InboundInnerPackets != 1 || stats.InboundESPPackets != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestPacketSessionRejectsReplayAndCountsDrop(t *testing.T) {
	transport := &captureESPPacketTransport{}
	a, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(true), Transport: transport})
	if err != nil {
		t.Fatalf("NewPacketSession(a) error = %v", err)
	}
	b, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(false), Transport: &captureESPPacketTransport{}})
	if err != nil {
		t.Fatalf("NewPacketSession(b) error = %v", err)
	}
	if err := a.SendInnerPacket(context.Background(), []byte{0x45, 0x00, 0x00, 0x14}); err != nil {
		t.Fatalf("SendInnerPacket() error = %v", err)
	}
	if _, err := b.ReceiveESPPacket(context.Background(), transport.packets[0]); err != nil {
		t.Fatalf("ReceiveESPPacket(first) error = %v", err)
	}
	if _, err := b.ReceiveESPPacket(context.Background(), transport.packets[0]); !errors.Is(err, esp.ErrReplay) {
		t.Fatalf("ReceiveESPPacket(replay) err=%v, want ErrReplay", err)
	}
	stats := b.PacketStats()
	if stats.InboundErrors != 1 || stats.ReplayDrops != 1 || stats.InvalidDrops != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestPacketSessionCloseRejectsTrafficAndClosesTransport(t *testing.T) {
	transport := &captureESPPacketTransport{}
	session, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(true), Transport: transport})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !transport.closed {
		t.Fatalf("transport was not closed")
	}
	if err := session.SendInnerPacket(context.Background(), []byte{0x45, 0x00}); !errors.Is(err, ErrPacketTunnelClosed) {
		t.Fatalf("SendInnerPacket() err=%v, want ErrPacketTunnelClosed", err)
	}
	if _, err := session.ReceiveESPPacket(context.Background(), []byte{1, 2, 3}); !errors.Is(err, ErrPacketTunnelClosed) {
		t.Fatalf("ReceiveESPPacket() err=%v, want ErrPacketTunnelClosed", err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close(second) error = %v", err)
	}
}

func TestPacketSessionCountsUnsupportedInnerPacket(t *testing.T) {
	session, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(true), Transport: &captureESPPacketTransport{}})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	if err := session.SendInnerPacket(context.Background(), []byte{0x10, 0x00}); !errors.Is(err, ErrUnsupportedInnerPacket) {
		t.Fatalf("SendInnerPacket() err=%v, want ErrUnsupportedInnerPacket", err)
	}
	stats := session.PacketStats()
	if stats.OutboundErrors != 1 || stats.UnsupportedDrops != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestPacketSessionRejectsOutboundNextHeaderMismatchAndCountsDrop(t *testing.T) {
	transport := &captureESPPacketTransport{}
	session, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(true), Transport: transport})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	if err := session.SendInnerPacketWithNextHeader(context.Background(), esp.NextHeaderIPv6, []byte{0x45, 0x00}); !errors.Is(err, ErrUnsupportedInnerPacket) {
		t.Fatalf("SendInnerPacketWithNextHeader() err=%v, want ErrUnsupportedInnerPacket", err)
	}
	if len(transport.packets) != 0 {
		t.Fatalf("captured packets=%d, want 0", len(transport.packets))
	}
	stats := session.PacketStats()
	if stats.OutboundErrors != 1 || stats.UnsupportedDrops != 1 || stats.OutboundESPPackets != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestPacketSessionRejectsInboundNextHeaderMismatchAndCountsDrop(t *testing.T) {
	sealer, err := esp.NewOutboundSAFromChild(packetChildSA(true))
	if err != nil {
		t.Fatalf("NewOutboundSAFromChild() error = %v", err)
	}
	packet, err := sealer.Seal(esp.NextHeaderIPv6, []byte{0x45, 0x00, 0x00, 0x14}, esp.SealOptions{
		Sequence: 1,
		IV:       bytes.Repeat([]byte{0x77}, 16),
	})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	session, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(false), Transport: &captureESPPacketTransport{}})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	if _, err := session.ReceiveESPPacket(context.Background(), packet); !errors.Is(err, ErrUnsupportedInnerPacket) {
		t.Fatalf("ReceiveESPPacket() err=%v, want ErrUnsupportedInnerPacket", err)
	}
	stats := session.PacketStats()
	if stats.InboundErrors != 1 || stats.UnsupportedDrops != 1 || stats.InboundInnerPackets != 0 || stats.InboundESPPackets != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestPacketSessionCountsTransportFailure(t *testing.T) {
	wantErr := errors.New("send failed")
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA: packetChildSA(true),
		Transport: ESPPacketTransportFunc(func(context.Context, []byte) error {
			return wantErr
		}),
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	if err := session.SendInnerPacket(context.Background(), []byte{0x45, 0x00, 0x00, 0x14}); !errors.Is(err, wantErr) {
		t.Fatalf("SendInnerPacket() err=%v, want send failed", err)
	}
	stats := session.PacketStats()
	if stats.OutboundErrors != 1 || stats.OutboundInnerPackets != 0 || stats.OutboundESPPackets != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestPacketSessionObserveMOBIKENATTriggersMOBIKE(t *testing.T) {
	start := time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)
	var requests []MOBIKERequest
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: &captureESPPacketTransport{},
		Result: TunnelResult{
			Ready:            true,
			IKEEstablished:   true,
			IPsecEstablished: true,
			MOBIKESupported:  true,
			LocalInnerIP:     "10.0.0.2",
			RemoteInnerIP:    "0.0.0.0/0",
			DNSServers:       []string{"10.0.0.1"},
		},
		MOBIKENAT: NewMOBIKENATState(MOBIKENATStateConfig{
			MOBIKESupported: true,
			LocalIP:         net.IPv4(192, 0, 2, 10),
			RemoteIP:        net.IPv4(198, 51, 100, 7),
			LocalPort:       4500,
			RemotePort:      4500,
			NATDetected:     true,
			UpdatedAt:       start,
		}),
		MOBIKEHandler: func(ctx context.Context, req MOBIKERequest) (MOBIKEResult, error) {
			requests = append(requests, req)
			return MOBIKEResult{
				IKEEstablished:   true,
				IPsecEstablished: true,
				LocalInnerIP:     "10.0.0.2",
				RemoteInnerIP:    "0.0.0.0/0",
				DNSServers:       []string{"10.0.0.1"},
				Reason:           "mobike updated from observation",
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}

	change, result, err := session.ObserveMOBIKENAT(context.Background(), MOBIKENATObservation{
		DeviceID:         "dev-1",
		TraceID:          "trace-1",
		LocalIP:          net.IPv4(192, 0, 2, 20),
		RemoteIP:         net.IPv4(198, 51, 100, 7),
		LocalPort:        4500,
		RemotePort:       4500,
		NATDetected:      true,
		NATDetectedKnown: true,
		At:               start.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("ObserveMOBIKENAT() error = %v", err)
	}
	if !change.Changed || !change.RequiresMOBIKEUpdate || !change.LocalAddressChanged || change.RemoteAddressChanged {
		t.Fatalf("change=%+v", change)
	}
	if len(requests) != 1 || requests[0].DeviceID != "dev-1" || requests[0].OldIP != "192.0.2.10" || requests[0].NewIP != "192.0.2.20" {
		t.Fatalf("MOBIKE requests=%+v", requests)
	}
	if result.Reason != "mobike updated from observation" || session.Result().Reason != "mobike updated from observation" {
		t.Fatalf("MOBIKE result=%+v session=%+v", result, session.Result())
	}
	endpoint, updatedAt := session.MOBIKENATSnapshot()
	if !endpoint.LocalIP.Equal(net.IPv4(192, 0, 2, 20)) || !updatedAt.Equal(start.Add(time.Minute)) {
		t.Fatalf("snapshot endpoint=%+v updatedAt=%v", endpoint, updatedAt)
	}

	change, result, err = session.ObserveMOBIKENAT(context.Background(), MOBIKENATObservation{
		DeviceID:         "dev-1",
		TraceID:          "trace-1",
		LocalIP:          net.IPv4(192, 0, 2, 20),
		RemoteIP:         net.IPv4(198, 51, 100, 7),
		LocalPort:        4500,
		RemotePort:       4500,
		NATDetected:      true,
		NATDetectedKnown: true,
		At:               start.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("ObserveMOBIKENAT(unchanged) error = %v", err)
	}
	if change.Changed || result.Reason != "" || len(requests) != 1 {
		t.Fatalf("unchanged change=%+v result=%+v requests=%+v", change, result, requests)
	}
}

type captureESPPacketTransport struct {
	packets [][]byte
	closed  bool
}

func (t *captureESPPacketTransport) SendESPPacket(ctx context.Context, packet []byte) error {
	t.packets = append(t.packets, append([]byte(nil), packet...))
	return nil
}

func (t *captureESPPacketTransport) ReadESPPacket(ctx context.Context) ([]byte, error) {
	if len(t.packets) == 0 {
		return nil, errors.New("no packets")
	}
	packet := append([]byte(nil), t.packets[0]...)
	t.packets = t.packets[1:]
	return packet, nil
}

func (t *captureESPPacketTransport) Close(ctx context.Context) error {
	t.closed = true
	return nil
}

func packetChildSA(aToB bool) ikev2.ChildSAResult {
	aOutbound := ikev2.ESPKeys{
		EncryptionKey: bytes.Repeat([]byte{0x10}, 16),
		IntegrityKey:  bytes.Repeat([]byte{0x20}, 32),
	}
	aInbound := ikev2.ESPKeys{
		EncryptionKey: bytes.Repeat([]byte{0x30}, 16),
		IntegrityKey:  bytes.Repeat([]byte{0x40}, 32),
	}
	child := ikev2.ChildSAResult{
		LocalSPI:  []byte{0x11, 0x11, 0x11, 0x11},
		RemoteSPI: []byte{0x22, 0x22, 0x22, 0x22},
		Keys: ikev2.ChildSAKeys{
			Profile:  ikev2.ESPKeyProfile{IntegrityID: ikev2.INTEG_HMAC_SHA2_256_128},
			Outbound: aOutbound,
			Inbound:  aInbound,
		},
	}
	if aToB {
		return child
	}
	child.LocalSPI = []byte{0x22, 0x22, 0x22, 0x22}
	child.RemoteSPI = []byte{0x11, 0x11, 0x11, 0x11}
	child.Keys.Outbound = aInbound
	child.Keys.Inbound = aOutbound
	return child
}
