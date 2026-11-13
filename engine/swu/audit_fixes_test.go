package swu

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kimoju/vowifi-go/engine/swu/eapaka"
	"github.com/kimoju/vowifi-go/engine/swu/esp"
	"github.com/kimoju/vowifi-go/engine/swu/ikev2"
)

func TestNonBlockingFDCloseWakesBlockedReadImmediately(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatalf("Pipe2 error = %v", err)
	}
	defer unix.Close(fds[1])
	if err := unix.SetNonblock(fds[0], true); err != nil {
		_ = unix.Close(fds[0])
		t.Fatalf("SetNonblock error = %v", err)
	}
	file := os.NewFile(uintptr(fds[0]), "test-nonblock-tun")
	dev := &TUNDevice{file: file, name: "tun-test0"}

	readDone := make(chan error, 1)
	go func() {
		_, err := dev.ReadInnerPacket(context.Background())
		readDone <- err
	}()
	time.Sleep(25 * time.Millisecond)
	start := time.Now()
	if err := dev.Close(context.Background()); err != nil {
		t.Fatalf("dev.Close error = %v", err)
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("expected ReadInnerPacket to return error on Close")
		}
		if time.Since(start) > 500*time.Millisecond {
			t.Fatalf("Close wakeup took too long: %v", time.Since(start))
		}
	case <-time.After(time.Second):
		t.Fatal("blocked ReadInnerPacket did not wake up on Close")
	}
}

type channelESPTransport struct {
	mu         sync.Mutex
	inboundCh  chan []byte
	outbound   [][]byte
	keepalives int
	closed     bool
}

func newChannelESPTransport() *channelESPTransport {
	return &channelESPTransport{inboundCh: make(chan []byte, 16)}
}

func (t *channelESPTransport) SendESPPacket(_ context.Context, pkt []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return net.ErrClosed
	}
	t.outbound = append(t.outbound, append([]byte(nil), pkt...))
	return nil
}

func (t *channelESPTransport) ReadESPPacket(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case pkt, ok := <-t.inboundCh:
		if !ok {
			return nil, net.ErrClosed
		}
		return pkt, nil
	}
}

func (t *channelESPTransport) SendNATTKeepalive(_ context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.keepalives++
	return nil
}

func (t *channelESPTransport) Close(context.Context) error {
	t.mu.Lock()
	if !t.closed {
		t.closed = true
		close(t.inboundCh)
	}
	t.mu.Unlock()
	return nil
}

func TestPacketSessionDropsTFCDummyRetainsPrevInboundAndSendsChildDelete(t *testing.T) {
	oldChild := packetChildSA(true)
	oldChild.LocalSPI = []byte{0x11, 0x22, 0x33, 0x44}
	oldChild.RemoteSPI = []byte{0x55, 0x66, 0x77, 0x88}

	newChild := packetChildSA(true)
	newChild.LocalSPI = []byte{0xaa, 0xbb, 0xcc, 0xdd}
	newChild.RemoteSPI = []byte{0xee, 0xff, 0x00, 0x11}

	peerOutboundOldChild := oldChild
	peerOutboundOldChild.RemoteSPI = append([]byte(nil), oldChild.LocalSPI...)
	peerOutboundOldChild.Keys.Outbound = oldChild.Keys.Inbound
	peerOutboundOld, err := esp.NewOutboundSAFromChild(peerOutboundOldChild)
	if err != nil {
		t.Fatalf("NewSA(peerOutboundOld) error = %v", err)
	}

	tr := newChannelESPTransport()
	var deletedSPIs [][]byte
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:          oldChild,
		Transport:        tr,
		Random:           rand.Reader,
		RekeyGracePeriod: 80 * time.Millisecond,
		RekeyHandler: func(context.Context) (ikev2.ChildSAResult, error) {
			return newChild, nil
		},
		ChildSADeleteHandler: func(_ context.Context, spi []byte) error {
			deletedSPIs = append(deletedSPIs, append([]byte(nil), spi...))
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	defer session.Close(context.Background())

	// 1. TFC dummy packet (NextHeader = 59) followed by real IPv4 packet.
	dummyESP, err := peerOutboundOld.Seal(esp.NextHeaderNoNext, []byte{0xde, 0xad, 0xbe, 0xef}, esp.SealOptions{Random: rand.Reader})
	if err != nil {
		t.Fatalf("Seal(dummy) error = %v", err)
	}
	realIPv4 := []byte{0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}
	realESP, err := peerOutboundOld.Seal(esp.NextHeaderIPv4, realIPv4, esp.SealOptions{Random: rand.Reader})
	if err != nil {
		t.Fatalf("Seal(real) error = %v", err)
	}
	tr.inboundCh <- dummyESP
	tr.inboundCh <- realESP

	got, err := session.ReadInnerPacket(context.Background())
	if err != nil {
		t.Fatalf("ReadInnerPacket() error = %v", err)
	}
	if got.NextHeader != esp.NextHeaderIPv4 || !bytes.Equal(got.Payload, realIPv4) {
		t.Fatalf("got inner packet = %+v", got)
	}
	stats := session.PacketStats()
	if stats.InboundErrors != 0 || stats.InboundESPPackets != 2 || stats.InboundInnerPackets != 1 {
		t.Fatalf("unexpected stats after TFC dummy: %+v", stats)
	}

	// 2. Rekey Child SA: sends DELETE for OldLocalSPI and keeps prevInbound during grace window.
	if _, err := session.RekeyChildSA(context.Background()); err != nil {
		t.Fatalf("RekeyChildSA() error = %v", err)
	}
	if len(deletedSPIs) != 1 || !bytes.Equal(deletedSPIs[0], oldChild.LocalSPI) {
		t.Fatalf("deletedSPIs = %x, want [%x]", deletedSPIs, oldChild.LocalSPI)
	}

	inFlightOldESP, err := peerOutboundOld.Seal(esp.NextHeaderIPv4, realIPv4, esp.SealOptions{Random: rand.Reader})
	if err != nil {
		t.Fatalf("Seal(inFlightOld) error = %v", err)
	}
	decodedGrace, err := session.ReceiveESPPacket(context.Background(), inFlightOldESP)
	if err != nil || !bytes.Equal(decodedGrace.Payload, realIPv4) {
		t.Fatalf("ReceiveESPPacket(during grace window) err=%v pkt=%+v", err, decodedGrace)
	}

	time.Sleep(100 * time.Millisecond)
	lateOldESP, err := peerOutboundOld.Seal(esp.NextHeaderIPv4, realIPv4, esp.SealOptions{Random: rand.Reader})
	if err != nil {
		t.Fatalf("Seal(lateOld) error = %v", err)
	}
	if _, err := session.ReceiveESPPacket(context.Background(), lateOldESP); err == nil {
		t.Fatal("expected packet on expired prevInbound SPI to be rejected after grace period")
	}

	// 3. Proactive sequence exhaustion rekey (>= 0xE0000000).
	session.mu.Lock()
	session.outbound.Sequence = espSequenceRekeyThreshold
	session.mu.Unlock()
	decision, err := session.RunChildSARekeyDue(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("RunChildSARekeyDue(seq threshold) error = %v", err)
	}
	if decision.Action != ChildSARekeyDue || len(deletedSPIs) != 2 {
		t.Fatalf("expected sequence-triggered rekey: decision=%+v deletes=%d", decision, len(deletedSPIs))
	}
}

type flakyPumpSession struct {
	PacketTunnelReadSession
	inStep  atomic.Int32
	outStep atomic.Int32
	inGood  chan PacketTunnelPacket
	outGood chan []byte
}

func (f *flakyPumpSession) ReadInnerPacket(ctx context.Context) (PacketTunnelPacket, error) {
	switch f.inStep.Add(1) {
	case 1:
		return PacketTunnelPacket{}, esp.ErrReplay
	case 2:
		return PacketTunnelPacket{}, esp.ErrInvalidPacket
	case 3:
		return PacketTunnelPacket{}, ErrUnsupportedInnerPacket
	case 4:
		return PacketTunnelPacket{}, syscall.EAGAIN
	default:
		select {
		case <-ctx.Done():
			return PacketTunnelPacket{}, ctx.Err()
		case pkt := <-f.inGood:
			return pkt, nil
		}
	}
}

func (f *flakyPumpSession) SendInnerPacket(ctx context.Context, payload []byte) error {
	switch f.outStep.Add(1) {
	case 1:
		return ErrUnsupportedInnerPacket
	case 2:
		return syscall.ENOBUFS
	case 3:
		return syscall.ECONNREFUSED
	default:
		select {
		case <-ctx.Done():
			return ctx.Err()
		case f.outGood <- append([]byte(nil), payload...):
			return nil
		}
	}
}

func TestPacketPumpSurvivesNonFatalPacketErrors(t *testing.T) {
	base := newTUNManagerPacketSession(TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true})
	flaky := &flakyPumpSession{
		PacketTunnelReadSession: base,
		inGood:                  make(chan PacketTunnelPacket, 2),
		outGood:                 make(chan []byte, 2),
	}
	dev := newTUNManagerDevice("tun-resilient0")
	pump, err := NewPacketPump(PacketPumpConfig{
		Session: flaky,
		Device:  dev,
	})
	if err != nil {
		t.Fatalf("NewPacketPump error = %v", err)
	}
	if err := pump.Start(context.Background()); err != nil {
		t.Fatalf("pump.Start error = %v", err)
	}
	defer pump.Close(context.Background())

	wantIn := []byte{0x45, 0, 0, 0x14, 0x11}
	flaky.inGood <- PacketTunnelPacket{Payload: wantIn}
	if got := readPumpBytes(t, dev.writes); !bytes.Equal(got, wantIn) {
		t.Fatalf("espToDevice payload = %x, want %x", got, wantIn)
	}

	wantOut := []byte{0x45, 0, 0, 0x14, 0x22}
	for i := 0; i < 4; i++ {
		dev.reads <- wantOut
	}
	if got := readPumpBytes(t, flaky.outGood); !bytes.Equal(got, wantOut) {
		t.Fatalf("deviceToESP payload = %x, want %x", got, wantOut)
	}
}

func TestSharedNATTTransientErrorsPeerDPDAndDeleteAndSingleMissedDPDIncrement(t *testing.T) {
	for _, err := range []error{
		syscall.ECONNREFUSED,
		syscall.EHOSTUNREACH,
		syscall.ENETUNREACH,
		syscall.EMSGSIZE,
		syscall.EAGAIN,
		syscall.ENOBUFS,
	} {
		if !isTransientUDPReadError(err) {
			t.Fatalf("expected %v to be treated as transient UDP read error", err)
		}
	}

	// Verify missedDPDProbes increments by exactly 1 per failed probe across AdvanceIKELiveness.
	start := time.Unix(1000, 0)
	liveness, err := NewIKELivenessState(IKELivenessConfig{
		DisableKeepalive:   true,
		DPDInterval:        10 * time.Second,
		DPDTimeout:         5 * time.Second,
		MaxMissedDPDProbes: 2,
	}, start)
	if err != nil {
		t.Fatalf("NewIKELivenessState error = %v", err)
	}
	tr := newChannelESPTransport()
	child := packetChildSA(true)
	ps, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   child,
		Transport: tr,
		Liveness:  liveness,
		DPDHandler: func(context.Context) error {
			return errors.New("dpd timeout")
		},
	})
	if err != nil {
		t.Fatalf("NewPacketSession error = %v", err)
	}
	defer ps.Close(context.Background())

	_, _ = ps.AdvanceIKELiveness(context.Background(), start.Add(10*time.Second))
	if snap := ps.IKELivenessSnapshot(); snap.MissedDPDProbes != 1 || snap.Dead {
		t.Fatalf("after 1st failed DPD probe: missed=%d dead=%v, want missed=1 dead=false", snap.MissedDPDProbes, snap.Dead)
	}
	_, _ = ps.AdvanceIKELiveness(context.Background(), start.Add(15*time.Second))
	if snap := ps.IKELivenessSnapshot(); snap.MissedDPDProbes != 2 || !snap.Dead {
		t.Fatalf("after 2nd failed DPD probe: missed=%d dead=%v, want missed=2 dead=true", snap.MissedDPDProbes, snap.Dead)
	}

	// Verify sharedNATTUDPConn separates responder-initiated DPD & DELETE requests from client ExchangeIKE responses.
	peerUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP error = %v", err)
	}
	defer peerUDP.Close()

	ikeTr := newSharedNATTTransport(peerUDP.LocalAddr().String(), "127.0.0.1:0", 2*time.Second)
	defer ikeTr.Close()
	if _, _, err := ikeTr.prepareNetworkEndpoints(context.Background()); err != nil {
		t.Fatalf("prepareNetworkEndpoints error = %v", err)
	}
	clientAddr := ikeTr.core.conn.LocalAddr().(*net.UDPAddr)

	init := ikeControlInit(t)
	peerSession, err := NewPacketSession(PacketSessionConfig{
		ChildSA:               child,
		Transport:             ikeTr.sharedESPTransport(),
		IKEInit:               init,
		IKEKeys:               init.Keys,
		BackgroundMaintenance: true,
		MaintenanceInterval:   20 * time.Millisecond,
		Liveness: func() *IKELivenessState {
			st, _ := NewIKELivenessState(IKELivenessConfig{
				KeepaliveInterval: 30 * time.Millisecond,
				DisableDPD:        true,
			}, time.Now().Add(-time.Second))
			return st
		}(),
	})
	if err != nil {
		t.Fatalf("NewPacketSession(peerSession) error = %v", err)
	}
	defer peerSession.Close(context.Background())

	// Peer sends responder-initiated empty INFORMATIONAL DPD request (MessageID = 42, fromInitiator = false).
	iv, err := ikev2.RandomIV(rand.Reader, init.Keys.Profile)
	if err != nil {
		t.Fatalf("RandomIV error = %v", err)
	}
	_, dpdReqBytes, err := ikev2.BuildInformationalRequestFrom(init, init.Keys, 42, false, nil, iv)
	if err != nil {
		t.Fatalf("BuildInformationalRequestFrom(DPD) error = %v", err)
	}
	if _, err := peerUDP.WriteToUDP(append([]byte{0, 0, 0, 0}, dpdReqBytes...), clientAddr); err != nil {
		t.Fatalf("WriteToUDP(DPD) error = %v", err)
	}

	// Read packets on peerUDP until we observe both a NAT-T 0xff keepalive and the encrypted DPD response!
	sawKeepalive := false
	sawDPDResponse := false
	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 2048)
	for (!sawKeepalive || !sawDPDResponse) && time.Now().Before(deadline) {
		_ = peerUDP.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, rerr := peerUDP.ReadFromUDP(buf)
		if rerr != nil {
			continue
		}
		pkt := buf[:n]
		if len(pkt) == 1 && pkt[0] == 0xff {
			sawKeepalive = true
			continue
		}
		if len(pkt) > 4 && bytes.Equal(pkt[:4], []byte{0, 0, 0, 0}) {
			_, content, parseErr := ikev2.ParseInformationalResponseContentFrom(pkt[4:], init, init.Keys, 42, true)
			if parseErr == nil && len(content.Payloads) == 0 {
				sawDPDResponse = true
			}
		}
	}
	if !sawKeepalive || !sawDPDResponse {
		t.Fatalf("sawKeepalive=%v sawDPDResponse=%v", sawKeepalive, sawDPDResponse)
	}

	// Now peer sends responder-initiated INFORMATIONAL DELETE for IKE SA (MessageID = 43).
	ivDel, _ := ikev2.RandomIV(rand.Reader, init.Keys.Profile)
	_, delReqBytes, err := ikev2.BuildInformationalRequestFrom(init, init.Keys, 43, false, []ikev2.Payload{ikev2.IKEDeletePayload()}, ivDel)
	if err != nil {
		t.Fatalf("BuildInformationalRequestFrom(DELETE) error = %v", err)
	}
	if _, err := peerUDP.WriteToUDP(append([]byte{0, 0, 0, 0}, delReqBytes...), clientAddr); err != nil {
		t.Fatalf("WriteToUDP(DELETE) error = %v", err)
	}

	sawDelAck := false
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_ = peerUDP.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, rerr := peerUDP.ReadFromUDP(buf)
		if rerr != nil {
			if !peerSession.Result().IsReady() && sawDelAck {
				break
			}
			continue
		}
		pkt := buf[:n]
		if len(pkt) > 4 && bytes.Equal(pkt[:4], []byte{0, 0, 0, 0}) {
			if _, _, parseErr := ikev2.ParseInformationalResponseContentFrom(pkt[4:], init, init.Keys, 43, true); parseErr == nil {
				sawDelAck = true
			}
		}
		if sawDelAck && !peerSession.Result().IsReady() {
			break
		}
	}
	if !sawDelAck {
		t.Fatal("did not receive encrypted INFORMATIONAL ACK for peer DELETE")
	}
	waitDeadline := time.Now().Add(time.Second)
	for peerSession.Result().IsReady() && time.Now().Before(waitDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if peerSession.Result().IsReady() {
		t.Fatalf("expected peerSession to be marked not ready after peer DELETE: %+v", peerSession.Result())
	}
}

func TestDualStackTUNRoutingIsolationAndConcurrentEstablishRace(t *testing.T) {
	init := ikeControlInit(t)
	child := packetChildSA(true)
	child.Configuration = &ikev2.Configuration{
		Type: ikev2.CFGReply,
		Attributes: []ikev2.ConfigurationAttribute{
			{Type: ikev2.ConfigInternalIPv4Address, Value: net.IPv4(10, 44, 0, 2).To4()},
			{Type: ikev2.ConfigInternalIPv6Address, Value: net.ParseIP("2001:db8:44::2").To16()},
		},
	}
	res := tunnelResultFromIKE(TunnelConfig{}, "epdg.example", init, child, DataplaneModeUserspace)
	if res.LocalInnerIP != "10.44.0.2" || res.LocalInnerIPv4 != "10.44.0.2" || res.LocalInnerIPv6 != "2001:db8:44::2" {
		t.Fatalf("dual-stack TunnelResult = %+v", res)
	}
	if len(res.LocalInnerIPs) != 2 || res.LocalInnerIPs[0] != "10.44.0.2" || res.LocalInnerIPs[1] != "2001:db8:44::2" {
		t.Fatalf("LocalInnerIPs = %v", res.LocalInnerIPs)
	}

	// Verify dual-stack TUNTunnelManager assigns both IPv4 & IPv6 addresses/routes/rules and protects table 20009 (NOT main!).
	baseSession := newTUNManagerPacketSession(res)
	routing := &tunManagerRouting{}
	tunMgr := NewTUNTunnelManager(TUNTunnelManagerConfig{
		Base:               &tunManagerBase{session: baseSession},
		RoutingManager:     routing,
		IsolateHostRouting: true,
		ProtectEPDGRoutes:  true,
		DisableMaintenance: true,
		EPDGRouteResolver: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("198.51.100.99"), net.ParseIP("2001:db8:99::1")}, nil
		},
		DeviceFactory: func(context.Context, TunnelConfig, TunnelResult) (InnerPacketDevice, string, error) {
			return newTUNManagerDevice("tun9"), "tun9", nil
		},
	})
	tunSess, err := tunMgr.EstablishTunnel(context.Background(), TunnelConfig{
		DeviceID:       "dual-1",
		Mode:           DataplaneModeUserspace,
		EPDGAddress:    "epdg.example",
		LocalInterface: "eth0",
		OuterLocalIP:   "192.0.2.10",
		IMSI:           "310260000000001",
	})
	if err != nil {
		t.Fatalf("EstablishTunnel(dual) error = %v", err)
	}
	defer tunSess.Close(context.Background())

	// Verify TUNPacketTunnelSession implements IKELivenessController and MOBIKENATObserver.
	var _ IKELivenessController = tunSess.(*TUNPacketTunnelSession)
	var _ MOBIKENATObserver = tunSess.(*TUNPacketTunnelSession)

	applied := routing.applies[0]
	if len(applied.Addresses) != 2 || applied.Addresses[0] != "10.44.0.2" || applied.Addresses[1] != "2001:db8:44::2" {
		t.Fatalf("dual-stack Addresses = %v", applied.Addresses)
	}
	if len(applied.Routes) != 2 || applied.Routes[0].Destination != "default" || applied.Routes[1].Destination != "::/0" {
		t.Fatalf("dual-stack Routes = %+v", applied.Routes)
	}
	if len(applied.Rules) != 2 || applied.Rules[0].From != "10.44.0.2/32" || applied.Rules[1].From != "2001:db8:44::2/128" {
		t.Fatalf("dual-stack Rules = %+v", applied.Rules)
	}
	if len(applied.EPDGRouteExclusions) != 2 {
		t.Fatalf("dual-stack EPDGRouteExclusions = %+v", applied.EPDGRouteExclusions)
	}
	for _, excl := range applied.EPDGRouteExclusions {
		if len(excl.Tables) != 1 || excl.Tables[0] != "20009" {
			t.Fatalf("exclusion mutated wrong table: %+v", excl)
		}
	}

	// Verify IPv6-only isolated route "::/0" and "0.0.0.0/0" never mutate main.
	if got := routingTablesForRoutes([]TUNRoute{{Destination: "::/0", Table: "20007"}}); len(got) != 1 || got[0] != "20007" {
		t.Fatalf("routingTablesForRoutes(::/0) = %v, want [20007]", got)
	}
	if got := routingTablesForRoutes([]TUNRoute{{Destination: "0.0.0.0/0", Table: "20008"}}); len(got) != 1 || got[0] != "20008" {
		t.Fatalf("routingTablesForRoutes(0.0.0.0/0) = %v, want [20008]", got)
	}

	// Verify concurrent EstablishTunnel calls updating Reauthentication have zero data races.
	ikeMgr := NewIKEPacketTunnelManager(IKEPacketTunnelManagerConfig{
		SIM:                      ikeTunnelAKAProvider{},
		ChildSPI:                 []byte{0x11, 0x22, 0x33, 0x44},
		DisableControlPlaneHooks: true,
		ReauthenticationLifetime: time.Minute,
		IKETransportFactory: func(TunnelConfig, IKETransportConfig) (ikev2.InitTransport, error) {
			return &ikeMOBIKETransport{t: t, init: init, keys: init.Keys, messageID: 5}, nil
		},
		ESPTransportFactory: func(TunnelConfig, ESPTransportConfig) (ESPPacketTransport, error) {
			return newChannelESPTransport(), nil
		},
		InitRunner: func(context.Context, ikev2.InitConfig) (ikev2.InitResult, error) {
			return init, nil
		},
		AuthRunner: func(context.Context, ikev2.FullAuthConfig) (ikev2.FullAuthResult, error) {
			c := packetChildSA(true)
			return ikev2.FullAuthResult{
				ChildSA:         &c,
				NextMessageID:   2,
				EAPNextReauthID: "reauth@nai.epc.mnc280.mcc310.3gppnetwork.org",
				EAPKeys: eapaka.Keys{
					KAut:  bytes.Repeat([]byte{0xaa}, 16),
					KEncr: bytes.Repeat([]byte{0xbb}, 16),
				},
			}, nil
		},
	})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, estabErr := ikeMgr.EstablishTunnel(context.Background(), TunnelConfig{
				DeviceID:    "race-dev",
				Mode:        DataplaneModeUserspace,
				EPDGAddress: "198.51.100.7",
				IMSI:        "310280233641503",
				MCC:         "310",
				MNC:         "280",
			})
			if estabErr != nil {
				t.Errorf("concurrent EstablishTunnel error = %v", estabErr)
				return
			}
			_ = s.Close(context.Background())
		}()
	}
	wg.Wait()
}
