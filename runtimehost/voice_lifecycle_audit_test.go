package runtimehost

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kimoju/vowifi-go/engine/swu"
	"github.com/kimoju/vowifi-go/runtimehost/eventhost"
	"github.com/kimoju/vowifi-go/runtimehost/identity"
	"github.com/kimoju/vowifi-go/runtimehost/messaging"
	"github.com/kimoju/vowifi-go/runtimehost/voiceclient"
	"github.com/kimoju/vowifi-go/runtimehost/voicehost"
)

type auditVoiceClientAdapter struct {
	contactURI string
	contactIP  string
	username   string
	err        error
}

func (a auditVoiceClientAdapter) GetClientContact(_ string) (string, string, string, error) {
	return a.contactURI, a.contactIP, a.username, a.err
}

type auditLocalClientSIPTransport struct {
	mu      sync.Mutex
	methods []string
}

func (t *auditLocalClientSIPTransport) RoundTripRequest(_ context.Context, msg voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error) {
	t.mu.Lock()
	t.methods = append(t.methods, msg.Method)
	t.mu.Unlock()
	switch msg.Method {
	case "INVITE":
		sdp := voicehost.BuildSDPAnswer(voicehost.SDPInfo{
			ConnectionIP: "127.0.0.1",
			MediaPort:    31000,
			Payloads:     []int{0},
		})
		return voiceclient.SIPResponse{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":           {"<sip:client@127.0.0.1:5095>;tag=client-mt-tag"},
				"Contact":      {"<sip:client@127.0.0.1:5095>"},
				"Content-Type": {"application/sdp"},
			},
			Body: sdp,
		}, nil
	default:
		return voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"}, nil
	}
}

func (t *auditLocalClientSIPTransport) WriteRequest(_ context.Context, msg voiceclient.SIPRequestMessage) error {
	t.mu.Lock()
	t.methods = append(t.methods, msg.Method)
	t.mu.Unlock()
	return nil
}

type auditSyncDispatcher struct {
	mu     sync.Mutex
	events []eventhost.Event
}

func (d *auditSyncDispatcher) Dispatch(_ context.Context, ev eventhost.Event) {
	d.mu.Lock()
	d.events = append(d.events, ev)
	d.mu.Unlock()
}

func (d *auditSyncDispatcher) voiceEvents() []eventhost.VoiceCallEvent {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []eventhost.VoiceCallEvent
	for _, ev := range d.events {
		if vc, ok := ev.(eventhost.VoiceCallEvent); ok {
			out = append(out, vc)
		}
	}
	return out
}

func TestRuntimeInboundVoiceAgentWiredEndToEnd(t *testing.T) {
	inboundConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket inbound: %v", err)
	}
	inboundAddr := inboundConn.LocalAddr().String()

	gw := voicehost.NewGateway()
	gw.SetClientAdapter(auditVoiceClientAdapter{
		contactURI: "sip:client@127.0.0.1:5095",
		contactIP:  "127.0.0.1",
		username:   "client",
	})
	clientTransport := &auditLocalClientSIPTransport{}
	dispatcher := &auditSyncDispatcher{}

	registrar := &testIMSRegistrar{
		result: IMSRegistrationResult{
			Registered: true,
			StatusCode: 200,
			Reason:     "OK",
			Profile: voiceclient.IMSProfile{
				IMPI:    "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				IMPU:    "sip:+18005550100@ims.mnc001.mcc001.3gppnetwork.org",
				Domain:  "ims.mnc001.mcc001.3gppnetwork.org",
				LocalIP: "127.0.0.1",
			},
			Binding: voiceclient.RegistrationBinding{
				PublicIdentity: "sip:+18005550100@ims.mnc001.mcc001.3gppnetwork.org",
				ContactURI:     "sip:+18005550100@" + inboundAddr,
			},
			VoiceTransport: &runtimeVoiceTransport{},
			Inbound: &IMSInboundConfig{
				Network:    "udp4",
				LocalAddr:  inboundAddr,
				ContactURI: "sip:+18005550100@" + inboundAddr,
				PacketConn: inboundConn,
			},
		},
	}

	inst, err := Start(context.Background(), StartRequest{
		DeviceID:             "dev-mt-1",
		VoiceGateway:         gw,
		VoiceClientTransport: clientTransport,
		VoiceMediaRelay: &voicehost.RTPRelayConfig{
			ClientListenIP:    "127.0.0.1",
			ClientAdvertiseIP: "127.0.0.1",
		},
		IMSRegistrar: registrar,
		Dispatch:     dispatcher,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = inst.Stop(context.Background()) }()

	callerConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket caller: %v", err)
	}
	defer callerConn.Close()

	sdpOffer := voicehost.BuildSDPAnswer(voicehost.SDPInfo{
		ConnectionIP: "127.0.0.1",
		MediaPort:    30000,
		Payloads:     []int{0},
	})
	rawInvite := strings.Join([]string{
		"INVITE sip:+18005550100@" + inboundAddr + " SIP/2.0",
		"Via: SIP/2.0/UDP " + callerConn.LocalAddr().String() + ";branch=z9hG4bK-mt-inv-1",
		"From: <sip:+18005559999@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-from-1",
		"To: <sip:+18005550100@ims.mnc001.mcc001.3gppnetwork.org>",
		"Call-ID: mt-e2e-call-1",
		"CSeq: 1 INVITE",
		"Contact: <sip:ims@" + callerConn.LocalAddr().String() + ">",
		"Max-Forwards: 70",
		"Content-Type: application/sdp",
		"Content-Length: " + strconv.Itoa(len(sdpOffer)),
		"",
		string(sdpOffer),
	}, "\r\n")
	if _, err := callerConn.WriteTo([]byte(rawInvite), inboundConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo INVITE: %v", err)
	}

	var toHeader string
	buf := make([]byte, 4096)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_ = callerConn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, _, readErr := callerConn.ReadFrom(buf)
		if readErr != nil {
			continue
		}
		resp, parseErr := voiceclient.ParseSIPResponse(buf[:n])
		if parseErr != nil {
			continue
		}
		if resp.StatusCode == 200 {
			if vals := resp.Headers["To"]; len(vals) > 0 {
				toHeader = vals[0]
			}
			break
		}
	}
	if toHeader == "" {
		t.Fatal("expected 200 OK for inbound MT INVITE")
	}

	rawAck := strings.Join([]string{
		"ACK sip:+18005550100@" + inboundAddr + " SIP/2.0",
		"Via: SIP/2.0/UDP " + callerConn.LocalAddr().String() + ";branch=z9hG4bK-mt-ack-1",
		"From: <sip:+18005559999@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-from-1",
		"To: " + toHeader,
		"Call-ID: mt-e2e-call-1",
		"CSeq: 1 ACK",
		"Max-Forwards: 70",
		"Content-Length: 0",
		"",
		"",
	}, "\r\n")
	if _, err := callerConn.WriteTo([]byte(rawAck), inboundConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo ACK: %v", err)
	}

	status := gw.DeviceStatus("dev-mt-1")
	if status["active_dialogs"] != 1 {
		t.Fatalf("gateway status during MT call = %+v, want active_dialogs=1", status)
	}

	rawBye := strings.Join([]string{
		"BYE sip:+18005550100@" + inboundAddr + " SIP/2.0",
		"Via: SIP/2.0/UDP " + callerConn.LocalAddr().String() + ";branch=z9hG4bK-mt-bye-2",
		"From: <sip:+18005559999@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-from-1",
		"To: " + toHeader,
		"Call-ID: mt-e2e-call-1",
		"CSeq: 2 BYE",
		"Max-Forwards: 70",
		"Content-Length: 0",
		"",
		"",
	}, "\r\n")
	if _, err := callerConn.WriteTo([]byte(rawBye), inboundConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo BYE: %v", err)
	}

	gotBye200 := false
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_ = callerConn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, _, readErr := callerConn.ReadFrom(buf)
		if readErr != nil {
			continue
		}
		resp, parseErr := voiceclient.ParseSIPResponse(buf[:n])
		if parseErr == nil && resp.StatusCode == 200 && strings.Contains(strings.Join(append(resp.Headers["Cseq"], resp.Headers["CSeq"]...), ","), "BYE") {
			gotBye200 = true
			break
		}
	}
	if !gotBye200 {
		t.Fatal("expected 200 OK for inbound MT BYE")
	}
	if gw.DeviceStatus("dev-mt-1")["active_dialogs"] != 0 {
		t.Fatalf("gateway status after MT BYE = %+v, want active_dialogs=0", gw.DeviceStatus("dev-mt-1"))
	}
	voiceEvents := dispatcher.voiceEvents()
	if len(voiceEvents) < 3 {
		t.Fatalf("voiceEvents=%+v, want early+established+terminated", voiceEvents)
	}
}

func TestRuntimeInboundWireRoutesActiveOutboundCallByeAndUpdate(t *testing.T) {
	inboundConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket inbound: %v", err)
	}
	inboundAddr := inboundConn.LocalAddr().String()

	imsSDP := voicehost.BuildSDPAnswer(voicehost.SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 32000, Payloads: []int{0}})
	voiceTransport := &runtimeVoiceTransport{
		responses: []voiceclient.SIPResponse{
			{
				StatusCode: 200,
				Reason:     "OK",
				Headers: map[string][]string{
					"To":           {"<sip:+18005551212@ims.mnc001.mcc001.3gppnetwork.org>;tag=ims-remote-tag"},
					"Contact":      {"<sip:ims@127.0.0.1:5060>"},
					"Content-Type": {"application/sdp"},
				},
				Body: imsSDP,
			},
		},
	}
	gw := voicehost.NewGateway()
	dispatcher := &auditSyncDispatcher{}
	registrar := &testIMSRegistrar{
		result: IMSRegistrationResult{
			Registered: true,
			StatusCode: 200,
			Reason:     "OK",
			Profile: voiceclient.IMSProfile{
				IMPI:    "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				IMPU:    "sip:+18005550100@ims.mnc001.mcc001.3gppnetwork.org",
				Domain:  "ims.mnc001.mcc001.3gppnetwork.org",
				LocalIP: "127.0.0.1",
			},
			Binding: voiceclient.RegistrationBinding{
				PublicIdentity: "sip:+18005550100@ims.mnc001.mcc001.3gppnetwork.org",
				ContactURI:     "sip:+18005550100@" + inboundAddr,
			},
			VoiceTransport: voiceTransport,
			Inbound: &IMSInboundConfig{
				Network:    "udp4",
				LocalAddr:  inboundAddr,
				ContactURI: "sip:+18005550100@" + inboundAddr,
				PacketConn: inboundConn,
			},
		},
	}

	inst, err := Start(context.Background(), StartRequest{
		DeviceID:     "dev-mo-1",
		VoiceGateway: gw,
		VoiceMediaRelay: &voicehost.RTPRelayConfig{
			ClientListenIP:    "127.0.0.1",
			ClientAdvertiseIP: "127.0.0.1",
		},
		IMSRegistrar: registrar,
		Dispatch:     dispatcher,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = inst.Stop(context.Background()) }()

	clientOffer := voicehost.BuildSDPAnswer(voicehost.SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 33000, Payloads: []int{0}})
	callRes, err := inst.StartOutboundCall(context.Background(), voicehost.OutboundCallRequest{
		DeviceID:  "dev-mo-1",
		CallID:    "mo-active-1",
		Callee:    "+18005551212",
		RemoteSDP: voicehost.SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 33000, Payloads: []int{0}},
		RawSDP:    clientOffer,
	})
	if err != nil || !callRes.Accepted {
		t.Fatalf("StartOutboundCall: res=%+v err=%v", callRes, err)
	}
	gw.RecordDialog(voicehost.DialogInfo{DeviceID: "dev-mo-1", CallID: "mo-active-1", Callee: "+18005551212", State: voicehost.DialogStateEstablished})

	peerConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket peer: %v", err)
	}
	defer peerConn.Close()

	// Send network BYE matching the active outbound dialog to IMSInboundWireServer!
	rawBye := strings.Join([]string{
		"BYE sip:+18005550100@" + inboundAddr + " SIP/2.0",
		"Via: SIP/2.0/UDP " + peerConn.LocalAddr().String() + ";branch=z9hG4bK-mo-bye-1",
		"From: <sip:+18005551212@ims.mnc001.mcc001.3gppnetwork.org>;tag=ims-remote-tag",
		"To: <sip:+18005550100@ims.mnc001.mcc001.3gppnetwork.org>;tag=vowifi-go",
		"Call-ID: mo-active-1",
		"CSeq: 2 BYE",
		"Max-Forwards: 70",
		"Content-Length: 0",
		"",
		"",
	}, "\r\n")
	if _, err := peerConn.WriteTo([]byte(rawBye), inboundConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo BYE: %v", err)
	}

	buf := make([]byte, 4096)
	_ = peerConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := peerConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom BYE response: %v", err)
	}
	resp, err := voiceclient.ParseSIPResponse(buf[:n])
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("BYE response=%+v err=%v, want 200 OK (not 481)", resp, err)
	}
	if inst.HasOutboundDialog("mo-active-1") {
		t.Fatal("outbound dialog still active after remote BYE")
	}
	if gw.DeviceStatus("dev-mo-1")["active_dialogs"] != 0 {
		t.Fatalf("gateway active_dialogs=%v, want 0", gw.DeviceStatus("dev-mo-1")["active_dialogs"])
	}
	events := dispatcher.voiceEvents()
	if len(events) != 1 || events[0].Direction != "outbound" || events[0].State != string(voicehost.DialogStateTerminated) {
		t.Fatalf("voiceEvents=%+v, want 1 outbound terminated event", events)
	}
}

type orderedStopTunnelManager struct {
	session *runtimeTunnelSession
	onStop  func()
}

func (m *orderedStopTunnelManager) EstablishTunnel(_ context.Context, _ swu.TunnelConfig) (swu.TunnelSession, error) {
	return m.session, nil
}

func (m *orderedStopTunnelManager) Stop(ctx context.Context, s swu.TunnelSession) error {
	if m.onStop != nil {
		m.onStop()
	}
	return s.Close(ctx)
}

type trackingClosePacketConn struct {
	net.PacketConn
	mu      sync.Mutex
	closed  bool
	onClose func()
}

func (c *trackingClosePacketConn) Close() error {
	c.mu.Lock()
	already := c.closed
	c.closed = true
	c.mu.Unlock()
	if !already && c.onClose != nil {
		c.onClose()
	}
	return c.PacketConn.Close()
}

func (c *trackingClosePacketConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func TestRuntimeStopOrderTerminatesCallsBeforeIMSDeregisterInboundAndTunnel(t *testing.T) {
	var mu sync.Mutex
	var order []string
	record := func(step string) {
		mu.Lock()
		order = append(order, step)
		mu.Unlock()
	}

	rawConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	trackedConn := &trackingClosePacketConn{
		PacketConn: rawConn,
		onClose:    func() { record("inbound_close") },
	}
	inboundAddr := rawConn.LocalAddr().String()

	session := &runtimeTunnelSession{
		result: swu.TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true, LocalInnerIP: "127.0.0.1"},
	}
	tunnelMgr := &orderedStopTunnelManager{
		session: session,
		onStop:  func() { record("tunnel_stop") },
	}

	imsSDP := voicehost.BuildSDPAnswer(voicehost.SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 34000, Payloads: []int{0}})
	voiceTransport := &auditStubRuntimeSIPTransport{
		onRoundTrip: func(msg voiceclient.SIPRequestMessage) voiceclient.SIPResponse {
			if msg.Method == "BYE" {
				if trackedConn.isClosed() || session.closed {
					t.Errorf("BYE sent after inbound (%v) or tunnel (%v) closed", trackedConn.isClosed(), session.closed)
				}
				record("active_call_bye")
				return voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"}
			}
			return voiceclient.SIPResponse{
				StatusCode: 200,
				Reason:     "OK",
				Headers: map[string][]string{
					"To":           {"<sip:+18005551212@ims.mnc001.mcc001.3gppnetwork.org>;tag=remote-stop"},
					"Contact":      {"<sip:ims@127.0.0.1:5060>"},
					"Content-Type": {"application/sdp"},
				},
				Body: imsSDP,
			}
		},
	}

	gw := voicehost.NewGateway()
	registrar := &testIMSRegistrar{
		result: IMSRegistrationResult{
			Registered: true,
			StatusCode: 200,
			Reason:     "OK",
			Profile: voiceclient.IMSProfile{
				IMPU:    "sip:alice@ims.mnc001.mcc001.3gppnetwork.org",
				Domain:  "ims.mnc001.mcc001.3gppnetwork.org",
				LocalIP: "127.0.0.1",
			},
			Binding: voiceclient.RegistrationBinding{
				PublicIdentity: "sip:alice@ims.mnc001.mcc001.3gppnetwork.org",
				ContactURI:     "sip:alice@" + inboundAddr,
			},
			VoiceTransport: voiceTransport,
			Inbound: &IMSInboundConfig{
				Network:    "udp4",
				LocalAddr:  inboundAddr,
				ContactURI: "sip:alice@" + inboundAddr,
				PacketConn: trackedConn,
			},
			Close: func(context.Context) error {
				if trackedConn.isClosed() || session.closed {
					t.Errorf("imsClose ran after inbound (%v) or tunnel (%v) closed", trackedConn.isClosed(), session.closed)
				}
				record("ims_close")
				return nil
			},
		},
	}

	inst, err := Start(context.Background(), StartRequest{
		DeviceID:      "dev-stop-order",
		Profile:       identity.Profile{IMSI: "001010123456789", MCC: "001", MNC: "01"},
		Dataplane:     DataplanePolicy{Mode: swu.DataplaneModeUserspace},
		TunnelManager: tunnelMgr,
		IMSRegistrar:  registrar,
		VoiceGateway:  gw,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if gw.GetAgent("dev-stop-order") == nil {
		t.Fatal("expected agent registered on VoiceGateway")
	}

	offer := voicehost.BuildSDPAnswer(voicehost.SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 35000, Payloads: []int{0}})
	if res, err := inst.StartOutboundCall(context.Background(), voicehost.OutboundCallRequest{
		DeviceID:  "dev-stop-order",
		CallID:    "call-stop-1",
		Callee:    "+18005551212",
		RemoteSDP: voicehost.SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 35000, Payloads: []int{0}},
		RawSDP:    offer,
	}); err != nil || !res.Accepted {
		t.Fatalf("StartOutboundCall: res=%+v err=%v", res, err)
	}

	if err := inst.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if gw.GetAgent("dev-stop-order") != nil {
		t.Fatal("expected VoiceGateway agent to be unregistered on Stop")
	}

	want := []string{"active_call_bye", "ims_close", "inbound_close", "tunnel_stop"}
	mu.Lock()
	got := append([]string(nil), order...)
	mu.Unlock()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("shutdown order = %v, want %v", got, want)
	}
}

type auditStubRuntimeSIPTransport struct {
	onRoundTrip func(voiceclient.SIPRequestMessage) voiceclient.SIPResponse
}

func (t *auditStubRuntimeSIPTransport) RoundTripRequest(_ context.Context, msg voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error) {
	return t.onRoundTrip(msg), nil
}

func (t *auditStubRuntimeSIPTransport) WriteRequest(_ context.Context, _ voiceclient.SIPRequestMessage) error {
	return nil
}

type callbackCapturingRegistrar struct {
	mu       sync.Mutex
	onUpdate func(IMSRegistrationResult)
	initial  IMSRegistrationResult
}

func (r *callbackCapturingRegistrar) RegisterIMS(_ context.Context, cfg IMSRegistrationConfig) (IMSRegistrationResult, error) {
	r.mu.Lock()
	r.onUpdate = cfg.OnRegistrationUpdate
	r.mu.Unlock()
	return r.initial, nil
}

func TestRuntimeBackgroundRegistrationUpdatePropagatesToInstance(t *testing.T) {
	initialSMS := &runtimeSMSTransport{}
	updatedSMS := &runtimeSMSTransport{}
	reg := &callbackCapturingRegistrar{
		initial: IMSRegistrationResult{
			Registered:     true,
			StatusCode:     200,
			Reason:         "initial",
			Profile:        voiceclient.IMSProfile{IMPU: "sip:alice@ims.mnc001.mcc001.3gppnetwork.org", Domain: "ims.mnc001.mcc001.3gppnetwork.org"},
			Binding:        voiceclient.RegistrationBinding{PublicIdentity: "sip:alice@ims.mnc001.mcc001.3gppnetwork.org", ContactURI: "sip:alice@10.0.0.1:5062"},
			VoiceTransport: &runtimeVoiceTransport{},
			SMSTransport:   initialSMS,
		},
	}

	inst, err := Start(context.Background(), StartRequest{
		DeviceID:     "dev-bg-reg",
		IMSRegistrar: reg,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = inst.Stop(context.Background()) }()

	reg.mu.Lock()
	cb := reg.onUpdate
	reg.mu.Unlock()
	if cb == nil {
		t.Fatal("expected OnRegistrationUpdate callback to be wired by Start")
	}

	cb(IMSRegistrationResult{
		Registered:     true,
		StatusCode:     200,
		Reason:         "background refresh",
		Profile:        voiceclient.IMSProfile{IMPU: "sip:alice@ims.mnc001.mcc001.3gppnetwork.org", Domain: "ims.mnc001.mcc001.3gppnetwork.org", LocalIP: "10.0.0.2"},
		Binding:        voiceclient.RegistrationBinding{PublicIdentity: "sip:alice@ims.mnc001.mcc001.3gppnetwork.org", ContactURI: "sip:alice@10.0.0.2:5064"},
		VoiceTransport: &runtimeVoiceTransport{},
		SMSTransport:   updatedSMS,
	})

	if inst.State().LastReason != "background refresh" {
		t.Fatalf("State().LastReason = %q, want background refresh", inst.State().LastReason)
	}
	if inst.inboundVoice == nil || inst.inboundVoice.LocalContact() != "sip:alice@10.0.0.2:5064" {
		t.Fatalf("inboundVoice LocalContact = %q, want sip:alice@10.0.0.2:5064", inst.inboundVoice.LocalContact())
	}
	if _, err := inst.SendSMSWithOptions(context.Background(), "+18005551212", "hello", messaging.SendOptions{}); err != nil {
		t.Fatalf("SendSMSWithOptions: %v", err)
	}
	if len(updatedSMS.requests) != 1 || len(initialSMS.requests) != 0 {
		t.Fatalf("expected updated SMS transport to be used; updated=%d initial=%d", len(updatedSMS.requests), len(initialSMS.requests))
	}
}

func TestDefaultTunnelManagerFallsBackToUserspaceWhenProxyActive(t *testing.T) {
	req := StartRequest{
		DeviceID:  "dev-proxy-kernel",
		SIM:       &runtimeSIMAdapter{},
		Dataplane: DataplanePolicy{Mode: swu.DataplaneModeKernel, TUNName: "tunproxy0"},
		Proxy:     &ProxyConfig{Enabled: true, Address: "127.0.0.1:1080"},
	}
	mgr, err := defaultTunnelManagerForStart(req)
	if err != nil {
		t.Fatalf("defaultTunnelManagerForStart: %v", err)
	}
	if _, ok := mgr.(*swu.TUNTunnelManager); !ok {
		t.Fatalf("manager = %T, want *swu.TUNTunnelManager when proxy is active", mgr)
	}
	tunnelCfg := buildTunnelConfig(req, nil)
	if tunnelCfg.Mode != swu.DataplaneModeUserspace {
		t.Fatalf("tunnelCfg.Mode = %q, want %q", tunnelCfg.Mode, swu.DataplaneModeUserspace)
	}
}
