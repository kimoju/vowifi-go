package voicehost

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/kimoju/vowifi-go/runtimehost/voiceclient"
)

func buildTestRTPPacket(seq uint16, ts uint32, ssrc uint32) []byte {
	pkt := make([]byte, 16)
	pkt[0] = 0x80
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], seq)
	binary.BigEndian.PutUint32(pkt[4:8], ts)
	binary.BigEndian.PutUint32(pkt[8:12], ssrc)
	copy(pkt[12:], []byte{1, 2, 3, 4})
	return pkt
}

func TestRTPStreamStatsTrackerBoundsSeenSequencesAndStreams(t *testing.T) {
	tracker := NewRTPStreamStatsTracker()
	now := time.Now()
	const ssrc = uint32(0x11223344)

	for i := 0; i < 6000; i++ {
		pkt := buildTestRTPPacket(uint16(i), uint32(i*160), ssrc)
		if _, err := tracker.ObserveRTPPacket(pkt, now.Add(time.Duration(i)*20*time.Millisecond), 8000); err != nil {
			t.Fatalf("ObserveRTPPacket(%d): %v", i, err)
		}
	}
	state := tracker.streams[ssrc]
	if state == nil {
		t.Fatal("expected stream state")
	}
	if len(state.seenSequences) > maxRTPSeenSequences || len(state.seenRing) > maxRTPSeenSequences {
		t.Fatalf("seenSequences=%d seenRing=%d, want <= %d", len(state.seenSequences), len(state.seenRing), maxRTPSeenSequences)
	}
	// Recent duplicate inside window must be detected.
	dupRecent := buildTestRTPPacket(uint16(5999), uint32(5999*160), ssrc)
	stats, err := tracker.ObserveRTPPacket(dupRecent, now.Add(120*time.Second), 8000)
	if err != nil {
		t.Fatalf("ObserveRTPPacket(dupRecent): %v", err)
	}
	if stats.DuplicatePackets != 1 || stats.Packets != 6000 {
		t.Fatalf("stats after recent dup = %+v", stats)
	}
	// Ancient packet outside window must also be treated safely without inflating unique Packets > ExpectedPackets.
	dupAncient := buildTestRTPPacket(uint16(10), uint32(10*160), ssrc)
	stats, err = tracker.ObserveRTPPacket(dupAncient, now.Add(121*time.Second), 8000)
	if err != nil {
		t.Fatalf("ObserveRTPPacket(dupAncient): %v", err)
	}
	if stats.Packets != 6000 || stats.DuplicatePackets != 2 {
		t.Fatalf("stats after ancient dup = %+v", stats)
	}

	// Track more than maxRTPTrackedStreams SSRCs and ensure map size stays bounded.
	for i := 0; i < maxRTPTrackedStreams+20; i++ {
		pkt := buildTestRTPPacket(1, 160, uint32(1000+i))
		if _, err := tracker.ObserveRTPPacket(pkt, now, 8000); err != nil {
			t.Fatalf("ObserveRTPPacket(ssrc %d): %v", i, err)
		}
	}
	if len(tracker.streams) > maxRTPTrackedStreams {
		t.Fatalf("tracked streams = %d, want <= %d", len(tracker.streams), maxRTPTrackedStreams)
	}
}

func TestRTPRelaySessionBindsIPv4AndIPv6AndSurvivesCancelledDialContext(t *testing.T) {
	canceledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if _, err := NewRTPRelaySession(canceledCtx, RTPRelayConfig{ClientListenIP: "127.0.0.1"}, SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 4000}); err == nil {
		t.Fatal("expected error for pre-cancelled context")
	}

	clientPeer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen clientPeer: %v", err)
	}
	defer clientPeer.Close()
	imsPeer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen imsPeer: %v", err)
	}
	defer imsPeer.Close()

	dialCtx, dialCancel := context.WithCancel(context.Background())
	relayCfg := effectiveMediaRelayForLocalIP(&RTPRelayConfig{
		ClientListenIP:    "127.0.0.1",
		ClientAdvertiseIP: "127.0.0.1",
	}, "127.0.0.1")
	relay, err := NewRTPRelaySession(dialCtx, *relayCfg, SDPInfo{
		ConnectionIP: "127.0.0.1",
		MediaPort:    clientPeer.LocalAddr().(*net.UDPAddr).Port,
		Direction:    "sendrecv",
	})
	if err != nil {
		t.Fatalf("NewRTPRelaySession: %v", err)
	}
	defer relay.Close()
	if err := relay.SetIMSRemote(SDPInfo{
		ConnectionIP: "127.0.0.1",
		MediaPort:    imsPeer.LocalAddr().(*net.UDPAddr).Port,
		Direction:    "sendrecv",
	}); err != nil {
		t.Fatalf("SetIMSRemote: %v", err)
	}

	// Cancel the dial context after session creation; active media forwarding must continue.
	dialCancel()

	rtpPkt := buildTestRTPPacket(7, 1120, 0xCAFEBABE)
	imsRelayAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(relay.IMSEndpoint().ConnectionIP, "0"))
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	imsRelayAddr.Port = relay.IMSEndpoint().MediaPort
	clientRelayAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: relay.ClientEndpoint().MediaPort}
	if _, err := clientPeer.WriteToUDP(rtpPkt, clientRelayAddr); err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}
	_ = imsPeer.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _, err := imsPeer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("imsPeer.ReadFromUDP after dialCtx cancel: %v", err)
	}
	if n != len(rtpPkt) {
		t.Fatalf("forwarded len=%d, want %d", n, len(rtpPkt))
	}

	// Verify IPv6 binding when ::1 loopback is available.
	probeV6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	v6PeerPort := probeV6.LocalAddr().(*net.UDPAddr).Port
	_ = probeV6.Close()

	v6Cfg := effectiveMediaRelayForLocalIP(&RTPRelayConfig{
		ClientListenIP:    "127.0.0.1",
		ClientAdvertiseIP: "127.0.0.1",
	}, "::1")
	v6Relay, err := NewRTPRelaySession(context.Background(), *v6Cfg, SDPInfo{
		ConnectionIP: "127.0.0.1",
		MediaPort:    clientPeer.LocalAddr().(*net.UDPAddr).Port,
		Direction:    "sendrecv",
	})
	if err != nil {
		t.Fatalf("NewRTPRelaySession IPv6 IMS leg: %v", err)
	}
	defer v6Relay.Close()
	if v6Relay.IMSEndpoint().ConnectionIP != "::1" || v6Relay.IMSEndpoint().MediaPort <= 0 || v6Relay.IMSEndpoint().MediaPort == v6PeerPort {
		// Port may match by coincidence, so only assert valid ::1 endpoint.
		if v6Relay.IMSEndpoint().ConnectionIP != "::1" || v6Relay.IMSEndpoint().MediaPort <= 0 {
			t.Fatalf("unexpected IPv6 IMSEndpoint: %+v", v6Relay.IMSEndpoint())
		}
	}
}

type auditStubSIPTransport struct {
	roundTripFn func(context.Context, voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error)
	writeErr    error
	written     []voiceclient.SIPRequestMessage
}

func (t *auditStubSIPTransport) RoundTripRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error) {
	if t.roundTripFn != nil {
		return t.roundTripFn(ctx, msg)
	}
	return voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"}, nil
}

func (t *auditStubSIPTransport) WriteRequest(_ context.Context, msg voiceclient.SIPRequestMessage) error {
	t.written = append(t.written, msg)
	return t.writeErr
}

func TestIMSOutboundAgentCleansUpRelayOnAckFailureAnd481Cancel(t *testing.T) {
	ackFailTransport := &auditStubSIPTransport{
		roundTripFn: func(_ context.Context, msg voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error) {
			return voiceclient.SIPResponse{
				StatusCode: 200,
				Reason:     "OK",
				Headers: map[string][]string{
					"To":           {"<sip:+18005551212@ims.mnc001.mcc001.3gppnetwork.org>;tag=ims-tag"},
					"Contact":      {"<sip:ims@127.0.0.1:5060>"},
					"Content-Type": {"application/sdp"},
				},
				Body: BuildSDPAnswer(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 19000, Payloads: []int{0}}),
			}, nil
		},
		writeErr: errors.New("ack send failure"),
	}
	agent := &IMSOutboundAgent{
		Transport: ackFailTransport,
		Profile: voiceclient.IMSProfile{
			IMPU:    "sip:alice@ims.mnc001.mcc001.3gppnetwork.org",
			Domain:  "ims.mnc001.mcc001.3gppnetwork.org",
			LocalIP: "127.0.0.1",
		},
		Registration: voiceclient.RegistrationBinding{
			PublicIdentity: "sip:alice@ims.mnc001.mcc001.3gppnetwork.org",
			ContactURI:     "sip:alice@127.0.0.1:5062",
		},
		MediaRelay: &RTPRelayConfig{
			ClientListenIP:    "127.0.0.1",
			ClientAdvertiseIP: "127.0.0.1",
		},
	}
	offer := BuildSDPAnswer(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 18000, Payloads: []int{0}})
	_, err := agent.StartOutboundCall(context.Background(), OutboundCallRequest{
		CallID:    "call-ack-fail",
		Callee:    "+18005551212",
		RemoteSDP: SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 18000, Payloads: []int{0}},
		RawSDP:    offer,
	})
	if err == nil {
		t.Fatal("expected ACK write failure")
	}
	if agent.HasOutboundDialog("call-ack-fail") {
		t.Fatal("dialog leaked after ACK write failure")
	}

	// Verify 481 response to CANCEL cleans up early dialog + relay.
	relay, err := NewRTPRelaySession(context.Background(), RTPRelayConfig{ClientListenIP: "127.0.0.1", ClientAdvertiseIP: "127.0.0.1"}, SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 18000})
	if err != nil {
		t.Fatalf("NewRTPRelaySession: %v", err)
	}
	cancel481Transport := &auditStubSIPTransport{
		roundTripFn: func(_ context.Context, _ voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error) {
			return voiceclient.SIPResponse{StatusCode: 481, Reason: "Call/Transaction Does Not Exist"}, nil
		},
	}
	agent.Transport = cancel481Transport
	agent.storeDialog("call-cancel-481", imsDialogState{
		cfg: voiceclient.DialogRequestConfig{
			LocalURI:        "sip:alice@ims.mnc001.mcc001.3gppnetwork.org",
			RemoteURI:       "sip:+18005551212@ims.mnc001.mcc001.3gppnetwork.org",
			RemoteTargetURI: "sip:+18005551212@127.0.0.1:5060",
			ContactURI:      "sip:alice@127.0.0.1:5062",
			CallID:          "call-cancel-481",
			LocalTag:        "local-1",
			CSeq:            1,
		},
		invite: voiceclient.SIPRequestMessage{
			Method:  "INVITE",
			URI:     "sip:+18005551212@127.0.0.1:5060",
			Headers: map[string]string{"Via": "SIP/2.0/UDP 127.0.0.1:5062;branch=z9hG4bK-c1"},
		},
		relay: relay,
		early: true,
	})
	_, _ = agent.CancelVoiceCallWithResult(context.Background(), DialogInfo{CallID: "call-cancel-481"})
	if agent.HasOutboundDialog("call-cancel-481") || !relay.isClosed() {
		t.Fatalf("expected 481 CANCEL to clean up dialog and close relay; hasDialog=%v relayClosed=%v", agent.HasOutboundDialog("call-cancel-481"), relay.isClosed())
	}
}

func TestIMSInboundWireServerRoutesOutboundInDialogRequests(t *testing.T) {
	outboundTransport := &auditStubSIPTransport{
		roundTripFn: func(_ context.Context, msg voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error) {
			return voiceclient.SIPResponse{
				StatusCode: 200,
				Reason:     "OK",
				Headers: map[string][]string{
					"To":           {"<sip:+18005551212@ims.mnc001.mcc001.3gppnetwork.org>;tag=remote-tag-99"},
					"Contact":      {"<sip:ims@127.0.0.1:5060>"},
					"Content-Type": {"application/sdp"},
				},
				Body: BuildSDPAnswer(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 21000, Payloads: []int{0}}),
			}, nil
		},
	}
	var terminatedCallID string
	outbound := &IMSOutboundAgent{
		Transport: outboundTransport,
		Profile: voiceclient.IMSProfile{
			IMPU:    "sip:alice@ims.mnc001.mcc001.3gppnetwork.org",
			Domain:  "ims.mnc001.mcc001.3gppnetwork.org",
			LocalIP: "127.0.0.1",
		},
		Registration: voiceclient.RegistrationBinding{
			PublicIdentity: "sip:alice@ims.mnc001.mcc001.3gppnetwork.org",
			ContactURI:     "sip:alice@127.0.0.1:5062",
		},
		LocalTag: "local-tag-11",
		MediaRelay: &RTPRelayConfig{
			ClientListenIP:    "127.0.0.1",
			ClientAdvertiseIP: "127.0.0.1",
		},
		OnDialogTerminated: func(_ context.Context, callID string, _ string) {
			terminatedCallID = callID
		},
	}

	offer := BuildSDPAnswer(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 20000, Payloads: []int{0}})
	res, err := outbound.StartOutboundCall(context.Background(), OutboundCallRequest{
		CallID:    "outbound-call-1",
		Callee:    "+18005551212",
		RemoteSDP: SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 20000, Payloads: []int{0}},
		RawSDP:    offer,
	})
	if err != nil || !res.Accepted {
		t.Fatalf("StartOutboundCall: res=%+v err=%v", res, err)
	}
	st, ok := outbound.dialog("outbound-call-1")
	if !ok || st.relay == nil {
		t.Fatal("expected active outbound dialog with RTP relay")
	}
	relay := st.relay

	wireServer := &IMSInboundWireServer{
		OutboundAgent: outbound,
		ContactURI:    "sip:alice@127.0.0.1:5062",
	}

	baseHeaders := func(method, cseq string) map[string][]string {
		return map[string][]string{
			"Via":          {"SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-" + method + "-" + cseq},
			"From":         {"<sip:+18005551212@ims.mnc001.mcc001.3gppnetwork.org>;tag=remote-tag-99"},
			"To":           {"<sip:alice@ims.mnc001.mcc001.3gppnetwork.org>;tag=local-tag-11"},
			"Call-ID":      {"outbound-call-1"},
			"CSeq":         {cseq + " " + method},
			"Max-Forwards": {"70"},
		}
	}

	// 1. Inbound UPDATE with SDP hold (sendonly -> recvonly answer on relay IMS endpoint).
	holdSDP := BuildSDPAnswer(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 21002, Payloads: []int{0}, Direction: "sendonly"})
	updateHeaders := baseHeaders("UPDATE", "2")
	updateHeaders["Content-Type"] = []string{"application/sdp"}
	updateResp, err := wireServer.HandleRequest(context.Background(), voiceclient.SIPIncomingRequest{
		Method:  "UPDATE",
		URI:     "sip:alice@127.0.0.1:5062",
		Headers: updateHeaders,
		Body:    holdSDP,
	})
	if err != nil || len(updateResp) != 1 || updateResp[0].StatusCode != 200 {
		t.Fatalf("UPDATE resp=%+v err=%v", updateResp, err)
	}
	if !strings.Contains(string(updateResp[0].Body), "a=recvonly") {
		t.Fatalf("expected recvonly SDP answer to hold UPDATE, got:\n%s", string(updateResp[0].Body))
	}

	// 2. Inbound re-INVITE + ACK on active outbound dialog.
	reinviteSDP := BuildSDPAnswer(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 21004, Payloads: []int{0}, Direction: "sendrecv"})
	reinviteHeaders := baseHeaders("INVITE", "3")
	reinviteHeaders["Content-Type"] = []string{"application/sdp"}
	reinviteResp, err := wireServer.HandleRequest(context.Background(), voiceclient.SIPIncomingRequest{
		Method:  "INVITE",
		URI:     "sip:alice@127.0.0.1:5062",
		Headers: reinviteHeaders,
		Body:    reinviteSDP,
	})
	if err != nil || len(reinviteResp) < 2 || reinviteResp[len(reinviteResp)-1].StatusCode != 200 {
		t.Fatalf("re-INVITE resp=%+v err=%v", reinviteResp, err)
	}
	if _, err := wireServer.HandleRequest(context.Background(), voiceclient.SIPIncomingRequest{
		Method:  "ACK",
		URI:     "sip:alice@127.0.0.1:5062",
		Headers: baseHeaders("ACK", "3"),
	}); err != nil {
		t.Fatalf("ACK for outbound re-INVITE failed: %v", err)
	}

	// 3. Inbound NOTIFY & INFO (DTMF).
	notifyHeaders := baseHeaders("NOTIFY", "4")
	notifyHeaders["Event"] = []string{"refer"}
	notifyHeaders["Subscription-State"] = []string{"active"}
	notifyResp, err := wireServer.HandleRequest(context.Background(), voiceclient.SIPIncomingRequest{
		Method:  "NOTIFY",
		URI:     "sip:alice@127.0.0.1:5062",
		Headers: notifyHeaders,
	})
	if err != nil || len(notifyResp) != 1 || notifyResp[0].StatusCode != 200 {
		t.Fatalf("NOTIFY resp=%+v err=%v", notifyResp, err)
	}

	infoHeaders := baseHeaders("INFO", "5")
	infoHeaders["Content-Type"] = []string{"application/dtmf-relay"}
	infoResp, err := wireServer.HandleRequest(context.Background(), voiceclient.SIPIncomingRequest{
		Method:  "INFO",
		URI:     "sip:alice@127.0.0.1:5062",
		Headers: infoHeaders,
		Body:    []byte("Signal=5\r\nDuration=160\r\n"),
	})
	if err != nil || len(infoResp) != 1 || infoResp[0].StatusCode != 200 {
		t.Fatalf("INFO resp=%+v err=%v", infoResp, err)
	}

	// 4. Mismatched To-tag BYE must be rejected with 481 without tearing down dialog.
	badByeHeaders := baseHeaders("BYE", "6")
	badByeHeaders["To"] = []string{"<sip:alice@ims.mnc001.mcc001.3gppnetwork.org>;tag=wrong-tag"}
	badByeResp, err := wireServer.HandleRequest(context.Background(), voiceclient.SIPIncomingRequest{
		Method:  "BYE",
		URI:     "sip:alice@127.0.0.1:5062",
		Headers: badByeHeaders,
	})
	if err != nil || len(badByeResp) != 1 || badByeResp[0].StatusCode != 481 {
		t.Fatalf("mismatched BYE resp=%+v err=%v, want 481", badByeResp, err)
	}
	if !outbound.HasOutboundDialog("outbound-call-1") || relay.isClosed() {
		t.Fatal("mismatched BYE must not terminate active outbound call")
	}

	// 5. Valid remote BYE terminates outbound call, closes RTP relay, and answers 200 OK.
	byeResp, err := wireServer.HandleRequest(context.Background(), voiceclient.SIPIncomingRequest{
		Method:  "BYE",
		URI:     "sip:alice@127.0.0.1:5062",
		Headers: baseHeaders("BYE", "7"),
	})
	if err != nil || len(byeResp) != 1 || byeResp[0].StatusCode != 200 {
		t.Fatalf("valid BYE resp=%+v err=%v, want 200", byeResp, err)
	}
	if outbound.HasOutboundDialog("outbound-call-1") {
		t.Fatal("outbound dialog still present after remote BYE")
	}
	if !relay.isClosed() {
		t.Fatal("RTP relay was not closed after remote BYE")
	}
	if terminatedCallID != "outbound-call-1" {
		t.Fatalf("terminatedCallID=%q, want outbound-call-1", terminatedCallID)
	}
}

func TestIMSInboundWireServerClosesDialogOnInvite200AckTimeout(t *testing.T) {
	clientTransport := &auditStubSIPTransport{
		roundTripFn: func(_ context.Context, _ voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error) {
			return voiceclient.SIPResponse{
				StatusCode: 200,
				Reason:     "OK",
				Headers: map[string][]string{
					"To":           {"<sip:alice@127.0.0.1:5090>;tag=client-tag"},
					"Contact":      {"<sip:alice@127.0.0.1:5090>"},
					"Content-Type": {"application/sdp"},
				},
				Body: BuildSDPAnswer(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 23000, Payloads: []int{0}}),
			}, nil
		},
	}
	inboundAgent := &IMSInboundAgent{
		ClientTransport:  clientTransport,
		ClientContactURI: "sip:alice@127.0.0.1:5090",
		LocalContactURI:  "sip:alice@127.0.0.1:5062",
		Profile:          voiceclient.IMSProfile{IMPU: "sip:alice@ims.mnc001.mcc001.3gppnetwork.org", LocalIP: "127.0.0.1"},
		MediaRelay: &RTPRelayConfig{
			ClientListenIP:    "127.0.0.1",
			ClientAdvertiseIP: "127.0.0.1",
		},
	}
	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket server: %v", err)
	}
	defer serverConn.Close()
	callerConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket caller: %v", err)
	}
	defer callerConn.Close()

	wireServer := &IMSInboundWireServer{
		Agent:          inboundAgent,
		ContactURI:     "sip:alice@" + serverConn.LocalAddr().String(),
		ReadTimeout:    50 * time.Millisecond,
		InviteFinalT1:  20 * time.Millisecond,
		InviteFinalT2:  40 * time.Millisecond,
		TransactionTTL: 90 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = wireServer.ServePacket(ctx, serverConn) }()

	sdp := BuildSDPAnswer(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 22000, Payloads: []int{0}})
	rawInvite := strings.Join([]string{
		"INVITE sip:alice@" + serverConn.LocalAddr().String() + " SIP/2.0",
		"Via: SIP/2.0/UDP " + callerConn.LocalAddr().String() + ";branch=z9hG4bK-noack-1",
		"From: <sip:+18005550000@ims.mnc001.mcc001.3gppnetwork.org>;tag=caller-1",
		"To: <sip:alice@ims.mnc001.mcc001.3gppnetwork.org>",
		"Call-ID: mt-no-ack-1",
		"CSeq: 1 INVITE",
		"Contact: <sip:caller@" + callerConn.LocalAddr().String() + ">",
		"Max-Forwards: 70",
		"Content-Type: application/sdp",
		"Content-Length: " + strconvItoaTest(len(sdp)),
		"",
		string(sdp),
	}, "\r\n")
	if _, err := callerConn.WriteTo([]byte(rawInvite), serverConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo INVITE: %v", err)
	}

	// Wait until 200 OK is observed by caller, then deliberately withhold ACK.
	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 4096)
	saw200 := false
	for time.Now().Before(deadline) {
		_ = callerConn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, _, readErr := callerConn.ReadFrom(buf)
		if readErr != nil {
			continue
		}
		if strings.Contains(string(buf[:n]), "SIP/2.0 200") {
			saw200 = true
			break
		}
	}
	if !saw200 {
		t.Fatal("did not receive 200 OK for inbound INVITE")
	}

	// Wait past TransactionTTL (90ms) and verify unacknowledged inbound dialog + relay were cleaned up.
	waitDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(waitDeadline) {
		if !inboundAgent.hasInboundDialog("mt-no-ack-1") {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("unacknowledged inbound dialog leaked past 200 OK retransmission timeout")
}

func strconvItoaTest(n int) string {
	return voiceclientItoaTest(n)
}

func voiceclientItoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var digits [20]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[i:])
}
