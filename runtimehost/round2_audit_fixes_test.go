package runtimehost

import (
	"context"
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kimoju/vowifi-go/runtimehost/identity"
	"github.com/kimoju/vowifi-go/runtimehost/messaging"
	"github.com/kimoju/vowifi-go/runtimehost/voiceclient"
	"github.com/kimoju/vowifi-go/runtimehost/voicehost"
)

func TestRound2Shard8B07IMSInstanceIDUsesSpareZero(t *testing.T) {
	got := imsInstanceID(IMSRegistrationConfig{
		Profile: identity.Profile{IMEI: "490154203237518"},
	}, "001010123456789@ims.mnc001.mcc001.3gppnetwork.org")
	const want = "urn:gsma:imei:49015420-323751-0"
	if got != want {
		t.Fatalf("imsInstanceID = %q, want %q", got, want)
	}

	fallback := imsInstanceID(IMSRegistrationConfig{
		Profile: identity.Profile{IMEI: "invalid-imei"},
	}, "001010123456789@ims.mnc001.mcc001.3gppnetwork.org")
	if !strings.HasPrefix(fallback, "urn:uuid:") {
		t.Fatalf("fallback imsInstanceID = %q, want urn:uuid:*", fallback)
	}
}

func TestRound2Critical1AndMSG09RegEventSubscribeNotifyAndMWINotify(t *testing.T) {
	inboundProbe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket probe: %v", err)
	}
	contactPort := inboundProbe.LocalAddr().(*net.UDPAddr).Port
	_ = inboundProbe.Close()

	imsServer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket imsServer: %v", err)
	}
	defer imsServer.Close()

	subscribeSeen := make(chan string, 4)
	reregisterSeen := make(chan string, 4)
	var registerCountMu sync.Mutex
	registerCount := 0

	go func() {
		buf := make([]byte, 65535)
		for {
			_ = imsServer.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, addr, rErr := imsServer.ReadFrom(buf)
			if rErr != nil {
				return
			}
			wire := string(buf[:n])
			req, pErr := voiceclient.ParseSIPRequest(buf[:n])
			if pErr != nil {
				continue
			}
			via := firstRuntimeSIPHeaderCI(req.Headers, "Via", "v")
			from := firstRuntimeSIPHeaderCI(req.Headers, "From", "f")
			to := firstRuntimeSIPHeaderCI(req.Headers, "To", "t")
			callID := firstRuntimeSIPHeaderCI(req.Headers, "Call-ID", "i")
			cseq := firstRuntimeSIPHeaderCI(req.Headers, "CSeq")

			switch req.Method {
			case "REGISTER":
				registerCountMu.Lock()
				registerCount++
				rc := registerCount
				registerCountMu.Unlock()
				if strings.Contains(wire, "Expires: 0\r\n") {
					resp := "SIP/2.0 200 OK\r\n" +
						"Via: " + via + "\r\n" +
						"From: " + from + "\r\n" +
						"To: " + to + ";tag=scscf-reg\r\n" +
						"Call-ID: " + callID + "\r\n" +
						"CSeq: " + cseq + "\r\n" +
						"Content-Length: 0\r\n\r\n"
					_, _ = imsServer.WriteTo([]byte(resp), addr)
					continue
				}
				if rc >= 2 {
					select {
					case reregisterSeen <- wire:
					default:
					}
				}
				resp := "SIP/2.0 200 OK\r\n" +
					"Via: " + via + "\r\n" +
					"From: " + from + "\r\n" +
					"To: " + to + ";tag=scscf-reg\r\n" +
					"Call-ID: " + callID + "\r\n" +
					"CSeq: " + cseq + "\r\n" +
					"Service-Route: <sip:scscf.ims.example;lr>\r\n" +
					"P-Associated-URI: <sip:310280233641503@ims.mnc280.mcc310.3gppnetwork.org>\r\n" +
					"Contact: <sip:310280233641503@127.0.0.1:" + itoaTest(contactPort) + ">;expires=600\r\n" +
					"Content-Length: 0\r\n\r\n"
				_, _ = imsServer.WriteTo([]byte(resp), addr)

			case "SUBSCRIBE":
				select {
				case subscribeSeen <- wire:
				default:
				}
				resp := "SIP/2.0 200 OK\r\n" +
					"Via: " + via + "\r\n" +
					"From: " + from + "\r\n" +
					"To: " + to + ";tag=scscf-sub\r\n" +
					"Call-ID: " + callID + "\r\n" +
					"CSeq: " + cseq + "\r\n" +
					"Expires: 600\r\n" +
					"Content-Length: 0\r\n\r\n"
				_, _ = imsServer.WriteTo([]byte(resp), addr)
			}
		}
	}()

	dispatcher := &auditSyncDispatcher{}
	inst, err := Start(context.Background(), StartRequest{
		DeviceID: "dev-reg-event",
		TraceID:  "trace-reg-event",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280", IMEI: "490154203237518"},
		Dispatch: dispatcher,
		IMSRegistrar: WireIMSRegistrar{
			Network:          "udp4",
			ServerAddr:       imsServer.LocalAddr().String(),
			ContactHost:      "127.0.0.1",
			ContactPort:      contactPort,
			Expires:          600,
			DisableRefresh:   true,
			DisableKeepalive: true,
			Timeout:          time.Second,
		},
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() { _ = inst.Stop(context.Background()) }()

	var subWire string
	select {
	case subWire = <-subscribeSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SUBSCRIBE Event: reg")
	}
	if !strings.Contains(subWire, "Event: reg\r\n") ||
		!strings.Contains(subWire, "Accept: application/reginfo+xml\r\n") ||
		!strings.Contains(subWire, "Route: <sip:scscf.ims.example;lr>\r\n") {
		t.Fatalf("unexpected SUBSCRIBE wire:\n%s", subWire)
	}

	notifySender, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket notifySender: %v", err)
	}
	defer notifySender.Close()

	inboundTarget := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: contactPort}

	// 1. Send NOTIFY Event: message-summary (MSG-09) -> verify 200 OK and MessageWaitingEvent!
	mwiBody := "Messages-Waiting: yes\r\nMessage-Account: sip:vm@ims.mnc280.mcc310.3gppnetwork.org\r\nVoice-Message: 2/1 (1/0)\r\n"
	mwiNotify := strings.Join([]string{
		"NOTIFY sip:310280233641503@127.0.0.1:" + itoaTest(contactPort) + " SIP/2.0",
		"Via: SIP/2.0/UDP " + notifySender.LocalAddr().String() + ";branch=z9hG4bK-mwi-1",
		"From: <sip:vm@ims.mnc280.mcc310.3gppnetwork.org>;tag=vm-1",
		"To: <sip:310280233641503@ims.mnc280.mcc310.3gppnetwork.org>",
		"Call-ID: mwi-notify-1",
		"CSeq: 1 NOTIFY",
		"Event: message-summary",
		"Subscription-State: active;expires=3600",
		"Content-Type: application/simple-message-summary",
		"Content-Length: " + itoaTest(len(mwiBody)),
		"",
		mwiBody,
	}, "\r\n")
	if _, err := notifySender.WriteTo([]byte(mwiNotify), inboundTarget); err != nil {
		t.Fatalf("WriteTo MWI NOTIFY: %v", err)
	}
	resp := readUDPSIPResponseTest(t, notifySender)
	if resp.StatusCode != 200 {
		t.Fatalf("MWI NOTIFY status=%d reason=%q, want 200", resp.StatusCode, resp.Reason)
	}
	dispatcher.mu.Lock()
	var mwiEvents []messaging.MessageWaitingEvent
	for _, ev := range dispatcher.events {
		if mwi, ok := ev.(messaging.MessageWaitingEvent); ok {
			mwiEvents = append(mwiEvents, mwi)
		}
	}
	dispatcher.mu.Unlock()
	if len(mwiEvents) != 1 || !mwiEvents[0].Active || mwiEvents[0].Count != 2 {
		t.Fatalf("mwiEvents=%+v, want 1 event with Active=true Count=2", mwiEvents)
	}

	// 2. Send NOTIFY Event: reg with state="terminated" event="deactivated" -> verify re-REGISTER!
	regDeactivatedXML := `<?xml version="1.0"?>` +
		`<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">` +
		`<registration aor="sip:310280233641503@ims.mnc280.mcc310.3gppnetwork.org" id="r1" state="terminated">` +
		`<contact id="c1" state="terminated" event="deactivated"><uri>sip:310280233641503@127.0.0.1:` + itoaTest(contactPort) + `</uri></contact>` +
		`</registration></reginfo>`
	regNotify1 := strings.Join([]string{
		"NOTIFY sip:310280233641503@127.0.0.1:" + itoaTest(contactPort) + " SIP/2.0",
		"Via: SIP/2.0/UDP " + notifySender.LocalAddr().String() + ";branch=z9hG4bK-reg-deact-1",
		"From: <sip:310280233641503@ims.mnc280.mcc310.3gppnetwork.org>;tag=scscf-sub",
		"To: <sip:310280233641503@ims.mnc280.mcc310.3gppnetwork.org>",
		"Call-ID: reg-notify-1",
		"CSeq: 2 NOTIFY",
		"Event: reg",
		"Subscription-State: terminated;reason=deactivated",
		"Content-Type: application/reginfo+xml",
		"Content-Length: " + itoaTest(len(regDeactivatedXML)),
		"",
		regDeactivatedXML,
	}, "\r\n")
	if _, err := notifySender.WriteTo([]byte(regNotify1), inboundTarget); err != nil {
		t.Fatalf("WriteTo reg deactivated NOTIFY: %v", err)
	}
	resp = readUDPSIPResponseTest(t, notifySender)
	if resp.StatusCode != 200 {
		t.Fatalf("reg deactivated NOTIFY status=%d, want 200", resp.StatusCode)
	}
	select {
	case <-reregisterSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for automatic re-REGISTER after reg-event deactivated NOTIFY")
	}

	// Drain post-recovery SUBSCRIBE before testing permanent rejection halt.
	select {
	case <-subscribeSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for post-recovery SUBSCRIBE Event: reg")
	}

	// 3. Send NOTIFY Event: reg with event="rejected" -> verify IMSReady becomes false!
	regRejectedXML := `<?xml version="1.0"?>` +
		`<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="2" state="full">` +
		`<registration aor="sip:310280233641503@ims.mnc280.mcc310.3gppnetwork.org" id="r1" state="terminated">` +
		`<contact id="c1" state="terminated" event="rejected"><uri>sip:310280233641503@127.0.0.1:` + itoaTest(contactPort) + `</uri></contact>` +
		`</registration></reginfo>`
	regNotify2 := strings.Join([]string{
		"NOTIFY sip:310280233641503@127.0.0.1:" + itoaTest(contactPort) + " SIP/2.0",
		"Via: SIP/2.0/UDP " + notifySender.LocalAddr().String() + ";branch=z9hG4bK-reg-rej-1",
		"From: <sip:310280233641503@ims.mnc280.mcc310.3gppnetwork.org>;tag=scscf-sub",
		"To: <sip:310280233641503@ims.mnc280.mcc310.3gppnetwork.org>",
		"Call-ID: reg-notify-2",
		"CSeq: 3 NOTIFY",
		"Event: reg",
		"Subscription-State: terminated;reason=rejected",
		"Content-Type: application/reginfo+xml",
		"Content-Length: " + itoaTest(len(regRejectedXML)),
		"",
		regRejectedXML,
	}, "\r\n")
	if _, err := notifySender.WriteTo([]byte(regNotify2), inboundTarget); err != nil {
		t.Fatalf("WriteTo reg rejected NOTIFY: %v", err)
	}
	resp = readUDPSIPResponseTest(t, notifySender)
	if resp.StatusCode != 200 {
		t.Fatalf("reg rejected NOTIFY status=%d, want 200", resp.StatusCode)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && inst.State().IMSReady {
		time.Sleep(10 * time.Millisecond)
	}
	if inst.State().IMSReady {
		t.Fatalf("State().IMSReady = true after event=rejected NOTIFY, want false (state=%+v)", inst.State())
	}
}

func TestRound2Critical2InboundListenerClosesUDPOnTCPFailureAndRebindsAcrossRecovery(t *testing.T) {
	// Part A: Occupy a TCP port, bind real UDP on the same port, verify bindIMSInboundUDPAndTCP closes existing UDP on TCP failure.
	occupiedTCP, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen occupiedTCP: %v", err)
	}
	defer occupiedTCP.Close()
	portAddr := occupiedTCP.Addr().String()

	existingUDP, err := net.ListenPacket("udp4", portAddr)
	if err != nil {
		t.Fatalf("ListenPacket existingUDP on %s: %v", portAddr, err)
	}
	if _, _, bindErr := bindIMSInboundUDPAndTCP("udp4", portAddr, existingUDP); bindErr == nil {
		t.Fatal("bindIMSInboundUDPAndTCP succeeded when TCP port was already occupied, want error")
	}
	if _, writeErr := existingUDP.WriteTo([]byte("probe"), occupiedTCP.Addr()); writeErr == nil {
		_ = existingUDP.Close()
		t.Fatal("existingUDP was left open after TCP bind failure, want closed")
	}

	// Part B: Verify applyIMSRegistrationResult closes old inbound socket and rebinds to new port-s across recovery/rekey.
	connA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket connA: %v", err)
	}
	addrA := connA.LocalAddr().String()

	dispatcher := &auditSyncDispatcher{}
	inst, err := Start(context.Background(), StartRequest{
		DeviceID: "dev-rebind-1",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
		Dispatch: dispatcher,
		IMSRegistrar: &testIMSRegistrar{
			result: IMSRegistrationResult{
				Registered: true,
				StatusCode: 200,
				Reason:     "OK",
				Profile: voiceclient.IMSProfile{
					IMPI:   "310280233641503@ims.mnc280.mcc310.3gppnetwork.org",
					IMPU:   "sip:310280233641503@ims.mnc280.mcc310.3gppnetwork.org",
					Domain: "ims.mnc280.mcc310.3gppnetwork.org",
				},
				Binding: voiceclient.RegistrationBinding{
					PublicIdentity: "sip:310280233641503@ims.mnc280.mcc310.3gppnetwork.org",
					ContactURI:     "sip:310280233641503@" + addrA,
				},
				Inbound: &IMSInboundConfig{
					Network:    "udp4",
					LocalAddr:  addrA,
					ContactURI: "sip:310280233641503@" + addrA,
					PacketConn: connA,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = inst.Stop(context.Background()) }()

	connB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket connB: %v", err)
	}
	addrB := connB.LocalAddr().String()

	inst.applyIMSRegistrationResult(context.Background(), IMSRegistrationResult{
		Registered: true,
		StatusCode: 200,
		Reason:     "rekeyed",
		Profile: voiceclient.IMSProfile{
			IMPI:   "310280233641503@ims.mnc280.mcc310.3gppnetwork.org",
			IMPU:   "sip:310280233641503@ims.mnc280.mcc310.3gppnetwork.org",
			Domain: "ims.mnc280.mcc310.3gppnetwork.org",
		},
		Binding: voiceclient.RegistrationBinding{
			PublicIdentity: "sip:310280233641503@ims.mnc280.mcc310.3gppnetwork.org",
			ContactURI:     "sip:310280233641503@" + addrB,
		},
		Inbound: &IMSInboundConfig{
			Network:    "udp4",
			LocalAddr:  addrB,
			ContactURI: "sip:310280233641503@" + addrB,
			PacketConn: connB,
		},
	}, "rekeyed", true)

	// Verify old port A was released (we can bind UDP on addrA again!).
	reclaimedA, err := net.ListenPacket("udp4", addrA)
	if err != nil {
		t.Fatalf("old inbound port %s was not closed on rebind: %v", addrA, err)
	}
	_ = reclaimedA.Close()

	// Verify new port B actively serves SIP MESSAGE!
	sender, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket sender: %v", err)
	}
	defer sender.Close()
	body := "rebound hello"
	rawMsg := strings.Join([]string{
		"MESSAGE sip:310280233641503@" + addrB + " SIP/2.0",
		"Via: SIP/2.0/UDP " + sender.LocalAddr().String() + ";branch=z9hG4bK-rebind-msg",
		"From: <sip:+18005551212@ims.mnc280.mcc310.3gppnetwork.org>;tag=s1",
		"To: <sip:310280233641503@ims.mnc280.mcc310.3gppnetwork.org>",
		"Call-ID: rebind-msg-1",
		"CSeq: 1 MESSAGE",
		"Content-Type: text/plain",
		"Content-Length: " + itoaTest(len(body)),
		"",
		body,
	}, "\r\n")
	addrBUDP, _ := net.ResolveUDPAddr("udp4", addrB)
	if _, err := sender.WriteTo([]byte(rawMsg), addrBUDP); err != nil {
		t.Fatalf("WriteTo addrB: %v", err)
	}
	msgResp := readUDPSIPResponseTest(t, sender)
	if msgResp.StatusCode != 200 {
		t.Fatalf("MESSAGE on rebound port B status=%d, want 200", msgResp.StatusCode)
	}
}

func TestRound2Critical5SharedDigestAuthSessionSyncAcrossSMSRefreshAndClose(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()

	rawNonce := append(runtimeBytesFrom(0x10, 16), runtimeBytesFrom(0x40, 16)...)
	challenge := `Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv1-MD5, qop="auth"`

	var mu sync.Mutex
	var authHeaders []string
	refreshTrigger := make(chan struct{}, 1)
	refreshDone := make(chan struct{}, 1)

	go func() {
		buf := make([]byte, 65535)
		step := 0
		for {
			_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, addr, rErr := pc.ReadFrom(buf)
			if rErr != nil {
				return
			}
			req, pErr := voiceclient.ParseSIPRequest(buf[:n])
			if pErr != nil {
				continue
			}
			step++
			via := firstRuntimeSIPHeaderCI(req.Headers, "Via", "v")
			from := firstRuntimeSIPHeaderCI(req.Headers, "From", "f")
			to := firstRuntimeSIPHeaderCI(req.Headers, "To", "t")
			callID := firstRuntimeSIPHeaderCI(req.Headers, "Call-ID", "i")
			cseq := firstRuntimeSIPHeaderCI(req.Headers, "CSeq")
			authz := firstRuntimeSIPHeaderCI(req.Headers, "Authorization")

			if step == 1 {
				resp := "SIP/2.0 401 Unauthorized\r\n" +
					"Via: " + via + "\r\n" +
					"From: " + from + "\r\n" +
					"To: " + to + ";tag=s1\r\n" +
					"Call-ID: " + callID + "\r\n" +
					"CSeq: " + cseq + "\r\n" +
					"WWW-Authenticate: " + challenge + "\r\n" +
					"Content-Length: 0\r\n\r\n"
				_, _ = pc.WriteTo([]byte(resp), addr)
				continue
			}

			mu.Lock()
			authHeaders = append(authHeaders, req.Method+" "+authz)
			count := len(authHeaders)
			mu.Unlock()

			if req.Method == "MESSAGE" {
				rpAck := messaging.BuildSMSRPAck(0x01)
				resp := "SIP/2.0 200 OK\r\n" +
					"Via: " + via + "\r\n" +
					"From: " + from + "\r\n" +
					"To: " + to + ";tag=s1\r\n" +
					"Call-ID: " + callID + "\r\n" +
					"CSeq: " + cseq + "\r\n" +
					"Content-Type: " + messaging.IMS3GPPSMSContentType + "\r\n" +
					"Content-Length: " + itoaTest(len(rpAck)) + "\r\n\r\n" +
					string(rpAck)
				_, _ = pc.WriteTo([]byte(resp), addr)
				continue
			}

			resp := "SIP/2.0 200 OK\r\n" +
				"Via: " + via + "\r\n" +
				"From: " + from + "\r\n" +
				"To: " + to + ";tag=s1\r\n" +
				"Call-ID: " + callID + "\r\n" +
				"CSeq: " + cseq + "\r\n" +
				"P-Associated-URI: <sip:310280233641503@ims.mnc280.mcc310.3gppnetwork.org>\r\n" +
				"Contact: <sip:310280233641503@192.0.2.10:5060>;expires=60\r\n" +
				"Content-Length: 0\r\n\r\n"
			_, _ = pc.WriteTo([]byte(resp), addr)
			if count == 3 {
				select {
				case refreshDone <- struct{}{}:
				default:
				}
			}
			if strings.Contains(string(buf[:n]), "Expires: 0\r\n") {
				return
			}
		}
	}()

	res, err := WireIMSRegistrar{
		Network:             "udp4",
		ServerAddr:          pc.LocalAddr().String(),
		ContactHost:         "192.0.2.10",
		ContactPort:         5060,
		Expires:             60,
		RefreshInterval:     40 * time.Millisecond,
		DisableKeepalive:    true,
		DisableRegSubscribe: true,
		Timeout:             time.Second,
		CNonce:              "cnonce-sync",
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-nc-sync",
		TraceID:  "trace-nc-sync",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280", SMSC: "+12063130004"},
		SIM:      &wireIMSRegistrarSIM{},
	})
	_ = refreshTrigger
	if err != nil {
		t.Fatalf("RegisterIMS: %v", err)
	}

	// Immediately send MO SMS (consumes nc=00000002), then wait for background refresh (must use nc=00000003!), then send MO SMS #2 (nc=00000004), then Close/Deregister (nc=00000005)!
	if _, err := res.SMSTransport.SendSMSPart(context.Background(), messaging.SMSSendRequest{
		Peer:      "+18005551212",
		MessageID: "sms-1",
		Part:      messaging.SMSPart{PartNo: 1, TotalParts: 1, Text: "one"},
	}); err != nil {
		t.Fatalf("SendSMSPart 1: %v", err)
	}

	select {
	case <-refreshDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for background refresh")
	}

	if _, err := res.SMSTransport.SendSMSPart(context.Background(), messaging.SMSSendRequest{
		Peer:      "+18005551212",
		MessageID: "sms-2",
		Part:      messaging.SMSPart{PartNo: 1, TotalParts: 1, Text: "two"},
	}); err != nil {
		t.Fatalf("SendSMSPart 2: %v", err)
	}

	if err := res.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	mu.Lock()
	got := append([]string(nil), authHeaders...)
	mu.Unlock()
	if len(got) < 5 {
		t.Fatalf("authenticated requests=%d %+v, want >= 5", len(got), got)
	}
	wantNCs := []string{"nc=00000001", "nc=00000002", "nc=00000003", "nc=00000004", "nc=00000005"}
	for idx, wantNC := range wantNCs {
		if !strings.Contains(got[idx], wantNC) {
			t.Fatalf("authHeaders[%d]=%q, want %s (all=%+v)", idx, got[idx], wantNC, got)
		}
	}
}

func TestRound2High1RecoverRegistrationDoesNotWedgeAfterFailedRecoveryAndNoProfileRace(t *testing.T) {
	transport := &wireIMSRegistrarTransport{
		responses: []voiceclient.RegisterResponse{
			// 1. Recovery #1 returns 200 without Contact binding? Or non-error unregistered result?
			// Simulate transient 503 failure followed by unregistered status and then 200 OK!
			{StatusCode: 503, Reason: "Service Unavailable"},
			{
				StatusCode: 200,
				Reason:     "OK",
				Headers: map[string][]string{
					"Contact":          {"<sip:310280233641503@192.0.2.10:5060>;expires=600"},
					"P-Associated-URI": {"<sip:310280233641503@ims.mnc280.mcc310.3gppnetwork.org>"},
				},
			},
		},
	}
	cfg := IMSRegistrationConfig{
		DeviceID: "dev-wedge",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
	}
	reg := WireIMSRegistrar{
		ContactHost:      "192.0.2.10",
		ContactPort:      5060,
		DisableRefresh:   true,
		DisableKeepalive: true,
	}
	profile, err := reg.profileFromConfig(cfg)
	if err != nil {
		t.Fatalf("profileFromConfig: %v", err)
	}
	session := reg.registerSession(cfg, profile, "sip:ims.mnc280.mcc310.3gppnetwork.org", "sip:310280233641503@192.0.2.10:5060", transport, 600)
	flow := &voiceclient.WireSIPFlow{Network: "udp4", ServerAddr: "127.0.0.1:9"}
	defer flow.Close()

	m := newIMSRegistrationMaintenance(flow, session, voiceclient.RegisterResult{
		Registered: false, // Simulate prior recovery having set m.registered = false!
		StatusCode: 503,
		Reason:     "Service Unavailable",
	}, reg, cfg, profile, time.Now())

	// Concurrent m.result() readers to verify zero data race on m.profile!
	doneReaders := make(chan struct{})
	go func() {
		defer close(doneReaders)
		for i := 0; i < 25; i++ {
			_ = m.result("snapshot")
		}
	}()

	// First Recover fails with 503 while m.registered is already false.
	if _, err := m.Recover(context.Background()); err == nil {
		t.Fatal("first Recover() succeeded unexpectedly, want 503 error")
	}
	// Second Recover MUST NOT wedge even though m.registered == false!
	recovered, err := m.Recover(context.Background())
	if err != nil || !recovered.Registered {
		t.Fatalf("second Recover() = (%+v, %v), want Registered=true", recovered, err)
	}
	<-doneReaders
}

func TestRound2High4AndHigh8SIPURIHelpersAndLeadingZeroMNC(t *testing.T) {
	phoneCtxV6 := "<sips:+15551234567;phone-context=ims.mnc001.mcc001.3gppnetwork.org@[2001:db8::10]:5062;user=phone;transport=tls>"
	if got := sipURIHostLiteral(phoneCtxV6); got != "2001:db8::10" {
		t.Fatalf("sipURIHostLiteral = %q, want 2001:db8::10", got)
	}
	if got := sipURIPortNumber(phoneCtxV6); got != 5062 {
		t.Fatalf("sipURIPortNumber = %d, want 5062", got)
	}
	if isV6, ok := runtimeEndpointIPIsV6(phoneCtxV6); !ok || !isV6 {
		t.Fatalf("runtimeEndpointIPIsV6 = (%v, %v), want (true, true)", isV6, ok)
	}
	if got := sipUser(phoneCtxV6); got != "+15551234567" {
		t.Fatalf("sipUser(phoneCtxV6) = %q, want +15551234567", got)
	}
	if got := sipUser("tel:+15559876543;phone-context=ims.example.com"); got != "+15559876543" {
		t.Fatalf("sipUser(tel:) = %q, want +15559876543", got)
	}
	if got := sipDomainRuntime("<sip:ims.mnc01.mcc001.3gppnetwork.org:5060;lr>"); got != "ims.mnc01.mcc001.3gppnetwork.org" {
		t.Fatalf("sipDomainRuntime(host-only) = %q", got)
	}
	if got := sipDomainRuntime(phoneCtxV6); got != "2001:db8::10" {
		t.Fatalf("sipDomainRuntime(phoneCtxV6) = %q, want 2001:db8::10", got)
	}
	if got := sipDomainRuntime("tel:+15551234567"); got != "" {
		t.Fatalf("sipDomainRuntime(tel:) = %q, want empty", got)
	}

	// MEDIUM-2: refreshedISIMPublicIdentity prefers sip:/sips: over tel:
	pickedIMPU := refreshedISIMPublicIdentity(identity.Identity{
		IMPI:   "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
		IMPU:   []string{"tel:+15551234567", "sip:+15551234567@ims.mnc001.mcc001.3gppnetwork.org"},
		Domain: "ims.mnc001.mcc001.3gppnetwork.org",
	}, identity.Profile{IMSI: "001010123456789"})
	if pickedIMPU != "sip:+15551234567@ims.mnc001.mcc001.3gppnetwork.org" {
		t.Fatalf("refreshedISIMPublicIdentity = %q, want sip: URI over tel:", pickedIMPU)
	}

	// HIGH-8: cfgMCCMNC preserves leading-zero 2-digit and 3-digit MNCs!
	for _, tc := range []struct {
		cfg     IMSRegistrationConfig
		wantMCC string
		wantMNC string
	}{
		{
			cfg:     IMSRegistrationConfig{Profile: identity.Profile{IMSI: "208011234567890", MCC: "208", MNC: "01", MNCLength: 2}},
			wantMCC: "208",
			wantMNC: "01",
		},
		{
			cfg:     IMSRegistrationConfig{Profile: identity.Profile{IMSI: "001001123456789", MCC: "001", MNC: "001", MNCLength: 3}},
			wantMCC: "001",
			wantMNC: "001",
		},
		{
			cfg:     IMSRegistrationConfig{Profile: identity.Profile{IMSI: "310007123456789", MNCLength: 3}},
			wantMCC: "310",
			wantMNC: "007",
		},
	} {
		mcc, mnc := cfgMCCMNC(tc.cfg)
		if mcc != tc.wantMCC || mnc != tc.wantMNC {
			t.Fatalf("cfgMCCMNC(%+v) = (%q, %q), want (%q, %q)", tc.cfg.Profile, mcc, mnc, tc.wantMCC, tc.wantMNC)
		}
	}
}

type closingMockRegisterTransport struct {
	mu        sync.Mutex
	closed    int
	responses []voiceclient.RegisterResponse
}

func (t *closingMockRegisterTransport) RoundTripRegister(_ context.Context, _ voiceclient.RegisterMessage) (voiceclient.RegisterResponse, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.responses) == 0 {
		return voiceclient.RegisterResponse{StatusCode: 500, Reason: "empty"}, nil
	}
	out := t.responses[0]
	t.responses = t.responses[1:]
	return out, nil
}

func (t *closingMockRegisterTransport) Close() error {
	t.mu.Lock()
	t.closed++
	t.mu.Unlock()
	return nil
}

func TestRound2High10RegisterIMS403RefreshCleansSecurityPlansAndRecreatesTransport(t *testing.T) {
	rawNonce := append(runtimeBytesFrom(0x10, 16), runtimeBytesFrom(0x40, 16)...)
	challenge := `Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv1-MD5, qop="auth"`

	t1 := &closingMockRegisterTransport{
		responses: []voiceclient.RegisterResponse{
			{
				StatusCode: 401,
				Reason:     "Unauthorized",
				Headers: map[string][]string{
					"WWW-Authenticate": {challenge},
					"Security-Server":  {"ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=101;spi-s=202;port-c=5062;port-s=5063"},
				},
			},
			{StatusCode: 403, Reason: "Forbidden"},
		},
	}
	t2 := &closingMockRegisterTransport{
		responses: []voiceclient.RegisterResponse{
			{
				StatusCode: 200,
				Reason:     "OK",
				Headers: map[string][]string{
					"Contact":          {"<sip:refreshed@192.0.2.10:5060>;expires=600"},
					"P-Associated-URI": {"<sip:refreshed@ims.refreshed.example>"},
				},
			},
		},
	}
	factoryCalls := 0
	installer := &wireIMSRegistrarSecurityInstaller{}
	access := &wireIMSRegistrarAccess{
		id: identity.Identity{
			IMPI:   "refreshed@ims.refreshed.example",
			IMPU:   []string{"sip:refreshed@ims.refreshed.example"},
			Domain: "ims.refreshed.example",
		},
	}

	res, err := WireIMSRegistrar{
		ContactHost:           "192.0.2.10",
		ContactPort:           5060,
		DisableRefresh:        true,
		DisableKeepalive:      true,
		SecurityPlanInstaller: installer,
		TransportFactory: func(IMSRegistrationConfig, voiceclient.IMSProfile, string, string) voiceclient.SIPRegisterTransport {
			factoryCalls++
			if factoryCalls == 1 {
				return t1
			}
			return t2
		},
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-403-cleanup",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
		SIM:      &wireIMSRegistrarSIM{},
		Access:   access,
	})
	if err != nil || !res.Registered {
		t.Fatalf("RegisterIMS = (%+v, %v), want Registered=true", res, err)
	}
	if installer.cleanupCalls != 1 {
		t.Fatalf("installer.cleanupCalls = %d, want 1 cleanup of attempt-1 security plans before attempt-2", installer.cleanupCalls)
	}
	if t1.closed != 1 {
		t.Fatalf("attempt-1 transport closed = %d, want 1", t1.closed)
	}
}

func TestRound2Medium4UnnegotiatedUDPDoesNotSendUnsolicitedCRLFKeepalive(t *testing.T) {
	flow := &voiceclient.WireSIPFlow{Network: "udp4", ServerAddr: "127.0.0.1:9"}
	defer flow.Close()

	m := &imsRegistrationMaintenance{
		flow:       flow,
		config:     WireIMSRegistrar{Network: "udp4"},
		registered: true,
		binding:    voiceclient.RegistrationBinding{KeepaliveNegotiated: false},
	}
	if m.shouldSendCRLFKeepalive() {
		t.Fatal("shouldSendCRLFKeepalive() = true on unnegotiated UDP, want false")
	}

	m.binding.KeepaliveNegotiated = true
	m.binding.FlowTimer = 15
	if !m.shouldSendCRLFKeepalive() {
		t.Fatal("shouldSendCRLFKeepalive() = false when KeepaliveNegotiated=true, want true")
	}
	if got := m.keepaliveInterval(); got != 15*time.Second {
		t.Fatalf("keepaliveInterval() = %v, want 15s from FlowTimer", got)
	}

	mTCP := &imsRegistrationMaintenance{
		flow:       flow,
		config:     WireIMSRegistrar{Network: "tcp4"},
		registered: true,
	}
	if !mTCP.shouldSendCRLFKeepalive() {
		t.Fatal("shouldSendCRLFKeepalive() = false on TCP stream flow, want true")
	}
}

func TestRound2VH01InboundCallByeAndHoldRoutedThroughRuntimeVoiceGateway(t *testing.T) {
	inboundConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket inbound: %v", err)
	}
	inboundAddr := inboundConn.LocalAddr().String()

	gw := voicehost.NewGateway()
	gw.SetClientAdapter(auditVoiceClientAdapter{
		contactURI: "sip:client@127.0.0.1:5096",
		contactIP:  "127.0.0.1",
		username:   "client",
	})
	clientTransport := &auditLocalClientSIPTransport{}
	imsSDP := voicehost.BuildSDPAnswer(voicehost.SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 34000, Payloads: []int{0}})
	imsUACTransport := &runtimeVoiceTransport{
		responses: []voiceclient.SIPResponse{
			{
				StatusCode: 200,
				Reason:     "OK",
				Headers:    map[string][]string{"Content-Type": {"application/sdp"}},
				Body:       imsSDP,
			},
			{
				StatusCode: 200,
				Reason:     "OK",
			},
		},
	}

	inst, err := Start(context.Background(), StartRequest{
		DeviceID:             "dev-mt-uac",
		VoiceGateway:         gw,
		VoiceClientTransport: clientTransport,
		VoiceTransport:       imsUACTransport,
		VoiceMediaRelay: &voicehost.RTPRelayConfig{
			ClientListenIP:    "127.0.0.1",
			ClientAdvertiseIP: "127.0.0.1",
		},
		IMSRegistrar: &testIMSRegistrar{
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
				Inbound: &IMSInboundConfig{
					Network:    "udp4",
					LocalAddr:  inboundAddr,
					ContactURI: "sip:+18005550100@" + inboundAddr,
					PacketConn: inboundConn,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = inst.Stop(context.Background()) }()

	imsCaller, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket imsCaller: %v", err)
	}
	defer imsCaller.Close()

	inviteSDP := string(imsSDP)
	rawInvite := strings.Join([]string{
		"INVITE sip:+18005550100@" + inboundAddr + " SIP/2.0",
		"Via: SIP/2.0/UDP " + imsCaller.LocalAddr().String() + ";branch=z9hG4bK-mt-vh01-inv",
		"Record-Route: <sip:p1.ims.example;lr>, <sip:s1.ims.example;lr>",
		"From: <sip:+18005559999@ims.mnc001.mcc001.3gppnetwork.org>;tag=ims-caller-tag",
		"To: <sip:+18005550100@ims.mnc001.mcc001.3gppnetwork.org>",
		"Call-ID: mt-vh01-call-1",
		"CSeq: 10 INVITE",
		"Contact: <sip:caller@" + imsCaller.LocalAddr().String() + ">",
		"Content-Type: application/sdp",
		"Content-Length: " + itoaTest(len(inviteSDP)),
		"",
		inviteSDP,
	}, "\r\n")
	if _, err := imsCaller.WriteTo([]byte(rawInvite), inboundConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo INVITE: %v", err)
	}

	var okResp voiceclient.SIPResponse
	for {
		r := readUDPSIPResponseTest(t, imsCaller)
		if r.StatusCode >= 200 {
			okResp = r
			break
		}
	}
	if okResp.StatusCode != 200 {
		t.Fatalf("inbound INVITE final status=%d, want 200", okResp.StatusCode)
	}
	// VH-02: Verify Record-Route is echoed on 200 OK!
	if rr := firstRuntimeSIPHeaderCI(okResp.Headers, "Record-Route"); !strings.Contains(rr, "p1.ims.example") {
		t.Fatalf("200 OK missing echoed Record-Route, headers=%+v", okResp.Headers)
	}
	toHeader := firstRuntimeSIPHeaderCI(okResp.Headers, "To", "t")
	rawAck := strings.Join([]string{
		"ACK sip:+18005550100@" + inboundAddr + " SIP/2.0",
		"Via: SIP/2.0/UDP " + imsCaller.LocalAddr().String() + ";branch=z9hG4bK-mt-vh01-ack",
		"From: <sip:+18005559999@ims.mnc001.mcc001.3gppnetwork.org>;tag=ims-caller-tag",
		"To: " + toHeader,
		"Call-ID: mt-vh01-call-1",
		"CSeq: 10 ACK",
		"Content-Length: 0",
		"",
		"",
	}, "\r\n")
	_, _ = imsCaller.WriteTo([]byte(rawAck), inboundConn.LocalAddr())
	time.Sleep(25 * time.Millisecond)

	// Local client puts inbound call on hold and then hangs up via Gateway / Instance!
	holdRes, err := inst.SendDialogHold(context.Background(), voicehost.DialogHoldRequest{
		DeviceID: "dev-mt-uac",
		CallID:   "mt-vh01-call-1",
	})
	if err != nil || !holdRes.Accepted {
		t.Fatalf("SendDialogHold on inbound call = (%+v, %v), want Accepted=true", holdRes, err)
	}
	if err := inst.EndVoiceCall(context.Background(), voicehost.DialogInfo{
		DeviceID: "dev-mt-uac",
		CallID:   "mt-vh01-call-1",
	}); err != nil {
		t.Fatalf("inst.EndVoiceCall on inbound call error = %v", err)
	}
	if len(imsUACTransport.requests) < 2 {
		t.Fatalf("imsUACTransport.requests = %d, want >= 2 (hold + BYE)", len(imsUACTransport.requests))
	}
	byeReq := imsUACTransport.requests[len(imsUACTransport.requests)-1]
	if byeReq.Method != "BYE" {
		t.Fatalf("last IMS UAC request method = %q, want BYE", byeReq.Method)
	}
	// VH-01: UAS route set MUST preserve Record-Route order (p1 before s1, unreversed)!
	route := byeReq.Headers["Route"]
	p1Idx := strings.Index(route, "p1.ims.example")
	s1Idx := strings.Index(route, "s1.ims.example")
	if p1Idx < 0 || s1Idx < 0 || p1Idx > s1Idx {
		t.Fatalf("BYE Route = %q, want unreversed <sip:p1.ims.example;lr>, <sip:s1.ims.example;lr>", route)
	}
}

func readUDPSIPResponseTest(t *testing.T, pc net.PacketConn) voiceclient.SIPResponse {
	t.Helper()
	buf := make([]byte, 65535)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom UDP SIP response: %v", err)
	}
	resp, err := voiceclient.ParseSIPResponse(buf[:n])
	if err != nil {
		t.Fatalf("ParseSIPResponse(%q): %v", string(buf[:n]), err)
	}
	return resp
}

func itoaTest(n int) string {
	return strconv.Itoa(n)
}
