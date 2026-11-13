package voiceclient

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kimoju/vowifi-go/engine/sim"
)

func TestRegInfoParseAndEvaluateNotify(t *testing.T) {
	xmlRaw := []byte(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="3" state="full">
  <registration aor="sip:+12065550100@ims.mnc260.mcc310.3gppnetwork.org" id="reg1" state="active">
    <contact id="c1" state="terminated" event="deactivated" retry-after="15">
      <uri>sip:+12065550100@192.0.2.20:5062;transport=udp</uri>
    </contact>
  </registration>
</reginfo>`)

	doc, err := ParseRegInfoXML(xmlRaw)
	if err != nil {
		t.Fatalf("ParseRegInfoXML() error = %v", err)
	}
	if !doc.HasVersion || doc.Version != 3 || doc.State != "full" || len(doc.Registrations) != 1 {
		t.Fatalf("unexpected doc = %+v", doc)
	}

	subState, err := ParseSubscriptionStateHeader(`active;expires=599900`)
	if err != nil {
		t.Fatalf("ParseSubscriptionStateHeader() error = %v", err)
	}
	eval := EvaluateRegEventNotify(subState, &doc, "<sip:+12065550100@192.0.2.20:5062>")
	if eval.Action != RegEventActionReRegister || eval.RetryAfter != 15*time.Second || eval.Version != 3 {
		t.Fatalf("EvaluateRegEventNotify(deactivated) = %+v", eval)
	}

	rejectedXML := []byte(`<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="4" state="partial">
  <registration aor="sip:+12065550100@ims.example" id="reg1" state="terminated">
    <contact id="c1" state="terminated" event="rejected">
      <uri>sip:+12065550100@192.0.2.20:5062</uri>
    </contact>
  </registration>
</reginfo>`)
	rejectedDoc, err := ParseRegInfoXML(rejectedXML)
	if err != nil {
		t.Fatalf("ParseRegInfoXML(rejected) error = %v", err)
	}
	rejectedEval := EvaluateRegEventNotify(subState, &rejectedDoc, "sip:+12065550100@192.0.2.20:5062")
	if rejectedEval.Action != RegEventActionHalt {
		t.Fatalf("EvaluateRegEventNotify(rejected) = %+v, want halt", rejectedEval)
	}

	termSub, err := ParseSubscriptionStateHeader(`terminated;reason=probation;retry-after=10`)
	if err != nil {
		t.Fatalf("ParseSubscriptionStateHeader(terminated) error = %v", err)
	}
	termEval := EvaluateRegEventNotify(termSub, nil, "sip:+12065550100@192.0.2.20:5062")
	if termEval.Action != RegEventActionReRegister || termEval.RetryAfter != 10*time.Second {
		t.Fatalf("EvaluateRegEventNotify(terminated probation) = %+v", termEval)
	}

	subReq, err := BuildSubscribeRequest(DialogRequestConfig{
		Profile: IMSProfile{
			Domain: "ims.example",
			IMPU:   "sip:+12065550100@ims.example",
		},
		ContactURI:      "<sip:+12065550100@192.0.2.20:5062>",
		LocalURI:        "sip:+12065550100@ims.example",
		RemoteURI:       "sip:+12065550100@ims.example",
		RemoteTargetURI: "sip:+12065550100@ims.example",
		CallID:          "reg-sub-1",
		LocalTag:        "tag-1",
		CSeq:            1,
	}, "reg", "600000", "", nil)
	if err != nil {
		t.Fatalf("BuildSubscribeRequest(reg) error = %v", err)
	}
	if subReq.Headers["Accept"] != "application/reginfo+xml" || !strings.Contains(subReq.Headers["Allow-Events"], "reg") {
		t.Fatalf("BuildSubscribeRequest(reg) headers = %+v", subReq.Headers)
	}
}

func TestSecurityXFRMRefreshDeletesSupersededSAsAndCleanupIsIdempotent(t *testing.T) {
	req1 := validSecurityXFRMInstallRequest()
	req2 := validSecurityXFRMInstallRequest()
	req2.Plan.SPIClient = 0x11111111
	req2.Plan.SPIServer = 0x22222222
	req2.Plan.Inbound.SPI = 0x11111111
	req2.Plan.Outbound.SPI = 0x22222222
	req2.Agreement.SPIClient = 0x11111111
	req2.Agreement.SPIServer = 0x22222222

	var seen [][]string
	runner := IMSSecurityXFRMCommandRunnerFunc(func(_ context.Context, args ...string) error {
		seen = append(seen, append([]string(nil), args...))
		if len(args) >= 3 && args[1] == "policy" && args[2] == "delete" {
			return syscall.ENOENT
		}
		return nil
	})
	installer := &LinuxIMSSecurityXFRMInstaller{Runner: runner}
	st1, err := installer.Apply(context.Background(), req1)
	if err != nil {
		t.Fatalf("Apply(1) error = %v", err)
	}
	st2, err := installer.Apply(context.Background(), req2)
	if err != nil {
		t.Fatalf("Apply(2) error = %v", err)
	}
	if st1.Plan.ReqID == st2.Plan.ReqID {
		t.Fatalf("expected distinct ReqIDs across installs, both got %d", st1.Plan.ReqID)
	}
	if installer.StateCount() != 1 {
		t.Fatalf("StateCount() = %d, want 1", installer.StateCount())
	}

	deletedOldSPI := false
	for _, cmd := range seen {
		if len(cmd) >= 11 && cmd[1] == "state" && cmd[2] == "delete" && cmd[10] == "0x0a0b0c0d" {
			deletedOldSPI = true
		}
	}
	if !deletedOldSPI {
		t.Fatalf("expected old SPI 0x0a0b0c0d to be deleted on refresh, commands=%v", seen)
	}

	if err := installer.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() with ENOENT should succeed idempotently, got %v", err)
	}
	if installer.StateCount() != 0 {
		t.Fatalf("StateCount(after cleanup) = %d, want 0", installer.StateCount())
	}
}

func TestUDPToTCPAutomaticFallbackOver1300BytesAndTransportParam(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen(tcp) error = %v", err)
	}
	defer ln.Close()

	tcpSeen := make(chan string, 2)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				raw, err := readSIPStreamMessage(r)
				if err != nil {
					return
				}
				req, err := ParseSIPRequest(raw)
				if err != nil {
					return
				}
				tcpSeen <- string(raw)
				respWire, _ := BuildSIPResponseWire(req, 200, "OK", map[string]string{
					"To": firstHeader(req.Headers, "To") + ";tag=srv",
				}, nil)
				_, _ = c.Write(respWire)
			}(conn)
		}
	}()

	largeBody := []byte(strings.Repeat("a=fmtp:96 mode-set=0,1,2,3,4,5,6,7,8\r\n", 40))
	transport := WireSIPTransport{
		Network:    "udp",
		ServerAddr: ln.Addr().String(),
		Timeout:    2 * time.Second,
	}
	resp, err := transport.RoundTripRequest(context.Background(), SIPRequestMessage{
		Method: "INVITE",
		URI:    "sip:callee@ims.example",
		Headers: map[string]string{
			"From":         "<sip:caller@ims.example>;tag=loc1",
			"To":           "<sip:callee@ims.example>",
			"Call-ID":      "large-udp-fallback",
			"CSeq":         "1 INVITE",
			"Contact":      "<sip:caller@127.0.0.1:5060>",
			"Content-Type": "application/sdp",
			"Max-Forwards": "70",
		},
		Body: largeBody,
	})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("RoundTripRequest(>1300B) resp=%+v err=%v", resp, err)
	}
	select {
	case wire := <-tcpSeen:
		if !strings.Contains(wire, "Via: SIP/2.0/TCP ") {
			t.Fatalf("expected TCP Via on fallback wire, got %q", wire)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for TCP fallback request")
	}

	flow := &WireSIPFlow{
		Network:    "udp",
		ServerAddr: ln.Addr().String(),
		Timeout:    2 * time.Second,
	}
	defer flow.Close()
	resp2, err := flow.RoundTripRequest(context.Background(), SIPRequestMessage{
		Method: "OPTIONS",
		URI:    "sip:ims.example;transport=tcp",
		Headers: map[string]string{
			"From":         "<sip:caller@ims.example>;tag=loc2",
			"To":           "<sip:ims.example>",
			"Call-ID":      "explicit-tcp-param",
			"CSeq":         "1 OPTIONS",
			"Max-Forwards": "70",
		},
	})
	if err != nil || resp2.StatusCode != 200 {
		t.Fatalf("WireSIPFlow ;transport=tcp resp=%+v err=%v", resp2, err)
	}
}

func TestSharedDigestAuthSessionAcrossDialogAndRefresh(t *testing.T) {
	challenge := DigestChallenge{
		Realm:     "ims.example",
		Nonce:     "bm9uY2UtMQ==",
		Algorithm: "MD5",
		QOP:       "auth",
	}
	input := DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "user@ims.example",
		Password: "secret",
		CNonce:   "cnonce1",
		NC:       1,
	}
	hdr, err := BuildDigestAuthorization(challenge, input)
	if err != nil {
		t.Fatalf("BuildDigestAuthorization() error = %v", err)
	}
	state := newDigestAuthState("Authorization", challenge, input, hdr)
	shared := NewDigestAuthSession("Authorization", hdr, state)

	// Simulate an INVITE incrementing nc -> 00000002.
	_, inviteAuth, err := shared.Next("INVITE", "sip:callee@ims.example")
	if err != nil || !strings.Contains(inviteAuth, "nc=00000002") {
		t.Fatalf("shared.Next(INVITE) = %q, err = %v", inviteAuth, err)
	}

	// Simulate Refresh using the same RegistrationBinding.AuthSession -> must emit nc=00000003!
	var seenAuth string
	regTransport := roundTripRegisterFunc(func(_ context.Context, msg RegisterMessage) (RegisterResponse, error) {
		seenAuth = msg.Headers["Authorization"]
		return RegisterResponse{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"Contact":       {msg.Headers["Contact"] + ";expires=600"},
				"Service-Route": {"<sip:new-scscf.ims.example;lr>"},
			},
		}, nil
	})

	sess := &RegisterSession{
		Transport:    regTransport,
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		Profile: IMSProfile{
			Domain: "ims.example",
			IMPI:   "user@ims.example",
			IMPU:   "sip:user@ims.example",
		},
	}
	refreshed, err := sess.Refresh(context.Background(), RefreshRequest{
		CallID:  "reg-call-1",
		CSeq:    2,
		Expires: 600,
		Binding: RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@ims.example",
			ServiceRoutes:  []string{"<sip:old-scscf.ims.example;lr>"},
			AuthSession:    shared,
		},
		AuthState: state, // stale snapshot with nextNC=2
	})
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if !strings.Contains(seenAuth, "nc=00000003") {
		t.Fatalf("expected Refresh to use shared nc=00000003, got %q", seenAuth)
	}
	if refreshed.Binding.AuthSession != shared {
		t.Fatal("expected Refresh to preserve shared AuthSession pointer")
	}
	// MEDIUM-1: ServiceRoutes must be replaced, not appended.
	if len(refreshed.Binding.ServiceRoutes) != 1 || refreshed.Binding.ServiceRoutes[0] != "<sip:new-scscf.ims.example;lr>" {
		t.Fatalf("ServiceRoutes = %v, want authoritative replacement", refreshed.Binding.ServiceRoutes)
	}

	// Next dialog request must continue at nc=00000004!
	_, msgAuth, err := shared.Next("MESSAGE", "sip:smsc@ims.example")
	if err != nil || !strings.Contains(msgAuth, "nc=00000004") {
		t.Fatalf("shared.Next(MESSAGE) = %q, err = %v", msgAuth, err)
	}
}

type roundTripRegisterFunc func(context.Context, RegisterMessage) (RegisterResponse, error)

func (f roundTripRegisterFunc) RoundTripRegister(ctx context.Context, msg RegisterMessage) (RegisterResponse, error) {
	return f(ctx, msg)
}

func TestFreshViaBranchOnDigestRetryAndRoundTripResult(t *testing.T) {
	var seenVias []string
	var seenCSeqs []string
	challengeHdr := `Digest realm="ims.example", nonce="bm9uY2UtMg==", algorithm=MD5, qop="auth"`
	sess := NewDigestAuthSessionWithChallengeInput("Authorization", "", DigestAuthState{}, func(_ DigestChallenge, _ string) (DigestAuthInput, error) {
		return DigestAuthInput{
			Username: "user@ims.example",
			Password: "pw",
			CNonce:   "cn1",
		}, nil
	})
	transport := fakeSIPRequestTransportFunc{
		roundTrip: func(_ context.Context, msg SIPRequestMessage) (SIPResponse, error) {
			seenVias = append(seenVias, msg.Headers["Via"])
			seenCSeqs = append(seenCSeqs, msg.Headers["CSeq"])
			if len(seenCSeqs) == 1 {
				return SIPResponse{
					StatusCode: 401,
					Reason:     "Unauthorized",
					Headers: map[string][]string{
						"Via":              {msg.Headers["Via"]},
						"WWW-Authenticate": {challengeHdr},
					},
				}, nil
			}
			return SIPResponse{
				StatusCode: 200,
				Reason:     "OK",
				Headers:    map[string][]string{"Via": {msg.Headers["Via"]}},
			}, nil
		},
	}

	resp, finalReq, err := RoundTripRequestWithDigestAuthResult(context.Background(), transport, SIPRequestMessage{
		Method:      "INVITE",
		URI:         "sip:callee@ims.example",
		AuthSession: sess,
		Headers: map[string]string{
			"Via":     "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKinitialbranch;rport",
			"From":    "<sip:user@ims.example>;tag=f1",
			"To":      "<sip:callee@ims.example>",
			"Call-ID": "call-branch-test",
			"CSeq":    "10 INVITE",
		},
	})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("RoundTripRequestWithDigestAuthResult resp=%+v err=%v", resp, err)
	}
	if len(seenVias) != 2 || seenVias[0] == seenVias[1] {
		t.Fatalf("expected fresh Via branch on Digest retry, got %v", seenVias)
	}
	if finalReq.Headers["CSeq"] != "11 INVITE" || finalReq.Headers["Via"] != seenVias[1] {
		t.Fatalf("finalReq headers = %+v", finalReq.Headers)
	}
}

type fakeSIPRequestTransportFunc struct {
	roundTrip func(context.Context, SIPRequestMessage) (SIPResponse, error)
	write     func(context.Context, SIPRequestMessage) error
}

func (f fakeSIPRequestTransportFunc) RoundTripRequest(ctx context.Context, msg SIPRequestMessage) (SIPResponse, error) {
	return f.roundTrip(ctx, msg)
}

func (f fakeSIPRequestTransportFunc) WriteRequest(ctx context.Context, msg SIPRequestMessage) error {
	if f.write != nil {
		return f.write(ctx, msg)
	}
	return nil
}

func TestStreamFramingMixedCRLFAndMissingContentLength(t *testing.T) {
	rawNoCL := "SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK1\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:c@d>;tag=2\r\nCall-ID: cid1\r\nCSeq: 1 OPTIONS\r\n\r\nTRAILING"
	_, err := readSIPStreamMessage(bufio.NewReader(strings.NewReader(rawNoCL)))
	if !errors.Is(err, ErrInvalidSIPMessage) {
		t.Fatalf("expected ErrInvalidSIPMessage when Content-Length missing on stream, got %v", err)
	}

	rawMixed := "MESSAGE sip:user@ims.example SIP/2.0\r\nv: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK2\r\nf: <sip:a@b>;tag=1\r\nt: <sip:c@d>\r\ni: cid2\r\nCSeq: 1 MESSAGE\r\nc: text/plain\r\nl: 5\r\n\nhelloNEXT"
	r := bufio.NewReader(strings.NewReader(rawMixed))
	framed, err := readSIPStreamMessage(r)
	if err != nil {
		t.Fatalf("readSIPStreamMessage(mixed) error = %v", err)
	}
	req, err := ParseSIPRequest(framed)
	if err != nil {
		t.Fatalf("ParseSIPRequest(compact+mixed) error = %v", err)
	}
	if string(req.Body) != "hello" || len(req.Headers["Via"]) == 0 || firstHeader(req.Headers, "Call-ID") != "cid2" || firstHeader(req.Headers, "Content-Type") != "text/plain" {
		t.Fatalf("parsed compact request = %+v body=%q", req, string(req.Body))
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "NEXT" {
		t.Fatalf("stream over-read into next frame: rest=%q", string(rest))
	}
}

func TestPhoneContextPreservationEmergencyRouteAndAKASHA256(t *testing.T) {
	// HIGH-4: ;phone-context= in userinfo must not be truncated when rewriting host/port.
	uri := "sip:911;phone-context=ims.mnc260.mcc310.3gppnetwork.org@198.51.100.10:5060;user=phone;lr"
	rewrittenPort := rewriteSIPURIPort(uri, 5064)
	if !strings.Contains(rewrittenPort, "911;phone-context=ims.mnc260.mcc310.3gppnetwork.org@198.51.100.10:5064;user=phone;lr") {
		t.Fatalf("rewriteSIPURIPort corrupted phone-context: %q", rewrittenPort)
	}
	rewrittenHost := rewriteSIPURIHost(uri, "2001:db8::10")
	if !strings.Contains(rewrittenHost, "911;phone-context=ims.mnc260.mcc310.3gppnetwork.org@[2001:db8::10]:5060;user=phone;lr") {
		t.Fatalf("rewriteSIPURIHost corrupted phone-context: %q", rewrittenHost)
	}

	// HIGH-5: formatEmergencySIPRoute with bare IPv6, bracketed IPv6, and host:port.
	if got := formatEmergencySIPRoute("2001:db8::1"); got != "<sip:[2001:db8::1];lr>" {
		t.Fatalf("formatEmergencySIPRoute(ipv6) = %q", got)
	}
	if got := formatEmergencySIPRoute("[2001:db8::1]:5060"); got != "<sip:[2001:db8::1]:5060;lr>" {
		t.Fatalf("formatEmergencySIPRoute([ipv6]:port) = %q", got)
	}
	if got := formatEmergencySIPRoute("10.0.0.1:5060"); got != "<sip:10.0.0.1:5060;lr>" {
		t.Fatalf("formatEmergencySIPRoute(ipv4:port) = %q", got)
	}

	// HIGH-7 + MEDIUM-3: AKAv2-SHA-256 + base64url nonce without padding + qop="auth,auth-int".
	rawNonce := make([]byte, 32)
	for i := range rawNonce {
		rawNonce[i] = byte(i + 1)
	}
	b64URLNonce := base64.RawURLEncoding.EncodeToString(rawNonce)
	rand16, autn16, ok := ExtractAKAChallengeNonce(b64URLNonce)
	if !ok || len(rand16) != 16 || len(autn16) != 16 {
		t.Fatalf("ExtractAKAChallengeNonce(base64url) ok=%v rand=%d autn=%d", ok, len(rand16), len(autn16))
	}

	akaRes := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		IK:  bytesRepeatSeq(0x10, 16),
		CK:  bytesRepeatSeq(0x20, 16),
	}
	akaPw, err := BuildAKADigestPassword("AKAv2-SHA-256", akaRes)
	if err != nil {
		t.Fatalf("BuildAKADigestPassword(AKAv2-SHA-256) error = %v", err)
	}
	ch := DigestChallenge{
		Realm:     "ims.example",
		Nonce:     b64URLNonce,
		Algorithm: "AKAv2-SHA-256",
		QOP:       "auth,auth-int",
	}
	in := DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "001010123456789@ims.example",
		Password: akaPw,
		CNonce:   "abcdef01",
		NC:       1,
	}
	authHdr, err := BuildDigestAuthorization(ch, in)
	if err != nil {
		t.Fatalf("BuildDigestAuthorization(AKAv2-SHA-256) error = %v", err)
	}
	if !strings.Contains(authHdr, "algorithm=AKAv2-SHA-256") {
		t.Fatalf("unexpected AKAv2-SHA-256 header: %q", authHdr)
	}
	if _, verified, err := VerifyDigestAuthorization(authHdr, ch, in); err != nil || !verified {
		t.Fatalf("VerifyDigestAuthorization(AKAv2-SHA-256, qop=auth,auth-int) verified=%v err=%v", verified, err)
	}

	// HIGH-9: Comma-combined Via matching.
	reqMsg := SIPRequestMessage{
		Method: "OPTIONS",
		URI:    "sip:ims.example",
		Headers: map[string]string{
			"Via":     "SIP/2.0/UDP 192.0.2.10:5062;branch=z9hG4bKcomb123;rport",
			"Call-ID": "comb-1",
			"CSeq":    "1 OPTIONS",
		},
	}
	combResp := SIPResponse{
		StatusCode: 200,
		Reason:     "OK",
		Headers: map[string][]string{
			"Via":     {"SIP/2.0/UDP 192.0.2.10:5062;branch=z9hG4bKcomb123;rport=5062, SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bKproxy"},
			"Call-ID": {"comb-1"},
			"CSeq":    {"1 OPTIONS"},
		},
	}
	if !sipResponseMatchesRequest(combResp, reqMsg) {
		t.Fatal("sipResponseMatchesRequest failed on comma-combined Via header")
	}

	// MEDIUM-2: defaultPublicIdentity prefers sip: over tel:.
	if got := defaultPublicIdentity(IMSProfile{}, []string{"<tel:+12065550100>", "<sip:+12065550100@ims.example>"}); got != "sip:+12065550100@ims.example" {
		t.Fatalf("defaultPublicIdentity() = %q, want sip: URI", got)
	}

	// MEDIUM-5 + VH-02: CRLF injection sanitization & Record-Route preservation on 180 Ringing.
	if _, err := buildSIPRequestWire(SIPRequestMessage{
		Method:  "OPTIONS",
		URI:     "sip:ims.example\r\nX-Injected: bad",
		Headers: map[string]string{"Call-ID": "crlf-1", "CSeq": "1 OPTIONS"},
	}, "UDP", nil); !errors.Is(err, ErrInvalidSIPMessage) {
		t.Fatalf("expected ErrInvalidSIPMessage on CRLF in Request-URI, got %v", err)
	}
	inReq := SIPIncomingRequest{
		Method: "INVITE",
		URI:    "sip:b@ims.example",
		Headers: map[string][]string{
			"Via":          {"SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1"},
			"Record-Route": {"<sip:pcscf.ims.example;lr>", "<sip:scscf.ims.example;lr>"},
			"From":         {"<sip:a@ims.example>;tag=1"},
			"To":           {"<sip:b@ims.example>"},
			"Call-ID":      {"rr-preserve"},
			"CSeq":         {"1 INVITE"},
		},
	}
	wireSanitized, err := BuildSIPResponseWire(inReq, 180, "Ringing\r\nX-Evil: 1", map[string]string{
		"To": "<sip:b@ims.example>;tag=2\r\nBcc: evil@ims.example",
	}, nil)
	if err != nil {
		t.Fatalf("BuildSIPResponseWire() error = %v", err)
	}
	wireStr := string(wireSanitized)
	if strings.Contains(wireStr, "\r\nX-Evil:") || strings.Contains(wireStr, "\r\nBcc:") {
		t.Fatalf("CRLF injection was not sanitized: %q", wireStr)
	}
	if !strings.Contains(wireStr, "Record-Route: <sip:pcscf.ims.example;lr>\r\nRecord-Route: <sip:scscf.ims.example;lr>\r\n") {
		t.Fatalf("VH-02: BuildSIPResponseWire dropped Record-Route on 180 Ringing: %q", wireStr)
	}
}

func bytesRepeatSeq(base byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = base + byte(i)
	}
	return out
}
