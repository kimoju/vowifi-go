package voicehost

import (
	"context"
	"strings"
	"testing"

	"github.com/iniwex5/vowifi-go/runtimehost/voiceclient"
)

func TestIMSOutboundAgentAppliesDigestAuthenticationInfo(t *testing.T) {
	binding := testVoiceDigestBinding(t, "nonce-voice")
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":                  {"<sip:+18005551212@ims.example>;tag=remote-tag"},
				"Contact":             {"<sip:carrier@198.51.100.1:5060>"},
				"Authentication-Info": {`nextnonce="nonce-voice-next"`},
			},
			Body: []byte(sampleSDP("203.0.113.10", 49170)),
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSOutboundAgent{
		Transport:    transport,
		Profile:      voiceclient.IMSProfile{IMPI: "impi@example", IMPU: "sip:user@ims.example", Domain: "ims.example"},
		Registration: binding,
	}
	if _, err := agent.StartOutboundCall(context.Background(), OutboundCallRequest{
		CallID: "call-auth-info",
		Callee: "+18005551212",
		RawSDP: []byte(sampleSDP("192.0.2.50", 4002)),
	}); err != nil {
		t.Fatalf("StartOutboundCall() error = %v", err)
	}
	if len(transport.requests) != 1 || len(transport.writes) != 1 {
		t.Fatalf("requests=%+v writes=%+v", transport.requests, transport.writes)
	}
	if auth := transport.requests[0].Headers["Authorization"]; !strings.Contains(auth, `nonce="nonce-voice"`) || !strings.Contains(auth, `nc=00000002`) {
		t.Fatalf("INVITE Authorization=%s", auth)
	}
	if auth := transport.writes[0].Headers["Authorization"]; !strings.Contains(auth, `nonce="nonce-voice-next"`) || !strings.Contains(auth, `nc=00000001`) {
		t.Fatalf("ACK Authorization=%s", auth)
	}
	if err := agent.EndVoiceCall(context.Background(), DialogInfo{CallID: "call-auth-info"}); err != nil {
		t.Fatalf("EndVoiceCall() error = %v", err)
	}
	if len(transport.requests) != 2 {
		t.Fatalf("requests=%+v", transport.requests)
	}
	if auth := transport.requests[1].Headers["Authorization"]; !strings.Contains(auth, `nonce="nonce-voice-next"`) || !strings.Contains(auth, `nc=00000002`) {
		t.Fatalf("BYE Authorization=%s", auth)
	}
}

func TestIMSOutboundAgentRetriesDialogDigestChallenge(t *testing.T) {
	binding := testVoiceDigestBinding(t, "nonce-voice-retry")
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:+18005551212@ims.example>;tag=remote-tag"},
				"Contact": {"<sip:carrier@198.51.100.1:5060>"},
			},
			Body: []byte(sampleSDP("203.0.113.10", 49170)),
		},
		{
			StatusCode: 407,
			Reason:     "Proxy Authentication Required",
			Headers: map[string][]string{
				"Proxy-Authenticate": {`Digest realm="ims.example", nonce="nonce-voice-bye", algorithm=MD5, qop="auth"`},
			},
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSOutboundAgent{
		Transport:    transport,
		Profile:      voiceclient.IMSProfile{IMPI: "impi@example", IMPU: "sip:user@ims.example", Domain: "ims.example"},
		Registration: binding,
	}
	if _, err := agent.StartOutboundCall(context.Background(), OutboundCallRequest{
		CallID: "call-auth-retry",
		Callee: "+18005551212",
		RawSDP: []byte(sampleSDP("192.0.2.50", 4002)),
	}); err != nil {
		t.Fatalf("StartOutboundCall() error = %v", err)
	}
	if err := agent.EndVoiceCall(context.Background(), DialogInfo{CallID: "call-auth-retry"}); err != nil {
		t.Fatalf("EndVoiceCall() error = %v", err)
	}
	if len(transport.requests) != 3 {
		t.Fatalf("requests=%+v", transport.requests)
	}
	initial := transport.requests[1]
	retry := transport.requests[2]
	if initial.Method != "BYE" || retry.Method != "BYE" {
		t.Fatalf("requests=%+v", transport.requests)
	}
	if auth := retry.Headers["Proxy-Authorization"]; !strings.Contains(auth, `nonce="nonce-voice-bye"`) ||
		!strings.Contains(auth, `uri="sip:carrier@198.51.100.1:5060"`) ||
		!strings.Contains(auth, `nc=00000001`) {
		t.Fatalf("retry BYE Proxy-Authorization=%s", auth)
	}
	if retry.Headers["Authorization"] != "" {
		t.Fatalf("retry BYE kept Authorization: %+v", retry.Headers)
	}
}

func TestIMSOutboundAgentRetriesInviteDigestChallenge(t *testing.T) {
	binding := testVoiceDigestBinding(t, "nonce-invite-old")
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"To":               {"<sip:+18005551212@ims.example>;tag=challenge-tag"},
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="nonce-invite-new", algorithm=MD5, qop="auth"`},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:+18005551212@ims.example>;tag=remote-tag"},
				"Contact": {"<sip:carrier@198.51.100.1:5060>"},
			},
			Body: []byte(sampleSDP("203.0.113.10", 49170)),
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSOutboundAgent{
		Transport:    transport,
		Profile:      voiceclient.IMSProfile{IMPI: "impi@example", IMPU: "sip:user@ims.example", Domain: "ims.example"},
		Registration: binding,
	}
	result, err := agent.StartOutboundCall(context.Background(), OutboundCallRequest{
		CallID: "call-invite-auth-retry",
		Callee: "+18005551212",
		RawSDP: []byte(sampleSDP("192.0.2.50", 4002)),
	})
	if err != nil || !result.Accepted {
		t.Fatalf("StartOutboundCall() result=%+v err=%v", result, err)
	}
	if len(transport.requests) != 2 {
		t.Fatalf("requests=%+v", transport.requests)
	}
	firstInvite := transport.requests[0]
	retryInvite := transport.requests[1]
	if firstInvite.Headers["CSeq"] != "1 INVITE" || retryInvite.Headers["CSeq"] != "2 INVITE" {
		t.Fatalf("INVITE CSeqs=%q/%q", firstInvite.Headers["CSeq"], retryInvite.Headers["CSeq"])
	}
	if auth := retryInvite.Headers["Authorization"]; !strings.Contains(auth, `nonce="nonce-invite-new"`) ||
		!strings.Contains(auth, `uri="sip:+18005551212@ims.example"`) ||
		!strings.Contains(auth, `nc=00000001`) {
		t.Fatalf("retry INVITE Authorization=%s", auth)
	}
	if len(transport.writes) != 2 || transport.writes[0].Method != "ACK" || transport.writes[1].Method != "ACK" {
		t.Fatalf("writes=%+v", transport.writes)
	}
	if transport.writes[0].Headers["CSeq"] != "1 ACK" || !strings.Contains(transport.writes[0].Headers["To"], "challenge-tag") ||
		transport.writes[0].Headers["Via"] != firstInvite.Headers["Via"] {
		t.Fatalf("challenge ACK=%+v first=%+v", transport.writes[0], firstInvite)
	}
	if transport.writes[1].Headers["CSeq"] != "2 ACK" || transport.writes[1].URI != "sip:carrier@198.51.100.1:5060" {
		t.Fatalf("final ACK=%+v", transport.writes[1])
	}
	if err := agent.EndVoiceCall(context.Background(), DialogInfo{CallID: "call-invite-auth-retry"}); err != nil {
		t.Fatalf("EndVoiceCall() error = %v", err)
	}
	if len(transport.requests) != 3 || transport.requests[2].Method != "BYE" || transport.requests[2].Headers["CSeq"] != "3 BYE" {
		t.Fatalf("BYE after invite auth retry=%+v", transport.requests)
	}
}

func TestIMSOutboundAgentRetriesReinviteDigestChallenge(t *testing.T) {
	binding := testVoiceDigestBinding(t, "nonce-reinvite-old")
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:+18005551212@ims.example>;tag=remote-tag"},
				"Contact": {"<sip:carrier@198.51.100.1:5060>"},
			},
			Body: []byte(sampleSDP("203.0.113.10", 49170)),
		},
		{
			StatusCode: 407,
			Reason:     "Proxy Authentication Required",
			Headers: map[string][]string{
				"To":                 {"<sip:+18005551212@ims.example>;tag=remote-tag"},
				"Proxy-Authenticate": {`Digest realm="ims.example", nonce="nonce-reinvite-new", algorithm=MD5, qop="auth"`},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:+18005551212@ims.example>;tag=remote-tag"},
				"Contact": {"<sip:updated@198.51.100.2:5060>"},
				"X-IMS":   {"reinvite-auth-ok"},
			},
			Body: []byte(sampleSDP("203.0.113.20", 49180)),
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSOutboundAgent{
		Transport:    transport,
		Profile:      voiceclient.IMSProfile{IMPI: "impi@example", IMPU: "sip:user@ims.example", Domain: "ims.example"},
		Registration: binding,
	}
	if _, err := agent.StartOutboundCall(context.Background(), OutboundCallRequest{
		CallID: "call-reinvite-auth-retry",
		Callee: "+18005551212",
		RawSDP: []byte(sampleSDP("192.0.2.50", 4002)),
	}); err != nil {
		t.Fatalf("StartOutboundCall() error = %v", err)
	}
	result, err := agent.SendDialogReinvite(context.Background(), DialogReinviteRequest{
		CallID:      "call-reinvite-auth-retry",
		ContentType: "application/sdp",
		Body:        []byte(sampleSDP("192.0.2.60", 4010)),
		Headers:     map[string]string{"Session-Expires": "1800"},
	})
	if err != nil || !result.Accepted || result.Headers["X-IMS"] != "reinvite-auth-ok" {
		t.Fatalf("SendDialogReinvite() result=%+v err=%v", result, err)
	}
	if len(transport.requests) != 3 {
		t.Fatalf("requests=%+v", transport.requests)
	}
	firstReinvite := transport.requests[1]
	retryReinvite := transport.requests[2]
	if firstReinvite.Headers["CSeq"] != "2 INVITE" || retryReinvite.Headers["CSeq"] != "3 INVITE" {
		t.Fatalf("re-INVITE CSeqs=%q/%q", firstReinvite.Headers["CSeq"], retryReinvite.Headers["CSeq"])
	}
	if auth := retryReinvite.Headers["Proxy-Authorization"]; !strings.Contains(auth, `nonce="nonce-reinvite-new"`) ||
		!strings.Contains(auth, `uri="sip:carrier@198.51.100.1:5060"`) ||
		!strings.Contains(auth, `nc=00000001`) {
		t.Fatalf("retry re-INVITE Proxy-Authorization=%s", auth)
	}
	if retryReinvite.Headers["Session-Expires"] != "1800" || retryReinvite.Headers["Content-Type"] != "application/sdp" {
		t.Fatalf("retry re-INVITE headers=%+v", retryReinvite.Headers)
	}
	if len(transport.writes) != 3 || transport.writes[1].Method != "ACK" || transport.writes[2].Method != "ACK" {
		t.Fatalf("ACK writes=%+v", transport.writes)
	}
	if transport.writes[1].Headers["CSeq"] != "2 ACK" || transport.writes[1].Headers["Via"] != firstReinvite.Headers["Via"] {
		t.Fatalf("challenge ACK=%+v first=%+v", transport.writes[1], firstReinvite)
	}
	if transport.writes[2].Headers["CSeq"] != "3 ACK" || transport.writes[2].URI != "sip:updated@198.51.100.2:5060" {
		t.Fatalf("final ACK=%+v", transport.writes[2])
	}
	if err := agent.EndVoiceCall(context.Background(), DialogInfo{CallID: "call-reinvite-auth-retry"}); err != nil {
		t.Fatalf("EndVoiceCall() error = %v", err)
	}
	if len(transport.requests) != 4 || transport.requests[3].Method != "BYE" || transport.requests[3].Headers["CSeq"] != "4 BYE" {
		t.Fatalf("BYE after re-INVITE auth retry=%+v", transport.requests)
	}
}

func testVoiceDigestBinding(t *testing.T, nonce string) voiceclient.RegistrationBinding {
	t.Helper()
	transport := &fakeVoiceRegisterTransport{responses: []voiceclient.RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="` + nonce + `", algorithm=MD5, qop="auth"`},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"Contact": {`<sip:user@192.0.2.10:5060>;expires=1800`},
			},
		},
	}}
	result, err := voiceclient.RegisterSession{
		Transport:    transport,
		Profile:      voiceclient.IMSProfile{IMPI: "impi@example", IMPU: "sip:user@ims.example", Domain: "ims.example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "register-auth-info",
		CNonce:       "cnonce",
	}.Register(context.Background())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !result.Registered || result.Binding.AuthSession == nil {
		t.Fatalf("registration result=%+v", result)
	}
	return result.Binding
}

type fakeVoiceRegisterTransport struct {
	responses []voiceclient.RegisterResponse
	requests  []voiceclient.RegisterMessage
}

func (t *fakeVoiceRegisterTransport) RoundTripRegister(ctx context.Context, msg voiceclient.RegisterMessage) (voiceclient.RegisterResponse, error) {
	t.requests = append(t.requests, msg)
	if len(t.responses) == 0 {
		return voiceclient.RegisterResponse{StatusCode: 500, Reason: "empty"}, nil
	}
	resp := t.responses[0]
	t.responses = t.responses[1:]
	return resp, nil
}
