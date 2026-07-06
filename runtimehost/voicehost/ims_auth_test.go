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
