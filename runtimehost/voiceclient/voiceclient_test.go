package voiceclient

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/iniwex5/vowifi-go/engine/sim"
)

func TestParseWWWAuthenticate(t *testing.T) {
	ch, err := ParseWWWAuthenticate(`Digest realm="ims.mnc280.mcc310.3gppnetwork.org", nonce="abc,123", algorithm=AKAv1-MD5, qop="auth,auth-int", opaque="opq"`)
	if err != nil {
		t.Fatalf("ParseWWWAuthenticate() error = %v", err)
	}
	if ch.Realm != "ims.mnc280.mcc310.3gppnetwork.org" || ch.Nonce != "abc,123" || ch.Algorithm != "AKAv1-MD5" || ch.QOP != "auth" || ch.Opaque != "opq" {
		t.Fatalf("challenge=%+v", ch)
	}
}

func TestExtractAKAChallengeNonce(t *testing.T) {
	raw := append(bytesFrom(0x10, 16), bytesFrom(0x40, 16)...)
	rand16, autn16, ok := ExtractAKAChallengeNonce(base64.StdEncoding.EncodeToString(raw))
	if !ok {
		t.Fatal("ExtractAKAChallengeNonce() ok=false")
	}
	if got := strings.ToUpper(hex.EncodeToString(rand16)); got != strings.ToUpper(hex.EncodeToString(bytesFrom(0x10, 16))) {
		t.Fatalf("RAND=%s", got)
	}
	if got := strings.ToUpper(hex.EncodeToString(autn16)); got != strings.ToUpper(hex.EncodeToString(bytesFrom(0x40, 16))) {
		t.Fatalf("AUTN=%s", got)
	}
}

func TestBuildDigestAuthorizationRFC2617Vector(t *testing.T) {
	ch := DigestChallenge{
		Realm:     "testrealm@host.com",
		Nonce:     "dcd98b7102dd2f0e8b11d0f600bfb0c093",
		Algorithm: "MD5",
		QOP:       "auth",
		Opaque:    "5ccc069c403ebaf9f0171e9517f40e41",
	}
	got, err := BuildDigestAuthorization(ch, DigestAuthInput{
		Method:   "GET",
		URI:      "/dir/index.html",
		Username: "Mufasa",
		Password: "Circle Of Life",
		CNonce:   "0a4f113b",
		NC:       1,
	})
	if err != nil {
		t.Fatalf("BuildDigestAuthorization() error = %v", err)
	}
	if !strings.Contains(got, `response="6629fae49393a05397450978507c4ef1"`) {
		t.Fatalf("authorization=%s", got)
	}
	if !strings.Contains(got, `qop=auth`) || !strings.Contains(got, `nc=00000001`) {
		t.Fatalf("authorization missing qop/nc: %s", got)
	}
}

func TestBuildRegisterHeaders(t *testing.T) {
	headers := BuildRegisterHeaders(IMSProfile{
		IMPI:      "310280233641503@private.att.net",
		IMPU:      "sip:310280233641503@one.att.net",
		Domain:    "one.att.net",
		UserAgent: "VoHive",
	}, "sip:310280233641503@192.0.2.10:5060", "call-1", "1")
	if headers["To"] != "<sip:310280233641503@one.att.net>" || headers["CSeq"] != "1 REGISTER" {
		t.Fatalf("headers=%+v", headers)
	}
	if !strings.Contains(headers["Security-Client"], "ipsec-3gpp") {
		t.Fatalf("Security-Client=%q", headers["Security-Client"])
	}
}

func TestRegisterSessionHandlesAKAv1MD5Challenge(t *testing.T) {
	rawNonce := append(bytesFrom(0x10, 16), bytesFrom(0x40, 16)...)
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv1-MD5, qop="auth"`},
			},
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	aka := &registerAKAProvider{}
	result, err := RegisterSession{
		Transport:    transport,
		AKAProvider:  aka,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "call-1",
		CNonce:       "cnonce",
	}.Register(context.Background())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !result.Registered || result.Attempts != 2 {
		t.Fatalf("result=%+v", result)
	}
	if len(transport.requests) != 2 {
		t.Fatalf("requests=%d, want 2", len(transport.requests))
	}
	auth := transport.requests[1].Headers["Authorization"]
	if !strings.Contains(auth, `algorithm=AKAv1-MD5`) || !strings.Contains(auth, `username="impi@example"`) {
		t.Fatalf("Authorization=%s", auth)
	}
	if got := strings.ToUpper(hex.EncodeToString(aka.rand)); got != strings.ToUpper(hex.EncodeToString(bytesFrom(0x10, 16))) {
		t.Fatalf("RAND=%s", got)
	}
}

func TestRegisterSessionRejectsFailedSecondRegister(t *testing.T) {
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="nonce", algorithm=MD5`},
			},
		},
		{StatusCode: 403, Reason: "Forbidden"},
	}}
	result, err := RegisterSession{
		Transport:    transport,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
	}.Register(context.Background())
	if err == nil {
		t.Fatal("Register() err=nil, want rejection")
	}
	if result.Registered || result.StatusCode != 403 || result.Attempts != 2 {
		t.Fatalf("result=%+v", result)
	}
}

type fakeRegisterTransport struct {
	requests  []RegisterMessage
	responses []RegisterResponse
}

func (f *fakeRegisterTransport) RoundTripRegister(ctx context.Context, msg RegisterMessage) (RegisterResponse, error) {
	f.requests = append(f.requests, msg)
	if len(f.responses) == 0 {
		return RegisterResponse{StatusCode: 500, Reason: "empty"}, nil
	}
	resp := f.responses[0]
	f.responses = f.responses[1:]
	return resp, nil
}

type registerAKAProvider struct {
	rand []byte
	autn []byte
}

func (p *registerAKAProvider) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	p.rand = append([]byte(nil), rand16...)
	p.autn = append([]byte(nil), autn16...)
	return sim.AKAResult{RES: []byte{0xAA, 0xBB, 0xCC, 0xDD}}, nil
}

func bytesFrom(start byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}
