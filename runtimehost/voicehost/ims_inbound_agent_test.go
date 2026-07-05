package voicehost

import (
	"context"
	"strings"
	"testing"

	"github.com/iniwex5/vowifi-go/runtimehost/voiceclient"
)

func TestIMSInboundAgentInviteAckAndBye(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:user@ims.example>;tag=client-tag"},
				"Contact": {"<sip:client@192.0.2.50:5060>"},
			},
			Body: []byte(sampleSDP("192.0.2.50", 4002)),
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSInboundAgent{
		ClientTransport: transport,
		Profile: voiceclient.IMSProfile{
			IMPU:      "sip:user@ims.example",
			Domain:    "ims.example",
			UserAgent: "VoHive",
		},
		Registration: voiceclient.RegistrationBinding{
			PublicIdentity: "sip:user@ims.example",
			ContactURI:     "sip:user@192.0.2.10:5060",
		},
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	result, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		DeviceID:  "dev-1",
		CallID:    "in-call-1",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		RemoteTag: "ims-tag",
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
	})
	if err != nil {
		t.Fatalf("HandleInboundInvite() error = %v", err)
	}
	if !result.Accepted || result.StatusCode != 200 || result.LocalSDP.ConnectionIP != "192.0.2.50" || result.LocalSDP.MediaPort != 4002 {
		t.Fatalf("result=%+v", result)
	}
	if len(transport.requests) != 1 || transport.requests[0].Method != "INVITE" {
		t.Fatalf("requests=%+v", transport.requests)
	}
	invite := transport.requests[0]
	if invite.URI != "sip:client@127.0.0.1:5070" || !strings.Contains(invite.Headers["From"], "ims-tag") || invite.Headers["Contact"] != "<sip:vowifi@127.0.0.1:5060>" {
		t.Fatalf("INVITE=%+v", invite)
	}
	if !strings.Contains(string(invite.Body), "m=audio 49170 RTP/AVP") {
		t.Fatalf("INVITE body=%q", invite.Body)
	}

	if err := agent.AckInboundCall(context.Background(), DialogInfo{CallID: "in-call-1"}); err != nil {
		t.Fatalf("AckInboundCall() error = %v", err)
	}
	if len(transport.writes) != 1 || transport.writes[0].Method != "ACK" {
		t.Fatalf("writes=%+v", transport.writes)
	}
	if transport.writes[0].URI != "sip:client@192.0.2.50:5060" || !strings.Contains(transport.writes[0].Headers["To"], "client-tag") {
		t.Fatalf("ACK=%+v", transport.writes[0])
	}

	if err := agent.EndInboundCall(context.Background(), DialogInfo{CallID: "in-call-1"}); err != nil {
		t.Fatalf("EndInboundCall() error = %v", err)
	}
	if len(transport.requests) != 2 || transport.requests[1].Method != "BYE" {
		t.Fatalf("requests=%+v", transport.requests)
	}
	bye := transport.requests[1]
	if bye.URI != "sip:client@192.0.2.50:5060" || bye.Headers["CSeq"] != "2 BYE" {
		t.Fatalf("BYE=%+v", bye)
	}
}

func TestIMSInboundAgentRejectedInvite(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{{StatusCode: 486, Reason: "Busy Here"}}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	result, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-2",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
	})
	if err != nil {
		t.Fatalf("HandleInboundInvite() error = %v", err)
	}
	if result.Accepted || result.StatusCode != 486 || result.Reason != "Busy Here" {
		t.Fatalf("result=%+v", result)
	}
	if err := agent.AckInboundCall(context.Background(), DialogInfo{CallID: "in-call-2"}); err != nil {
		t.Fatalf("AckInboundCall(rejected) error = %v", err)
	}
	if len(transport.writes) != 0 {
		t.Fatalf("writes=%+v, want none", transport.writes)
	}
}

func TestIMSInboundAgentUsesRTPRelay(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers:    map[string][]string{"To": {"<sip:user@ims.example>;tag=client-tag"}},
			Body:       []byte(sampleSDP("127.0.0.1", 4002)),
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
		MediaRelay: &RTPRelayConfig{
			ClientListenIP:    "127.0.0.1",
			ClientAdvertiseIP: "127.0.0.1",
			IMSListenIP:       "127.0.0.1",
			IMSAdvertiseIP:    "127.0.0.1",
		},
	}
	result, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-relay",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		RemoteSDP: SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 49170, Payloads: []int{0, 8, 101}, Direction: "sendrecv"},
		RawSDP:    []byte(sampleSDP("127.0.0.1", 49170)),
	})
	if err != nil {
		t.Fatalf("HandleInboundInvite() error = %v", err)
	}
	if len(transport.requests) != 1 || transport.requests[0].Method != "INVITE" {
		t.Fatalf("requests=%+v", transport.requests)
	}
	clientOffer, err := ParseSDP(transport.requests[0].Body)
	if err != nil {
		t.Fatalf("ParseSDP(client offer) error = %v", err)
	}
	if clientOffer.ConnectionIP != "127.0.0.1" || clientOffer.MediaPort == 49170 || clientOffer.MediaPort <= 0 || clientOffer.RTCPPort <= 0 {
		t.Fatalf("client offer=%+v", clientOffer)
	}
	if result.LocalSDP.ConnectionIP != "127.0.0.1" || result.LocalSDP.MediaPort == 4002 || result.LocalSDP.MediaPort <= 0 || result.LocalSDP.RTCPPort <= 0 {
		t.Fatalf("IMS answer=%+v", result.LocalSDP)
	}
	if answer := string(result.RawSDP); !strings.Contains(answer, "c=IN IP4 127.0.0.1") || !strings.Contains(answer, "a=rtcp:") || strings.Contains(answer, "m=audio 4002") {
		t.Fatalf("IMS answer body=%q", answer)
	}
	if err := agent.EndInboundCall(context.Background(), DialogInfo{CallID: "in-call-relay"}); err != nil {
		t.Fatalf("EndInboundCall() error = %v", err)
	}
}
