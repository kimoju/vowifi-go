package messaging

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/iniwex5/vowifi-go/runtimehost/voiceclient"
)

func TestIMSSMSTransportSendsSIPMessage(t *testing.T) {
	transport := &fakeSIPRequestTransport{responses: []voiceclient.SIPResponse{{StatusCode: 202, Reason: "Accepted"}}}
	sms := IMSSMSTransport{
		Transport: transport,
		Profile:   voiceclient.IMSProfile{IMPU: "sip:user@ims.example", Domain: "ims.example", UserAgent: "VoHive"},
		Registration: voiceclient.RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@ims.example",
			ServiceRoutes:  []string{"<sip:pcscf.ims.example;lr>"},
		},
	}

	result, err := sms.SendSMSPart(context.Background(), SMSSendRequest{
		DeviceID:  "dev-1",
		IMSI:      "310280233641503",
		Peer:      "+18005551212",
		MessageID: "msg-1",
		Part:      SMSPart{PartNo: 2, TotalParts: 2, Text: "hello", Encoding: "gsm7"},
	})
	if err != nil {
		t.Fatalf("SendSMSPart() error = %v", err)
	}
	if result.State != "accepted" || result.SIPCode != 202 || result.RPMR != 2 || result.CallID != "msg-1-2@vowifi-go" {
		t.Fatalf("result=%+v", result)
	}
	if len(transport.requests) != 1 {
		t.Fatalf("requests=%d", len(transport.requests))
	}
	req := transport.requests[0]
	if req.Method != "MESSAGE" || req.URI != "sip:+18005551212@ims.example" || string(req.Body) != "hello" {
		t.Fatalf("MESSAGE=%+v body=%q", req, req.Body)
	}
	if req.Headers["Route"] != "<sip:pcscf.ims.example;lr>" || req.Headers["Content-Type"] != "text/plain;charset=UTF-8" {
		t.Fatalf("headers=%+v", req.Headers)
	}
	if req.Headers["P-Preferred-Service"] != "urn:urn-7:3gpp-service.ims.icsi.sms" || req.Headers["Accept-Contact"] != "*;+g.3gpp.smsip" {
		t.Fatalf("SMS service headers=%+v", req.Headers)
	}
	if !strings.Contains(req.Headers["From"], "sip:user@ims.example") || !strings.Contains(req.Headers["To"], "sip:+18005551212@ims.example") {
		t.Fatalf("dialog headers=%+v", req.Headers)
	}
}

func TestIMSSMSTransportRejectsFailedMessage(t *testing.T) {
	transport := &fakeSIPRequestTransport{responses: []voiceclient.SIPResponse{{StatusCode: 403, Reason: "Forbidden"}}}
	sms := IMSSMSTransport{
		Transport:    transport,
		Profile:      voiceclient.IMSProfile{IMPU: "sip:user@ims.example", Domain: "ims.example"},
		Registration: voiceclient.RegistrationBinding{ContactURI: "sip:user@192.0.2.10:5060"},
	}

	result, err := sms.SendSMSPart(context.Background(), SMSSendRequest{
		Peer:      "sip:+18005551212@ims.example",
		MessageID: "msg reject",
		Part:      SMSPart{PartNo: 1, TotalParts: 1, Text: "hello"},
	})
	if err == nil {
		t.Fatal("SendSMSPart() err=nil, want rejection")
	}
	if result.State != "failed" || result.SIPCode != 403 || result.CallID != "msg-reject-1@vowifi-go" || result.ErrorText != "Forbidden" {
		t.Fatalf("result=%+v", result)
	}
}

func TestIMSSMSTransportRequiresSIPTransport(t *testing.T) {
	_, err := IMSSMSTransport{}.SendSMSPart(context.Background(), SMSSendRequest{Peer: "+18005551212", Part: SMSPart{Text: "hello"}})
	if !errors.Is(err, ErrSMSTransportUnavailable) {
		t.Fatalf("err=%v, want ErrSMSTransportUnavailable", err)
	}
}

type fakeSIPRequestTransport struct {
	requests  []voiceclient.SIPRequestMessage
	responses []voiceclient.SIPResponse
	writes    []voiceclient.SIPRequestMessage
}

func (t *fakeSIPRequestTransport) RoundTripRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error) {
	t.requests = append(t.requests, msg)
	if len(t.responses) == 0 {
		return voiceclient.SIPResponse{StatusCode: 500, Reason: "empty"}, nil
	}
	resp := t.responses[0]
	t.responses = t.responses[1:]
	return resp, nil
}

func (t *fakeSIPRequestTransport) WriteRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) error {
	t.writes = append(t.writes, msg)
	return nil
}
