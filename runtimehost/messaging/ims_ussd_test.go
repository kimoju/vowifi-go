package messaging

import (
	"context"
	"strings"
	"testing"

	"github.com/iniwex5/vowifi-go/runtimehost/voiceclient"
)

func TestIMSUSSDTransportExecuteAndContinue(t *testing.T) {
	replyXML, err := BuildIMSUSSDXML(IMSUSSDPayload{Text: "Balance: 10", Operation: IMSUSSDOperationNotify})
	if err != nil {
		t.Fatalf("BuildIMSUSSDXML() error = %v", err)
	}
	transport := &fakeSIPRequestTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:*100%23@ims.example;user=dialstring>;tag=as-tag"},
				"Contact": {"<sip:ussd-as@ims.example>"},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers:    map[string][]string{"Content-Type": {IMSUSSDContentType}},
			Body:       replyXML,
		},
	}}
	ussd := &IMSUSSDTransport{
		Transport: transport,
		Profile:   voiceclient.IMSProfile{IMPU: "sip:user@ims.example", Domain: "ims.example", LocalIP: "192.0.2.10"},
		Registration: voiceclient.RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@ims.example",
			ServiceRoutes:  []string{"<sip:pcscf.ims.example;lr>"},
		},
	}
	first, err := ussd.ExecuteUSSD(context.Background(), USSDRequest{SessionID: "session-1", Command: "*100#"})
	if err != nil {
		t.Fatalf("ExecuteUSSD() error = %v", err)
	}
	if first.Done || first.SessionID != "session-1" || first.Status != 200 {
		t.Fatalf("first=%+v", first)
	}
	if len(transport.requests) != 1 {
		t.Fatalf("requests=%d", len(transport.requests))
	}
	invite := transport.requests[0]
	if invite.Method != "INVITE" || invite.URI != "sip:*100%23@ims.example;user=dialstring" || invite.Headers["Recv-Info"] != IMSUSSDInfoPackage {
		t.Fatalf("invite=%+v", invite)
	}
	if invite.Headers["Route"] != "<sip:pcscf.ims.example;lr>" || !strings.Contains(invite.Headers["Content-Type"], "multipart/mixed") {
		t.Fatalf("invite headers=%+v", invite.Headers)
	}
	payload, ok, err := DecodeIMSUSSDDocument(invite.Headers["Content-Type"], invite.Body)
	if err != nil || !ok || payload.Text != "*100#" || payload.Operation != IMSUSSDOperationRequest {
		t.Fatalf("payload=%+v ok=%v err=%v", payload, ok, err)
	}
	if len(transport.writes) != 1 || transport.writes[0].Method != "ACK" || transport.writes[0].Headers["CSeq"] != "1 ACK" {
		t.Fatalf("ACK writes=%+v", transport.writes)
	}

	next, err := ussd.ContinueUSSD(context.Background(), USSDRequest{SessionID: "session-1", Input: "1"})
	if err != nil {
		t.Fatalf("ContinueUSSD() error = %v", err)
	}
	if !next.Done || next.Text != "Balance: 10" || next.Status != 200 {
		t.Fatalf("next=%+v", next)
	}
	if len(transport.requests) != 2 {
		t.Fatalf("requests=%d", len(transport.requests))
	}
	info := transport.requests[1]
	if info.Method != "INFO" || info.Headers["CSeq"] != "2 INFO" || info.Headers["Info-Package"] != IMSUSSDInfoPackage || info.Headers["Content-Disposition"] != IMSUSSDContentDisposition {
		t.Fatalf("info=%+v", info)
	}
	if _, err := ussd.ContinueUSSD(context.Background(), USSDRequest{SessionID: "session-1", Input: "1"}); err == nil {
		t.Fatal("ContinueUSSD() err=nil after terminal notify, want inactive session")
	}
}

func TestIMSUSSDTransportCancelSendsBye(t *testing.T) {
	transport := &fakeSIPRequestTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:*100%23@ims.example;user=dialstring>;tag=as-tag"},
				"Contact": {"<sip:ussd-as@ims.example>"},
			},
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	ussd := &IMSUSSDTransport{
		Transport: transport,
		Profile:   voiceclient.IMSProfile{IMPU: "sip:user@ims.example", Domain: "ims.example"},
		Registration: voiceclient.RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@ims.example",
		},
	}
	if _, err := ussd.ExecuteUSSD(context.Background(), USSDRequest{SessionID: "session-cancel", Command: "*100#"}); err != nil {
		t.Fatalf("ExecuteUSSD() error = %v", err)
	}
	if err := ussd.CancelUSSD(context.Background(), USSDRequest{SessionID: "session-cancel"}); err != nil {
		t.Fatalf("CancelUSSD() error = %v", err)
	}
	if len(transport.requests) != 2 {
		t.Fatalf("requests=%d", len(transport.requests))
	}
	bye := transport.requests[1]
	if bye.Method != "BYE" || bye.Headers["CSeq"] != "2 BYE" || bye.URI != "sip:ussd-as@ims.example" {
		t.Fatalf("bye=%+v", bye)
	}
}

func TestIMSUSSDTransportHandlesInboundInfoAndBye(t *testing.T) {
	transport := &fakeSIPRequestTransport{responses: []voiceclient.SIPResponse{{
		StatusCode: 200,
		Reason:     "OK",
		Headers: map[string][]string{
			"To":      {"<sip:*100%23@ims.example;user=dialstring>;tag=as-tag"},
			"Contact": {"<sip:ussd-as@ims.example>"},
		},
	}}}
	ussd := &IMSUSSDTransport{
		Transport: transport,
		Profile:   voiceclient.IMSProfile{IMPU: "sip:user@ims.example", Domain: "ims.example"},
		Registration: voiceclient.RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@ims.example",
		},
	}
	svc := NewService("dev-1", "310280233641503", nil, nil)
	svc.SetUSSDTransport(ussd)
	first, err := svc.SendUSSD(context.Background(), "*100#")
	if err != nil {
		t.Fatalf("SendUSSD() error = %v", err)
	}
	if first.Done || !svc.hasUSSDSession(first.SessionID) {
		t.Fatalf("first=%+v active=%v", first, svc.hasUSSDSession(first.SessionID))
	}

	menuXML, err := BuildIMSUSSDXML(IMSUSSDPayload{Text: "1. Balance\n2. Data", Operation: IMSUSSDOperationRequest})
	if err != nil {
		t.Fatalf("BuildIMSUSSDXML(menu) error = %v", err)
	}
	info, err := svc.HandleIMSUSSDInfo(context.Background(), IMSUSSDDialogRequest{
		CallID:      "ussd-" + smsToken(first.SessionID) + "@vowifi-go",
		CSeq:        2,
		ContentType: IMSUSSDContentType,
		InfoPackage: IMSUSSDInfoPackage,
		Body:        menuXML,
	})
	if err != nil {
		t.Fatalf("HandleIMSUSSDInfo() error = %v", err)
	}
	if !info.Handled || info.StatusCode != 200 || info.USSD.Text != "1. Balance\n2. Data" || info.USSD.Done || !svc.hasUSSDSession(first.SessionID) {
		t.Fatalf("info=%+v active=%v", info, svc.hasUSSDSession(first.SessionID))
	}

	byeXML, err := BuildIMSUSSDXML(IMSUSSDPayload{Text: "Bye", Operation: IMSUSSDOperationNotify})
	if err != nil {
		t.Fatalf("BuildIMSUSSDXML(bye) error = %v", err)
	}
	bye, err := svc.HandleIMSUSSDBye(context.Background(), IMSUSSDDialogRequest{
		CallID:      "ussd-" + smsToken(first.SessionID) + "@vowifi-go",
		CSeq:        3,
		ContentType: IMSUSSDContentType,
		Body:        byeXML,
	})
	if err != nil {
		t.Fatalf("HandleIMSUSSDBye() error = %v", err)
	}
	if !bye.Handled || bye.StatusCode != 200 || bye.USSD.Text != "Bye" || !bye.USSD.Done || svc.hasUSSDSession(first.SessionID) {
		t.Fatalf("bye=%+v active=%v", bye, svc.hasUSSDSession(first.SessionID))
	}
}
