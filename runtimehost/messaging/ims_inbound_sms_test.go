package messaging

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestHandleIMSMessageAcceptsCPIMIMDNDeliveryReport(t *testing.T) {
	store := &fakeDeliveryStore{match: DeliveryPartMatch{MessageID: "msg-123", PartNo: 1, State: "delivered"}}
	svc := NewService("dev-1", "310280233641503", store, nil)
	payload := strings.Join([]string{
		`<imdn xmlns="urn:ietf:params:xml:ns:imdn">`,
		`<message-id>msg-123-1@vowifi-go</message-id>`,
		`<datetime>2026-07-07T02:03:04Z</datetime>`,
		`<recipient-uri>tel:+18005551212</recipient-uri>`,
		`<delivery-notification><status><delivered/></status></delivery-notification>`,
		`</imdn>`,
	}, "")
	body, err := BuildIMSCPIMMessageWithHeaders(map[string][]string{
		"From":            {"<sip:smsc@ims.example>"},
		"To":              {"<sip:user@ims.example>"},
		"NS":              {"imdn <urn:ietf:params:imdn>"},
		"imdn.Message-ID": {"header-message-id"},
	}, map[string][]string{
		"Content-Type":        {"message/imdn+xml; charset=UTF-8"},
		"Content-Disposition": {"notification"},
	}, []byte(payload))
	if err != nil {
		t.Fatalf("BuildIMSCPIMMessageWithHeaders() error = %v", err)
	}

	result, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		CallID:      "imdn-report-call",
		ContentType: IMSCPIMContentType,
		Body:        body,
	})
	if err != nil {
		t.Fatalf("HandleIMSMessage() error = %v", err)
	}
	if result.StatusCode != 200 || result.DeliveryReport == nil || result.ReplyContentType != "" || len(result.ReplyBody) != 0 {
		t.Fatalf("result=%+v", result)
	}
	report := result.DeliveryReport
	if report.InReplyTo != "msg-123-1@vowifi-go" || report.CallID != "imdn-report-call" || report.State != "delivered" {
		t.Fatalf("report=%+v", report)
	}
	if report.Recipient != "tel:+18005551212" || report.ErrorText != "" || report.SIPCode != 200 {
		t.Fatalf("report fields=%+v", report)
	}
	wantAt := time.Date(2026, 7, 7, 2, 3, 4, 0, time.UTC)
	if !report.ReportAt.Equal(wantAt) {
		t.Fatalf("ReportAt=%s want %s", report.ReportAt, wantAt)
	}
	if store.reportInReplyTo != "msg-123-1@vowifi-go" || store.reportCallID != "imdn-report-call" || store.reportState != "delivered" {
		t.Fatalf("store=%+v", store)
	}
	if store.recomputedMessageID != "msg-123" {
		t.Fatalf("recomputedMessageID=%q", store.recomputedMessageID)
	}
}

func TestHandleIMSMessageAcceptsRPACKStatusReportBuiltFromStruct(t *testing.T) {
	store := &fakeDeliveryStore{match: DeliveryPartMatch{MessageID: "msg-456", PartNo: 1, State: "failed"}}
	svc := NewService("dev-1", "310280233641503", store, nil)
	sentAt := time.Date(2026, 7, 5, 12, 34, 56, 0, time.FixedZone("", 0))
	doneAt := time.Date(2026, 7, 5, 12, 44, 0, 0, time.FixedZone("", 0))
	tpdu, err := BuildSMSStatusReportTPDU(SMSStatusReport{
		FirstOctet: 0x02,
		Reference:  7,
		Recipient:  "+18005551212",
		Timestamp:  sentAt,
		DoneAt:     doneAt,
		Status:     0x46,
	})
	if err != nil {
		t.Fatalf("BuildSMSStatusReportTPDU() error = %v", err)
	}
	body, err := BuildSMSRPAckWithTPDU(0x55, tpdu)
	if err != nil {
		t.Fatalf("BuildSMSRPAckWithTPDU() error = %v", err)
	}

	result, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		CallID:      "status-report-call",
		ContentType: IMS3GPPSMSContentType,
		Body:        body,
	})
	if err != nil {
		t.Fatalf("HandleIMSMessage() error = %v", err)
	}
	if result.StatusCode != 200 || result.DeliveryReport == nil || result.RPDU.Kind != SMSRPDUKindAck {
		t.Fatalf("result=%+v", result)
	}
	report := result.DeliveryReport
	if report.CallID != "status-report-call" || report.RPMR != 7 || report.State != "failed" || report.RPCause != 0x46 {
		t.Fatalf("report=%+v", report)
	}
	if report.Recipient != "+18005551212" || !report.SentAt.Equal(sentAt) || !report.ReportAt.Equal(doneAt) || !strings.Contains(report.ErrorText, "validity period expired") {
		t.Fatalf("report fields=%+v", report)
	}
	if store.reportCallID != "status-report-call" || store.reportRPMR != 7 || store.reportState != "failed" || store.reportRPCause != 0x46 {
		t.Fatalf("store report=%+v", store)
	}
	if store.recomputedMessageID != "msg-456" {
		t.Fatalf("recomputedMessageID=%q", store.recomputedMessageID)
	}
}
