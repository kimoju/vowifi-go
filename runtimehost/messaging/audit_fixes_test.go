package messaging

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kimoju/vowifi-go/runtimehost/eventhost"
	"github.com/kimoju/vowifi-go/runtimehost/voiceclient"
)

func TestSMSRPUserDataTLVAndRPErrorCompliance(t *testing.T) {
	rpErr := BuildSMSRPError(0x23, SMSRPCauseTemporaryFailure)
	wantRPErr := []byte{0x04, 0x23, 0x01, SMSRPCauseTemporaryFailure}
	if !bytes.Equal(rpErr, wantRPErr) {
		t.Fatalf("BuildSMSRPError() = %x, want %x (no trailing 0x00)", rpErr, wantRPErr)
	}
	parsedErr, err := ParseSMSRPDU(rpErr)
	if err != nil || parsedErr.Kind != SMSRPDUKindError || parsedErr.MR != 0x23 || parsedErr.Cause != int(SMSRPCauseTemporaryFailure) || len(parsedErr.TPDU) != 0 {
		t.Fatalf("ParseSMSRPDU(BuildSMSRPError) = %+v, err=%v", parsedErr, err)
	}

	tpdu := mustHex(t, "02070B918100551512F2627050214365006270502144000000")
	ackWithTPDU, err := BuildSMSRPAckWithTPDU(0x55, tpdu)
	if err != nil {
		t.Fatalf("BuildSMSRPAckWithTPDU() error = %v", err)
	}
	if len(ackWithTPDU) != 4+len(tpdu) || ackWithTPDU[2] != 0x41 || int(ackWithTPDU[3]) != len(tpdu) {
		t.Fatalf("BuildSMSRPAckWithTPDU() = %x, want TLV IEI 0x41 + len %d", ackWithTPDU, len(tpdu))
	}
	parsedAck, err := ParseSMSRPDU(ackWithTPDU)
	if err != nil || parsedAck.Kind != SMSRPDUKindAck || parsedAck.MR != 0x55 || !bytes.Equal(parsedAck.TPDU, tpdu) {
		t.Fatalf("ParseSMSRPDU(ack TLV) = %+v, err=%v", parsedAck, err)
	}

	emptyAck, err := BuildSMSRPAckWithTPDU(0x55, nil)
	if err != nil || !bytes.Equal(emptyAck, []byte{0x02, 0x55}) {
		t.Fatalf("BuildSMSRPAckWithTPDU(nil) = %x, err=%v", emptyAck, err)
	}

	errWithDiagTPDU, err := BuildSMSRPErrorWithDiagnostics(0x56, SMSRPCauseTemporaryFailure, []byte{0x80}, tpdu)
	if err != nil {
		t.Fatalf("BuildSMSRPErrorWithDiagnostics(tpdu) error = %v", err)
	}
	if errWithDiagTPDU[5] != 0x41 || int(errWithDiagTPDU[6]) != len(tpdu) {
		t.Fatalf("BuildSMSRPErrorWithDiagnostics(tpdu) = %x, want TLV IEI 0x41 at offset 5", errWithDiagTPDU)
	}
	parsedDiagTPDU, err := ParseSMSRPDU(errWithDiagTPDU)
	if err != nil || !bytes.Equal(parsedDiagTPDU.CauseDiagnostics, []byte{0x80}) || !bytes.Equal(parsedDiagTPDU.TPDU, tpdu) {
		t.Fatalf("ParseSMSRPDU(err TLV) = %+v, err=%v", parsedDiagTPDU, err)
	}

	errDiagOnly, err := BuildSMSRPErrorWithDiagnostics(0x56, SMSRPCauseTemporaryFailure, []byte{0x80}, nil)
	if err != nil || !bytes.Equal(errDiagOnly, []byte{0x04, 0x56, 0x02, SMSRPCauseTemporaryFailure, 0x80}) {
		t.Fatalf("BuildSMSRPErrorWithDiagnostics(nil tpdu) = %x, err=%v", errDiagOnly, err)
	}

	if _, err := ParseSMSRPDU([]byte{0x02, 0x11, 0x41, 0x03, 0xaa}); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("ParseSMSRPDU(truncated TLV) err=%v, want truncated", err)
	}
	if _, err := ParseSMSRPDU([]byte{0x02, 0x11, 0x41, 0x01, 0xaa, 0xff}); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("ParseSMSRPDU(trailing TLV) err=%v, want trailing", err)
	}
}

func TestIMSSMSTransportAtomicModulo256MRAndRandomLocalTag(t *testing.T) {
	const count = 260
	responses := make([]voiceclient.SIPResponse, count+2)
	for i := range responses {
		responses[i] = voiceclient.SIPResponse{StatusCode: 202, Reason: "Accepted"}
	}
	transport := &fakeSIPRequestTransport{responses: responses}
	sms := IMSSMSTransport{
		Transport: transport,
		Profile:   voiceclient.IMSProfile{IMPU: "sip:user@ims.example", Domain: "ims.example"},
		Registration: voiceclient.RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@ims.example",
		},
	}

	seenTags := make(map[string]struct{}, count+2)
	var prevMR byte
	sawZeroMR := false
	for i := 0; i < count; i++ {
		res, err := sms.SendSMSPart(context.Background(), SMSSendRequest{
			Peer:      "+18005551212",
			MessageID: "seq",
			Part:      SMSPart{PartNo: 1, TotalParts: 1, Text: "hi"},
		})
		if err != nil {
			t.Fatalf("SendSMSPart(%d) error = %v", i, err)
		}
		req := transport.requests[i]
		rpMR, tpdu, err := ParseSMSRPData(req.Body)
		if err != nil {
			t.Fatalf("ParseSMSRPData(%d) error = %v", i, err)
		}
		if res.RPMR != int(rpMR) || len(tpdu) < 2 || tpdu[1] != rpMR {
			t.Fatalf("mismatch at %d: result.RPMR=%d rpMR=%d tpMR=%d", i, res.RPMR, rpMR, tpdu[1])
		}
		if i > 0 && rpMR != byte(prevMR+1) {
			t.Fatalf("non-sequential modulo-256 MR at %d: prev=%d got=%d", i, prevMR, rpMR)
		}
		if rpMR == 0 {
			sawZeroMR = true
		}
		prevMR = rpMR

		tag := sipHeaderTagValue(req.Headers["From"])
		if !strings.HasPrefix(tag, "sms-") || len(tag) != len("sms-")+16 {
			t.Fatalf("unexpected From tag %q in From=%q", tag, req.Headers["From"])
		}
		if _, dup := seenTags[tag]; dup {
			t.Fatalf("duplicate From LocalTag %q at %d", tag, i)
		}
		seenTags[tag] = struct{}{}
	}
	if !sawZeroMR {
		t.Fatal("expected modulo-256 counter to wrap through 0 across 260 messages")
	}

	for i := 0; i < 2; i++ {
		if _, err := sms.SendIMSDeliveryReport(context.Background(), IMSDeliveryReportRequest{
			RemoteURI: "sip:ipsmgw@ims.example",
			Body:      BuildSMSRPAck(0x01),
		}); err != nil {
			t.Fatalf("SendIMSDeliveryReport(%d) error = %v", i, err)
		}
		req := transport.requests[count+i]
		tag := sipHeaderTagValue(req.Headers["From"])
		if !strings.HasPrefix(tag, "sms-report-") || len(tag) != len("sms-report-")+16 {
			t.Fatalf("unexpected report From tag %q", tag)
		}
		if _, dup := seenTags[tag]; dup {
			t.Fatalf("duplicate report From LocalTag %q", tag)
		}
		seenTags[tag] = struct{}{}
	}
}

func TestIMSSMSTransportRoutesViaSMSCAndEncodesRPDA(t *testing.T) {
	transport := &fakeSIPRequestTransport{responses: []voiceclient.SIPResponse{
		{StatusCode: 202, Reason: "Accepted"},
		{StatusCode: 202, Reason: "Accepted"},
	}}
	sms := IMSSMSTransport{
		Transport: transport,
		SMSC:      "+8613800250500",
		Profile:   voiceclient.IMSProfile{IMPU: "sip:user@ims.example", Domain: "ims.example"},
		Registration: voiceclient.RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@ims.example",
		},
	}

	if _, err := sms.SendSMSPart(context.Background(), SMSSendRequest{
		Peer:      "+18005551212",
		MessageID: "smsc-num",
		Part:      SMSPart{PartNo: 1, TotalParts: 1, Text: "hello"},
	}); err != nil {
		t.Fatalf("SendSMSPart(numeric SMSC) error = %v", err)
	}
	req := transport.requests[0]
	if req.URI != "sip:+8613800250500@ims.example" || !strings.Contains(req.Headers["To"], "sip:+8613800250500@ims.example") {
		t.Fatalf("expected Request-URI and To to target SMSC PSI, got URI=%q To=%q", req.URI, req.Headers["To"])
	}
	rpdu, err := ParseSMSRPDU(req.Body)
	if err != nil {
		t.Fatalf("ParseSMSRPDU() error = %v", err)
	}
	if rpdu.Destination != "+8613800250500" {
		t.Fatalf("RP-DA Destination = %q, want +8613800250500", rpdu.Destination)
	}
	// Verify TP-DA in SMS-SUBMIT still encodes the subscriber peer (+18005551212):
	// tpdu[0]=firstOctet, tpdu[1]=MR, tpdu[2]=11 digits (0x0b), tpdu[3]=0x91.
	if len(rpdu.TPDU) < 10 || rpdu.TPDU[2] != 11 || rpdu.TPDU[3] != 0x91 {
		t.Fatalf("unexpected TP-DA header in TPDU=%x", rpdu.TPDU)
	}

	// Alphanumeric SIP PSI SMSC routes Request-URI cleanly without failing BCD RP-DA encoding.
	sms.SMSC = "sip:ipsmgw@ims.example"
	if _, err := sms.SendSMSPart(context.Background(), SMSSendRequest{
		Peer:      "+18005551212",
		MessageID: "smsc-psi",
		Part:      SMSPart{PartNo: 1, TotalParts: 1, Text: "hello"},
	}); err != nil {
		t.Fatalf("SendSMSPart(PSI SMSC) error = %v", err)
	}
	psiReq := transport.requests[1]
	if psiReq.URI != "sip:ipsmgw@ims.example" {
		t.Fatalf("PSI SMSC URI = %q, want sip:ipsmgw@ims.example", psiReq.URI)
	}
}

func TestHandleIMSMessageExtractsInReplyToForDeliveryReportCorrelation(t *testing.T) {
	store := &fakeDeliveryStore{match: DeliveryPartMatch{MessageID: "msg-corr", PartNo: 1, State: "delivered"}}
	svc := NewService("dev-1", "310280233641503", store, nil)

	// 1. Standalone RP-ACK referencing original MO Call-ID via In-Reply-To.
	res, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		CallID:      "ipsmgw-ack-call",
		ContentType: IMS3GPPSMSContentType,
		Headers:     map[string][]string{"In-Reply-To": {"msg-corr-1@vowifi-go"}},
		Body:        BuildSMSRPAck(0x12),
	})
	if err != nil || res.DeliveryReport == nil || res.DeliveryReport.InReplyTo != "msg-corr-1@vowifi-go" || store.reportInReplyTo != "msg-corr-1@vowifi-go" {
		t.Fatalf("RP-ACK In-Reply-To correlation failed: res=%+v store.reportInReplyTo=%q err=%v", res, store.reportInReplyTo, err)
	}

	// 2. Standalone RP-ERROR referencing original MO Call-ID via In-Reply-To.
	store.reportInReplyTo = ""
	res, err = svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		CallID:      "ipsmgw-err-call",
		ContentType: IMS3GPPSMSContentType,
		Headers:     map[string][]string{"in-reply-to": {"msg-corr-2@vowifi-go"}},
		Body:        BuildSMSRPError(0x13, SMSRPCauseTemporaryFailure),
	})
	if err != nil || res.DeliveryReport == nil || res.DeliveryReport.InReplyTo != "msg-corr-2@vowifi-go" || store.reportInReplyTo != "msg-corr-2@vowifi-go" {
		t.Fatalf("RP-ERROR In-Reply-To correlation failed: res=%+v store.reportInReplyTo=%q err=%v", res, store.reportInReplyTo, err)
	}

	// 3. SMS-STATUS-REPORT inside RP-DATA referencing MO Call-ID via In-Reply-To.
	store.reportInReplyTo = ""
	tpdu := mustHex(t, "02070B918100551512F2627050214365006270502144000000")
	res, err = svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		CallID:      "ipsmgw-sr-call",
		ContentType: IMS3GPPSMSContentType,
		Headers:     map[string][]string{"In-Reply-To": {"msg-corr-3@vowifi-go"}},
		Body:        imsRPDataBody(0x14, tpdu),
	})
	if err != nil || res.DeliveryReport == nil || res.DeliveryReport.InReplyTo != "msg-corr-3@vowifi-go" || store.reportInReplyTo != "msg-corr-3@vowifi-go" {
		t.Fatalf("SMS-STATUS-REPORT In-Reply-To correlation failed: res=%+v store.reportInReplyTo=%q err=%v", res, store.reportInReplyTo, err)
	}
}

type failingAuditSMSTransport struct {
	err error
}

func (f failingAuditSMSTransport) SendSMSPart(context.Context, SMSSendRequest) (SMSSendResult, error) {
	return SMSSendResult{CallID: "fail-call", RPMR: 1, State: "failed", ErrorText: f.err.Error()}, f.err
}

func TestSendSMSWithOptionsDoesNotDispatchSMSSentOnFailure(t *testing.T) {
	dispatch := &fakeDispatcher{}
	svc := NewService("dev-1", "310280233641503", nil, dispatch)
	svc.SetSMSTransport(failingAuditSMSTransport{err: errors.New("network failure")})

	outcome, err := svc.SendSMSWithOptions(context.Background(), "+18005551212", "should fail", SendOptions{})
	if err == nil || outcome.State != "failed" {
		t.Fatalf("SendSMSWithOptions() outcome=%+v err=%v, want failed", outcome, err)
	}
	for _, ev := range dispatch.events {
		if _, ok := ev.(eventhost.SMSSent); ok {
			t.Fatalf("unexpected SMSSent event dispatched on failed SMS: %+v", ev)
		}
	}

	// Verify positive path still dispatches SMSSent.
	svc.SetSMSTransport(&fakeSMSTransport{})
	outcome, err = svc.SendSMSWithOptions(context.Background(), "+18005551212", "should succeed", SendOptions{})
	if err != nil || outcome.State != "sent" {
		t.Fatalf("SendSMSWithOptions(success) outcome=%+v err=%v", outcome, err)
	}
	if len(dispatch.events) != 1 {
		t.Fatalf("expected 1 SMSSent event after success, got %d", len(dispatch.events))
	}
}

func TestIMSUSSDConcurrentSetTransportAndIPv6SDP(t *testing.T) {
	ipv6Body := string(buildIMSUSSDMultipartBody("2001:db8::10", "b1", []byte("<ussd-data/>")))
	if !strings.Contains(ipv6Body, "o=- 0 0 IN IP6 2001:db8::10\r\n") || !strings.Contains(ipv6Body, "c=IN IP6 2001:db8::10\r\n") {
		t.Fatalf("IPv6 USSD SDP missing IN IP6: %s", ipv6Body)
	}
	ipv4Body := string(buildIMSUSSDMultipartBody("10.20.30.40", "b1", []byte("<ussd-data/>")))
	if !strings.Contains(ipv4Body, "o=- 0 0 IN IP4 10.20.30.40\r\n") || !strings.Contains(ipv4Body, "c=IN IP4 10.20.30.40\r\n") {
		t.Fatalf("IPv4 USSD SDP missing IN IP4: %s", ipv4Body)
	}

	svc := NewService("dev-1", "310280233641503", nil, nil)
	ussdTransport := &IMSUSSDTransport{}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(3)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				svc.SetUSSDTransport(ussdTransport)
				svc.SetUSSDTransport(nil)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = svc.HandleIMSUSSDInfo(context.Background(), IMSUSSDDialogRequest{
					CallID:      "non-existent",
					ContentType: IMSUSSDContentType,
					InfoPackage: IMSUSSDInfoPackage,
					Body:        []byte(`<ussd-data><language>en</language><ussd-string>ok</ussd-string></ussd-data>`),
				})
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = svc.HandleIMSUSSDBye(context.Background(), IMSUSSDDialogRequest{
					CallID: "non-existent",
				})
			}
		}
	}()
	time.Sleep(25 * time.Millisecond)
	close(stop)
	wg.Wait()
}
