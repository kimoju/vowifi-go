package messaging

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/kimoju/vowifi-go/runtimehost/eventhost"
	"github.com/kimoju/vowifi-go/runtimehost/voiceclient"
)

func TestRound2MSG01AlphanumericAddressEncodeDecodeNibbles(t *testing.T) {
	for _, sender := range []string{"GOOGLE", "Verify", "1069001", "BANK-OTP", "PayPal12345"} {
		digits, toa, packed, err := EncodeSMSAlphanumericAddress(sender)
		if err != nil {
			t.Fatalf("EncodeSMSAlphanumericAddress(%q) error = %v", sender, err)
		}
		if toa != 0xd0 {
			t.Fatalf("toa=0x%02x want 0xd0", toa)
		}
		wantNibbles := (len(sender)*7 + 3) / 4
		if digits != wantNibbles {
			t.Fatalf("sender=%q digits=%d want %d semi-octets", sender, digits, wantNibbles)
		}
		octets, err := smsAddressOctets(digits, toa)
		if err != nil || octets != (digits+1)/2 || octets != len(packed) {
			t.Fatalf("sender=%q smsAddressOctets(%d, 0x%02x)=%d err=%v packed=%d", sender, digits, toa, octets, err, len(packed))
		}
		// Build a full SMS-DELIVER TPDU and verify ParseSMSDeliverTPDU decodes both TP-OA and TP-UD cleanly.
		var tpdu bytes.Buffer
		tpdu.WriteByte(0x04) // SMS-DELIVER, MMS=1
		tpdu.WriteByte(byte(digits))
		tpdu.WriteByte(toa)
		tpdu.Write(packed)
		tpdu.WriteByte(0x00) // TP-PID
		tpdu.WriteByte(0x00) // TP-DCS GSM-7
		ts, err := encodeSMSTimestamp(time.Date(2026, 11, 14, 10, 20, 30, 0, time.UTC))
		if err != nil {
			t.Fatalf("encodeSMSTimestamp error = %v", err)
		}
		tpdu.Write(ts)
		msgText := "Code 482910"
		ud, udl, _, err := encodeSMSUserDataWithLanguage(msgText, "gsm7", nil, 0, 0)
		if err != nil {
			t.Fatalf("encodeSMSUserDataWithLanguage error = %v", err)
		}
		tpdu.WriteByte(byte(udl))
		tpdu.Write(ud)

		deliver, err := ParseSMSDeliverTPDU(tpdu.Bytes())
		if err != nil {
			t.Fatalf("ParseSMSDeliverTPDU(%q) error = %v", sender, err)
		}
		if deliver.Sender != sender || deliver.Text != msgText {
			t.Fatalf("deliver=%+v want sender=%q text=%q", deliver, sender, msgText)
		}
	}
}

func TestRound2MSG02InboundRPDataErrorsReturn200OKAndAccurateRPError(t *testing.T) {
	svc := NewService("dev-1", "310280233641503", nil, nil)

	// 1. Malformed TPDU -> SIP 200 OK + RP-ERROR Cause 96 (Invalid mandatory information)
	resMalformed, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		FromURI:     "sip:smsc@ims.example",
		ToURI:       "sip:user@ims.example",
		CallID:      "mt-malformed",
		ContentType: IMS3GPPSMSContentType,
		Body:        imsRPDataBody(0x11, []byte{0x00, 0x05}),
	})
	if err == nil || resMalformed.StatusCode != 200 || resMalformed.ReplyContentType != IMS3GPPSMSContentType {
		t.Fatalf("malformed res=%+v err=%v", resMalformed, err)
	}
	if !bytes.Equal(resMalformed.ReplyBody, BuildSMSRPError(0x11, SMSRPCauseInvalidMandatoryInfo)) {
		t.Fatalf("malformed ReplyBody=%x want %x", resMalformed.ReplyBody, BuildSMSRPError(0x11, SMSRPCauseInvalidMandatoryInfo))
	}

	// 2. Unsupported MTI (0x01 SMS-SUBMIT on MT RP-DATA) -> SIP 200 OK + RP-ERROR Cause 97
	submitTPDU, err := BuildSMSSubmitTPDU("+18005551212", SMSPart{Text: "hi", Encoding: "gsm7"}, 1)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU error = %v", err)
	}
	resMTI, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		FromURI:     "sip:smsc@ims.example",
		ToURI:       "sip:user@ims.example",
		CallID:      "mt-unsupported-mti",
		ContentType: IMS3GPPSMSContentType,
		Body:        imsRPDataBody(0x12, submitTPDU),
	})
	if err == nil || resMTI.StatusCode != 200 || !bytes.Equal(resMTI.ReplyBody, BuildSMSRPError(0x12, SMSRPCauseMessageTypeNonExistent)) {
		t.Fatalf("unsupported MTI res=%+v err=%v body=%x", resMTI, err, resMTI.ReplyBody)
	}
}

func TestRound2MSG03StandardUSSDXMLInteractiveMenuAndMultipartCRLF(t *testing.T) {
	// Standard 3GPP TS 24.390 §5.1.2 <ussd-data> without <UnstructuredSS-*> keeps INFO menu session open!
	standardXML := []byte(`<?xml version="1.0" encoding="UTF-8"?><ussd-data><language>en</language><ussd-string>1. Check Balance</ussd-string></ussd-data>`)
	transport := &fakeSIPRequestTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:*100%23@ims.example;user=dialstring>;tag=as-1"},
				"Contact": {"<sip:ussd-as@ims.example>"},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers:    map[string][]string{"Content-Type": {IMSUSSDContentType}},
			Body:       standardXML,
		},
	}}
	ussd := &IMSUSSDTransport{
		Transport: transport,
		Profile:   voiceclient.IMSProfile{IMPU: "sip:user@ims.example", Domain: "ims.example", LocalIP: "2001:db8::10"},
		Registration: voiceclient.RegistrationBinding{
			ContactURI:     "sip:user@[2001:db8::10]:5060",
			PublicIdentity: "sip:user@ims.example",
		},
	}
	svc := NewService("dev-1", "310280233641503", nil, &fakeDispatcher{})
	svc.SetUSSDTransport(ussd)

	first, err := svc.SendUSSD(context.Background(), "*100#")
	if err != nil {
		t.Fatalf("SendUSSD error = %v", err)
	}
	// Verify outbound INVITE XML has no <UnstructuredSS-Request> direct child and SDP ends with \r\n before \r\n--boundary.
	inviteBody := string(transport.requests[0].Body)
	if strings.Contains(inviteBody, "UnstructuredSS-Request") {
		t.Fatalf("outbound INVITE emitted non-XSD UnstructuredSS-Request: %s", inviteBody)
	}
	if !strings.Contains(inviteBody, "a=recvonly\r\n\r\n--") {
		t.Fatalf("multipart SDP missing trailing CRLF before boundary delimiter: %q", inviteBody)
	}

	// Inbound INFO with standard <ussd-data> (no operation tag) must NOT terminate the session.
	infoRes, err := svc.HandleIMSUSSDInfo(context.Background(), IMSUSSDDialogRequest{
		CallID:      "ussd-" + smsToken(first.SessionID) + "@vowifi-go",
		CSeq:        2,
		ContentType: IMSUSSDContentType,
		InfoPackage: IMSUSSDInfoPackage,
		Body:        standardXML,
	})
	if err != nil || infoRes.USSD.Done || !svc.hasUSSDSession(first.SessionID) {
		t.Fatalf("infoRes=%+v err=%v active=%v, want active menu session", infoRes, err, svc.hasUSSDSession(first.SessionID))
	}

	// User reply via ContinueUSSD succeeds on the active session.
	cont, err := svc.ContinueUSSD(context.Background(), first.SessionID, "1")
	if err != nil || cont.Done {
		t.Fatalf("ContinueUSSD cont=%+v err=%v", cont, err)
	}
}

func TestRound2MSG04USSDPostDigestAuthCSeqAndUniqueTags(t *testing.T) {
	authSession := voiceclient.NewDigestAuthSessionWithChallengeInput("Authorization", "", voiceclient.DigestAuthState{}, func(ch voiceclient.DigestChallenge, method string) (voiceclient.DigestAuthInput, error) {
		return voiceclient.DigestAuthInput{
			Username: "user@ims.example",
			Password: "secret",
			Method:   method,
			URI:      "sip:*100%23@ims.example;user=dialstring",
			CNonce:   "cnonce1",
		}, nil
	})
	transport := &fakeSIPRequestTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="n1", algorithm=MD5, qop="auth"`},
				"To":               {"<sip:*100%23@ims.example;user=dialstring>;tag=chal-tag"},
			},
		},
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
			Body:       []byte(`<?xml version="1.0" encoding="UTF-8"?><ussd-data><language>en</language><ussd-string>Done</ussd-string><anyExt><UnstructuredSS-Notify/></anyExt></ussd-data>`),
		},
	}}
	ussd := &IMSUSSDTransport{
		Transport: transport,
		Profile:   voiceclient.IMSProfile{IMPU: "sip:user@ims.example", Domain: "ims.example", LocalIP: "192.0.2.10"},
		Registration: voiceclient.RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@ims.example",
			AuthSession:    authSession,
		},
	}
	res1, err := ussd.ExecuteUSSD(context.Background(), USSDRequest{Command: "*100#"})
	if err != nil {
		t.Fatalf("ExecuteUSSD() error = %v", err)
	}
	// transport.writes[0] is non-2xx ACK to 401 (CSeq 1 ACK); transport.writes[1] is 2xx ACK to 200 OK (must be CSeq 2 ACK!).
	if len(transport.writes) != 2 {
		t.Fatalf("writes=%+v, want 401 ACK and 200 ACK", transport.writes)
	}
	if transport.writes[1].Headers["CSeq"] != "2 ACK" {
		t.Fatalf("200 OK ACK CSeq=%q, want \"2 ACK\"", transport.writes[1].Headers["CSeq"])
	}
	// ContinueUSSD must use CSeq 3 INFO (not colliding with CSeq 2 INVITE).
	if _, err := ussd.ContinueUSSD(context.Background(), USSDRequest{SessionID: res1.SessionID, Input: "1"}); err != nil {
		t.Fatalf("ContinueUSSD() error = %v", err)
	}
	if got := transport.requests[2].Headers["CSeq"]; got != "3 INFO" {
		t.Fatalf("ContinueUSSD CSeq=%q, want \"3 INFO\"", got)
	}
}

func TestRound2MSG05MOSMSMandatoryRPDAHeadersAndNoContact(t *testing.T) {
	transport := &fakeSIPRequestTransport{responses: []voiceclient.SIPResponse{{StatusCode: 202, Reason: "Accepted"}}}
	sms := &IMSSMSTransport{
		Transport:     transport,
		Profile:       voiceclient.IMSProfile{IMPU: "sip:user@ims.example", Domain: "ims.example"},
		Registration:  voiceclient.RegistrationBinding{ContactURI: "sip:user@192.0.2.10:5060", PublicIdentity: "sip:user@ims.example"},
		SMSC:          "sip:smsc-psi.ims.example",
		SMSCRPAddress: "+12063130004",
	}
	_, err := sms.SendSMSPart(context.Background(), SMSSendRequest{
		MessageID: "m1",
		Peer:      "<tel:+1.800.555.1212>",
		Part:      SMSPart{PartNo: 1, TotalParts: 1, Text: "hi", Encoding: "gsm7"},
	})
	if err != nil {
		t.Fatalf("SendSMSPart error = %v", err)
	}
	msg := transport.requests[0]
	if _, hasContact := msg.Headers["Contact"]; hasContact {
		t.Fatalf("SIP MESSAGE must not contain Contact header per RFC 3428 §4: %+v", msg.Headers)
	}
	if msg.Headers["Request-Disposition"] != "no-fork" || msg.Headers["Content-Transfer-Encoding"] != "binary" {
		t.Fatalf("SIP MESSAGE missing TS 24.341 headers: %+v", msg.Headers)
	}
	rpdu, err := ParseSMSRPDU(msg.Body)
	if err != nil || rpdu.Destination != "+12063130004" {
		t.Fatalf("MO RP-DATA Destination=%q err=%v, want +12063130004", rpdu.Destination, err)
	}
}

type callIDMatchingStore struct {
	mu      sync.Mutex
	sent    map[string]int
	matched bool
	state   string
	errText string
	rpCause int
}

func (s *callIDMatchingStore) CreateSMSDelivery(messageID, imsi, deviceID, peer, content string, partsTotal int, at time.Time) error {
	return nil
}
func (s *callIDMatchingStore) UpsertSMSDeliveryPart(messageID string, partNo int, callID string, rpMR int, state string, sentAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sent == nil {
		s.sent = make(map[string]int)
	}
	s.sent[callID] = partNo
	return nil
}
func (s *callIDMatchingStore) MarkSMSDeliveryPartReport(inReplyTo, callID, deviceID string, rpMR int, state string, sipCode int, rpCause int, errText string, at time.Time) (DeliveryPartMatch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if partNo, ok := s.sent[inReplyTo]; ok {
		s.matched = true
		s.state = state
		s.errText = errText
		s.rpCause = rpCause
		return DeliveryPartMatch{MessageID: "m1", PartNo: partNo, State: state}, nil
	}
	return DeliveryPartMatch{}, ErrDeliveryNotFound
}
func (s *callIDMatchingStore) RecomputeSMSDelivery(messageID string, at time.Time) error { return nil }
func (s *callIDMatchingStore) UpdateSMSDeliveryState(messageID, state, lastError string, acks int, at time.Time) error {
	return nil
}
func (s *callIDMatchingStore) GetSMSDeliveryStatus(messageID string) (*DeliveryStatus, error) {
	return nil, ErrDeliveryNotFound
}

func TestRound2MSG06RPAckSentAndStatusReportTPStatusCorrelation(t *testing.T) {
	store := &callIDMatchingStore{}
	sipTransport := &fakeSIPRequestTransport{responses: []voiceclient.SIPResponse{{StatusCode: 202, Reason: "Accepted"}}}
	smsTransport := &IMSSMSTransport{
		Transport:    sipTransport,
		Profile:      voiceclient.IMSProfile{IMPU: "sip:user@ims.example", Domain: "ims.example"},
		Registration: voiceclient.RegistrationBinding{PublicIdentity: "sip:user@ims.example"},
	}
	svc := NewService("dev-1", "310280233641503", store, nil)
	svc.SetSMSTransport(smsTransport)

	out, err := svc.SendSMSWithOptions(context.Background(), "+18005551212", "hello", SendOptions{})
	if err != nil {
		t.Fatalf("SendSMSWithOptions error = %v", err)
	}
	sentRPDU, err := ParseSMSRPDU(sipTransport.requests[0].Body)
	if err != nil {
		t.Fatalf("ParseSMSRPDU error = %v", err)
	}
	sentCallID := sipTransport.requests[0].Headers["Call-ID"]

	// 1. MO RP-ACK (without TPDU) marks state "sent", NOT "delivered".
	ackRes, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		CallID:      "mt-rpack-call",
		Headers:     map[string][]string{"In-Reply-To": {sentCallID}},
		ContentType: IMS3GPPSMSContentType,
		Body:        BuildSMSRPAck(sentRPDU.MR),
	})
	if err != nil || ackRes.DeliveryReport == nil || ackRes.DeliveryReport.State != "sent" || store.state != "sent" {
		t.Fatalf("MO RP-ACK result=%+v storeState=%q err=%v, want state=\"sent\"", ackRes, store.state, err)
	}

	// 2. Subsequent MT SMS-STATUS-REPORT with TP-ST=0x01 (forwarded/delivered) has empty InReplyTo & new CallID,
	// correlates via (recipient, TP-MR) -> sentCallID, keeps RPCause=0 and ErrorText=""!
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	srTPDU, err := BuildSMSStatusReportTPDU(SMSStatusReport{
		FirstOctet: 0x02,
		Reference:  sentRPDU.MR,
		Recipient:  "+18005551212",
		Timestamp:  now,
		DoneAt:     now.Add(5 * time.Second),
		Status:     0x01,
	})
	if err != nil {
		t.Fatalf("BuildSMSStatusReportTPDU error = %v", err)
	}
	srRes, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		CallID:      "unrelated-mt-status-call-" + out.MessageID,
		ContentType: IMS3GPPSMSContentType,
		Body:        imsRPDataBody(0x77, srTPDU),
	})
	if err != nil || srRes.DeliveryReport == nil {
		t.Fatalf("SMS-STATUS-REPORT res=%+v err=%v", srRes, err)
	}
	if srRes.DeliveryReport.State != "delivered" || srRes.DeliveryReport.RPCause != 0 || srRes.DeliveryReport.ErrorText != "" || store.errText != "" || store.state != "delivered" {
		t.Fatalf("report=%+v storeState=%q storeErr=%q", srRes.DeliveryReport, store.state, store.errText)
	}
}

func TestRound2MSG07USSDInactivityTimeoutSendsByeAndCleansUp(t *testing.T) {
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
		Transport:         transport,
		Profile:           voiceclient.IMSProfile{IMPU: "sip:user@ims.example", Domain: "ims.example"},
		Registration:      voiceclient.RegistrationBinding{ContactURI: "sip:user@192.0.2.10:5060", PublicIdentity: "sip:user@ims.example"},
		InactivityTimeout: 40 * time.Millisecond,
	}
	res, err := ussd.ExecuteUSSD(context.Background(), USSDRequest{SessionID: "idle-session", Command: "*100#"})
	if err != nil || res.Done {
		t.Fatalf("ExecuteUSSD res=%+v err=%v", res, err)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, active := ussd.session("idle-session"); !active {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, active := ussd.session("idle-session"); active {
		t.Fatal("idle USSD session was not reaped after InactivityTimeout")
	}
}

type flakyMultipartTransport struct {
	mu       sync.Mutex
	calls    int
	requests []SMSSendRequest
}

func (f *flakyMultipartTransport) SendSMSPart(ctx context.Context, req SMSSendRequest) (SMSSendResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.requests = append(f.requests, req)
	if f.calls == 2 {
		return SMSSendResult{
			CallID:     smsCallID(req),
			RPMR:       req.Part.TPMR,
			State:      "failed",
			SIPCode:    503,
			ErrorText:  "Service Unavailable",
			RetryAfter: time.Second,
			Headers:    map[string][]string{"Retry-After": {"0"}},
		}, errors.New("Service Unavailable")
	}
	return SMSSendResult{CallID: smsCallID(req), RPMR: req.Part.TPMR, State: "accepted", SIPCode: 202}, nil
}

func TestRound2MSG08MultipartFailureQueuesRemainingPartsAndPreservesTPMR(t *testing.T) {
	store := &fakeRetryDeliveryStore{}
	flaky := &flakyMultipartTransport{}
	svc := NewService("dev-1", "310280233641503", store, nil)
	svc.SetSMSTransport(flaky)

	// 3-part GSM-7 SMS: Part 1 succeeds, Part 2 fails with 503 -> both Part 2 AND Part 3 must be queued!
	_, err := svc.SendSMSWithOptions(context.Background(), "+18005551212", strings.Repeat("x", 320), SendOptions{})
	if err == nil {
		t.Fatal("expected Part 2 failure")
	}
	if len(store.retryUpserts) != 2 {
		t.Fatalf("retryUpserts=%d, want 2 (Part 2 and Part 3)", len(store.retryUpserts))
	}
	part2OrigTPMR := flaky.requests[1].Part.TPMR
	if !store.retryUpserts[0].Plan.RetryAfterPresent {
		t.Fatalf("PlanIMSSMSSubmitRetry stripped Retry-After: 0 header: %+v", store.retryUpserts[0].Plan)
	}

	// Replay both due envelopes; Part 2 must reuse original TPMR with RejectDuplicates=true, Part 3 sends with RejectDuplicates=false.
	results, err := svc.ReplayDueIMSMessagingRetries(context.Background(), store.retryUpserts, time.Now().Add(2*time.Second), 10)
	if err != nil || len(results) != 2 {
		t.Fatalf("ReplayDueIMSMessagingRetries results=%+v err=%v", results, err)
	}
	if len(flaky.requests) != 4 {
		t.Fatalf("total SendSMSPart calls=%d want 4", len(flaky.requests))
	}
	replayedPart2 := flaky.requests[2]
	replayedPart3 := flaky.requests[3]
	if replayedPart2.Part.PartNo != 2 || replayedPart2.Part.TPMR != part2OrigTPMR || !replayedPart2.Part.RejectDuplicates {
		t.Fatalf("replayedPart2=%+v want PartNo=2 TPMR=%d RejectDuplicates=true", replayedPart2.Part, part2OrigTPMR)
	}
	if replayedPart3.Part.PartNo != 3 || replayedPart3.Part.RejectDuplicates {
		t.Fatalf("replayedPart3=%+v want PartNo=3 RejectDuplicates=false on first attempt", replayedPart3.Part)
	}
}

func TestRound2MSG09MWISimpleMessageSummaryAndDiscard0xC0SMS(t *testing.T) {
	dispatch := &fakeDispatcher{}
	svc := NewService("dev-1", "310280233641503", nil, dispatch)

	// 1. Out-of-dialog SIP NOTIFY with application/simple-message-summary
	mwiBody := []byte("Messages-Waiting: yes\r\nMessage-Account: sip:vm@ims.example\r\nVoice-Message: 3/1 (1/0)\r\n")
	summary, err := svc.HandleIMSMessageSummaryNotify(context.Background(), mwiBody, "sip:vm@ims.example", "sip:user@ims.example")
	if err != nil || !summary.MessagesWaiting || summary.VoiceNew != 3 {
		t.Fatalf("HandleIMSMessageSummaryNotify summary=%+v err=%v", summary, err)
	}

	// 2. Empty 3GPP TS 23.038 0xC8 (Active Voicemail Discard MWI, TP-UDL=0) SMS must return 200 OK + RP-ACK and emit MWI without SMSReceived!
	var tpdu bytes.Buffer
	tpdu.Write([]byte{0x04, 0x05, 0x81, 0x01, 0x80, 0xf6, 0x00, 0xc8})
	ts, _ := encodeSMSTimestamp(time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC))
	tpdu.Write(ts)
	tpdu.WriteByte(0x00) // TP-UDL = 0
	smsRes, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		FromURI:     "sip:smsc@ims.example",
		ToURI:       "sip:user@ims.example",
		ContentType: IMS3GPPSMSContentType,
		Body:        imsRPDataBody(0x21, tpdu.Bytes()),
	})
	if err != nil || smsRes.StatusCode != 200 || !bytes.Equal(smsRes.ReplyBody, BuildSMSRPAck(0x21)) {
		t.Fatalf("0xC8 empty MWI SMS res=%+v err=%v body=%x", smsRes, err, smsRes.ReplyBody)
	}
	if len(dispatch.events) != 2 {
		t.Fatalf("events=%+v want 2 MessageWaitingEvents and 0 SMSReceived", dispatch.events)
	}
	for i, ev := range dispatch.events {
		if _, isSMS := ev.(eventhost.SMSReceived); isSMS {
			t.Fatalf("event[%d] unexpectedly emitted SMSReceived for MWI: %+v", i, ev)
		}
	}
}

func TestRound2MSG10And11BoundsEscapeCPIMCharsetAndConcatWrap(t *testing.T) {
	// MSG-10: Oversized unsegmented TPDU rejected cleanly
	if _, err := BuildSMSSubmitTPDU("+18005551212", SMSPart{Text: strings.Repeat("a", 161), Encoding: "gsm7"}, 1); err == nil {
		t.Fatal("expected >160 septet single TPDU error")
	}
	if got := normalizeSMSNumber(`"Alice" <tel:+1.555.234.5678;ext=9>`); got != "+15552345678" {
		t.Fatalf("normalizeSMSNumber=%q want +15552345678", got)
	}

	// MSG-11: GSM-7 0x1B must not be treated as locking-table character and unknown escape maps to space ' '
	if _, ok := gsm7SeptetLen("hello\x1bworld"); ok {
		t.Fatal("raw ESC 0x1b must not be accepted as a GSM-7 character")
	}
	if got := decodeGSM7([]byte{0x1b, 0x41}); got != " A" {
		t.Fatalf("decodeGSM7([0x1b, 0x41])=%q want \" A\"", got)
	}

	// MSG-11: CPIM inner From + DateTime + UTF-16BE text/plain
	dispatch := &fakeDispatcher{}
	svc := NewService("dev-1", "310280233641503", nil, dispatch)
	u16 := utf16.Encode([]rune("Hi!"))
	var u16Bytes []byte
	for _, w := range u16 {
		u16Bytes = append(u16Bytes, byte(w>>8), byte(w))
	}
	cpim := []byte("From: <sip:+14155550199@ims.example>\r\nTo: <sip:user@ims.example>\r\nDateTime: 2026-11-14T08:30:00Z\r\n\r\nContent-Type: text/plain; charset=utf-16be\r\n\r\n")
	cpim = append(cpim, u16Bytes...)
	res, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		FromURI:     "sip:as-gateway@ims.example",
		ToURI:       "sip:user@ims.example",
		ContentType: IMSCPIMContentType,
		Body:        cpim,
	})
	if err != nil || res.Incoming == nil || res.Incoming.Content != "Hi!" || res.Incoming.Sender != "<sip:+14155550199@ims.example>" {
		t.Fatalf("CPIM UTF-16BE res=%+v incoming=%+v err=%v", res, res.Incoming, err)
	}
	if !res.Incoming.Timestamp.Equal(time.Date(2026, 11, 14, 8, 30, 0, 0, time.UTC)) {
		t.Fatalf("CPIM DateTime=%s", res.Incoming.Timestamp)
	}

	// MSG-11: Concat ref wrap-around with stale incomplete part 1 resets cleanly instead of splicing old part 1!
	_, ready := svc.collectSMSConcatPart(IncomingSMS{Sender: "10086", Recipient: "me", Content: "OLD-1"}, SMSConcatInfo{IsConcat: true, Ref: 9, RefBits: 8, Total: 2, Seq: 1}, time.Now())
	if ready {
		t.Fatal("single part should not complete 2-part concat")
	}
	_, ready = svc.collectSMSConcatPart(IncomingSMS{Sender: "10086", Recipient: "me", Content: "NEW-1"}, SMSConcatInfo{IsConcat: true, Ref: 9, RefBits: 8, Total: 2, Seq: 1}, time.Now())
	if ready {
		t.Fatal("new part 1 should replace stale part 1 without completing")
	}
	assembled, ready := svc.collectSMSConcatPart(IncomingSMS{Sender: "10086", Recipient: "me", Content: "-NEW-2"}, SMSConcatInfo{IsConcat: true, Ref: 9, RefBits: 8, Total: 2, Seq: 2}, time.Now())
	if !ready || assembled.Content != "NEW-1-NEW-2" {
		t.Fatalf("assembled=%+v ready=%v want NEW-1-NEW-2", assembled, ready)
	}
}
