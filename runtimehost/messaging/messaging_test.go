package messaging

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/runtimehost/eventhost"
)

func TestSegmentSMSGSM7(t *testing.T) {
	parts := SegmentSMS(strings.Repeat("a", 161), "")
	if len(parts) != 2 {
		t.Fatalf("parts=%d, want 2", len(parts))
	}
	if parts[0].Encoding != "gsm7" || len([]rune(parts[0].Text)) != 153 || len(parts[0].UDH) == 0 {
		t.Fatalf("first part=%+v", parts[0])
	}
	if parts[1].PartNo != 2 || parts[1].TotalParts != 2 {
		t.Fatalf("second part=%+v", parts[1])
	}
}

func TestSegmentSMSUCS2(t *testing.T) {
	parts := SegmentSMS(strings.Repeat("你", 71), "")
	if len(parts) != 2 {
		t.Fatalf("parts=%d, want 2", len(parts))
	}
	if parts[0].Encoding != "ucs2" || len([]rune(parts[0].Text)) != 67 {
		t.Fatalf("first part=%+v", parts[0])
	}
}

func TestSendSMSWithTransportStoresEveryPart(t *testing.T) {
	store := &fakeDeliveryStore{}
	dispatch := &fakeDispatcher{}
	transport := &fakeSMSTransport{}
	svc := NewService("dev-1", "310280233641503", store, dispatch)
	svc.SetSMSTransport(transport)

	out, err := svc.SendSMSWithOptions(context.Background(), "+18005551212", strings.Repeat("a", 161), SendOptions{})
	if err != nil {
		t.Fatalf("SendSMSWithOptions() error = %v", err)
	}
	if out.Parts != 2 || out.PartsTotal != 2 || out.State != "sent" {
		t.Fatalf("outcome=%+v", out)
	}
	if len(transport.requests) != 2 || transport.requests[0].Part.PartNo != 1 || transport.requests[1].Part.PartNo != 2 {
		t.Fatalf("transport requests=%+v", transport.requests)
	}
	if store.createdPartsTotal != 2 || len(store.parts) != 2 || store.state != "sent" || store.acks != 2 {
		t.Fatalf("store=%+v parts=%+v", store, store.parts)
	}
	if len(dispatch.events) != 1 {
		t.Fatalf("events=%d", len(dispatch.events))
	}
	sent, ok := dispatch.events[0].(eventhost.SMSSent)
	if !ok || sent.TotalParts != 2 {
		t.Fatalf("event=%+v", dispatch.events[0])
	}
}

func TestSendSMSWithTransportFailureMarksDeliveryFailed(t *testing.T) {
	store := &fakeDeliveryStore{}
	transport := &fakeSMSTransport{failPart: 2}
	svc := NewService("dev-1", "310280233641503", store, nil)
	svc.SetSMSTransport(transport)

	out, err := svc.SendSMSWithOptions(context.Background(), "+18005551212", strings.Repeat("a", 161), SendOptions{})
	if err == nil {
		t.Fatal("SendSMSWithOptions() err=nil, want failure")
	}
	if out.State != "failed" || out.Parts != 1 || store.state != "failed" || store.acks != 1 {
		t.Fatalf("outcome=%+v store=%+v", out, store)
	}
	if !strings.Contains(store.lastError, "part failed") {
		t.Fatalf("lastError=%q", store.lastError)
	}
}

type fakeSMSTransport struct {
	requests []SMSSendRequest
	failPart int
}

func (t *fakeSMSTransport) SendSMSPart(ctx context.Context, req SMSSendRequest) (SMSSendResult, error) {
	t.requests = append(t.requests, req)
	if req.Part.PartNo == t.failPart {
		return SMSSendResult{State: "failed", ErrorText: "part failed"}, errors.New("part failed")
	}
	return SMSSendResult{CallID: "call", RPMR: req.Part.PartNo, State: "sent"}, nil
}

type fakeDispatcher struct {
	events []eventhost.Event
}

func (d *fakeDispatcher) Dispatch(ctx context.Context, ev eventhost.Event) {
	d.events = append(d.events, ev)
}

type fakeDeliveryStore struct {
	createdPartsTotal int
	parts             []DeliveryPartStatus
	state             string
	lastError         string
	acks              int
}

func (s *fakeDeliveryStore) CreateSMSDelivery(messageID, imsi, deviceID, peer, content string, partsTotal int, at time.Time) error {
	s.createdPartsTotal = partsTotal
	return nil
}

func (s *fakeDeliveryStore) UpsertSMSDeliveryPart(messageID string, partNo int, callID string, rpMR int, state string, sentAt time.Time) error {
	s.parts = append(s.parts, DeliveryPartStatus{PartNo: partNo, CallID: callID, RPMR: rpMR, State: state, SentAt: sentAt})
	return nil
}

func (s *fakeDeliveryStore) MarkSMSDeliveryPartReport(inReplyTo, callID, deviceID string, rpMR int, state string, sipCode int, rpCause int, errText string, at time.Time) (DeliveryPartMatch, error) {
	return DeliveryPartMatch{}, nil
}

func (s *fakeDeliveryStore) RecomputeSMSDelivery(messageID string, at time.Time) error {
	return nil
}

func (s *fakeDeliveryStore) UpdateSMSDeliveryState(messageID, state, lastError string, acks int, at time.Time) error {
	s.state = state
	s.lastError = lastError
	s.acks = acks
	return nil
}

func (s *fakeDeliveryStore) GetSMSDeliveryStatus(messageID string) (*DeliveryStatus, error) {
	return nil, ErrDeliveryNotFound
}
