package runtimehost

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/runtimehost/eventhost"
	"github.com/iniwex5/vowifi-go/runtimehost/identity"
	"github.com/iniwex5/vowifi-go/runtimehost/messaging"
)

type testModem struct{}

func (testModem) DeviceID() string                           { return "dev-1" }
func (testModem) IsHealthy() bool                            { return true }
func (testModem) IsSimInserted() bool                        { return true }
func (testModem) QuerySIMInserted() (bool, error)            { return true, nil }
func (testModem) GetRegStatus() (int, string)                { return 1, "registered" }
func (testModem) GetNetworkMode() string                     { return "LTE" }
func (testModem) Stop()                                      {}
func (testModem) OpenLogicalChannel(aid string) (int, error) { return 1, nil }
func (testModem) CloseLogicalChannel(channel int) error      { return nil }
func (testModem) TransmitAPDU(channel int, hexAPDU string) (string, error) {
	return "9000", nil
}

type testIMSRegistrar struct {
	result IMSRegistrationResult
	err    error
	config IMSRegistrationConfig
}

func (r *testIMSRegistrar) RegisterIMS(ctx context.Context, cfg IMSRegistrationConfig) (IMSRegistrationResult, error) {
	r.config = cfg
	if r.err != nil {
		return IMSRegistrationResult{}, r.err
	}
	return r.result, nil
}

func TestStartUsesIMSRegistrarResult(t *testing.T) {
	registrar := &testIMSRegistrar{result: IMSRegistrationResult{
		Registered: true,
		StatusCode: 200,
		Reason:     "ims registered",
		Server:     "pcscf",
	}}
	inst, err := Start(context.Background(), StartRequest{
		DeviceID:     "dev-1",
		TraceID:      "trace-1",
		Access:       NewModemAccessAdapter(testModem{}),
		IMSRegistrar: registrar,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	st := inst.State()
	if !st.IMSReady || st.LastReason != "ims registered" {
		t.Fatalf("state=%+v", st)
	}
	if registrar.config.DeviceID != "dev-1" || registrar.config.TraceID != "trace-1" || registrar.config.Access == nil {
		t.Fatalf("registrar config=%+v", registrar.config)
	}
}

func TestStartRejectsIMSRegistrationFailure(t *testing.T) {
	registrar := &testIMSRegistrar{err: errors.New("401 after AKA")}
	_, err := Start(context.Background(), StartRequest{
		DeviceID:     "dev-1",
		Access:       NewModemAccessAdapter(testModem{}),
		IMSRegistrar: registrar,
	})
	if err == nil || !strings.Contains(err.Error(), "IMS registration failed") {
		t.Fatalf("Start() err=%v, want IMS registration failure", err)
	}
}

func TestStartRejectsUnregisteredIMSResult(t *testing.T) {
	registrar := &testIMSRegistrar{result: IMSRegistrationResult{Registered: false, StatusCode: 403, Reason: "Forbidden"}}
	_, err := Start(context.Background(), StartRequest{
		DeviceID:     "dev-1",
		Access:       NewModemAccessAdapter(testModem{}),
		IMSRegistrar: registrar,
	})
	if err == nil || !strings.Contains(err.Error(), "IMS registration rejected") {
		t.Fatalf("Start() err=%v, want rejected IMS registration", err)
	}
}

func TestStartWithoutIMSRegistrarKeepsCompatibilityReady(t *testing.T) {
	inst, err := Start(context.Background(), StartRequest{
		DeviceID: "dev-1",
		Access:   NewModemAccessAdapter(testModem{}),
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if !inst.State().IMSReady {
		t.Fatalf("IMSReady=false without explicit registrar")
	}
}

func TestStartWiresSMSTransport(t *testing.T) {
	transport := &runtimeSMSTransport{}
	inst, err := Start(context.Background(), StartRequest{
		DeviceID:     "dev-1",
		Profile:      identity.Profile{IMSI: "310280233641503"},
		SMSTransport: transport,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	out, err := inst.SendSMSWithOptions(context.Background(), "+18005551212", strings.Repeat("a", 161), messaging.SendOptions{})
	if err != nil {
		t.Fatalf("SendSMSWithOptions() error = %v", err)
	}
	if out.PartsTotal != 2 || len(transport.requests) != 2 {
		t.Fatalf("outcome=%+v requests=%+v", out, transport.requests)
	}
}

func TestStartWiresUSSDTransport(t *testing.T) {
	transport := &runtimeUSSDTransport{}
	inst, err := Start(context.Background(), StartRequest{
		DeviceID:      "dev-1",
		Profile:       identity.Profile{IMSI: "310280233641503"},
		USSDTransport: transport,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	res, err := inst.Service().SendUSSD(context.Background(), "*100#")
	if err != nil {
		t.Fatalf("SendUSSD() error = %v", err)
	}
	if res.Text != "ok" || len(transport.executeRequests) != 1 {
		t.Fatalf("res=%+v requests=%+v", res, transport.executeRequests)
	}
}

func TestInstanceHandlesIncomingSMSAndDeliveryReport(t *testing.T) {
	store := &runtimeDeliveryStore{match: messaging.DeliveryPartMatch{MessageID: "msg-1", PartNo: 1, State: "delivered"}}
	dispatch := &runtimeDispatcher{}
	inst, err := Start(context.Background(), StartRequest{
		DeviceID:      "dev-1",
		Profile:       identity.Profile{IMSI: "310280233641503"},
		DeliveryStore: store,
		Dispatch:      dispatch,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := inst.HandleIncomingSMS(context.Background(), messaging.IncomingSMS{Sender: "+10086", Content: "hi"}); err != nil {
		t.Fatalf("HandleIncomingSMS() error = %v", err)
	}
	if len(dispatch.events) != 1 {
		t.Fatalf("events=%d", len(dispatch.events))
	}
	match, err := inst.HandleSMSDeliveryReport(context.Background(), messaging.SMSDeliveryReport{InReplyTo: "sip-1", SIPCode: 200})
	if err != nil {
		t.Fatalf("HandleSMSDeliveryReport() error = %v", err)
	}
	if match.MessageID != "msg-1" || store.reportState != "delivered" || store.recomputed != "msg-1" {
		t.Fatalf("match=%+v store=%+v", match, store)
	}
}

type runtimeSMSTransport struct {
	requests []messaging.SMSSendRequest
}

type runtimeUSSDTransport struct {
	executeRequests []messaging.USSDRequest
}

type runtimeDispatcher struct {
	events []eventhost.Event
}

func (d *runtimeDispatcher) Dispatch(ctx context.Context, ev eventhost.Event) {
	d.events = append(d.events, ev)
}

type runtimeDeliveryStore struct {
	match       messaging.DeliveryPartMatch
	reportState string
	recomputed  string
}

func (s *runtimeDeliveryStore) CreateSMSDelivery(messageID, imsi, deviceID, peer, content string, partsTotal int, at time.Time) error {
	return nil
}

func (s *runtimeDeliveryStore) UpsertSMSDeliveryPart(messageID string, partNo int, callID string, rpMR int, state string, sentAt time.Time) error {
	return nil
}

func (s *runtimeDeliveryStore) MarkSMSDeliveryPartReport(inReplyTo, callID, deviceID string, rpMR int, state string, sipCode int, rpCause int, errText string, at time.Time) (messaging.DeliveryPartMatch, error) {
	s.reportState = state
	return s.match, nil
}

func (s *runtimeDeliveryStore) RecomputeSMSDelivery(messageID string, at time.Time) error {
	s.recomputed = messageID
	return nil
}

func (s *runtimeDeliveryStore) UpdateSMSDeliveryState(messageID, state, lastError string, acks int, at time.Time) error {
	return nil
}

func (s *runtimeDeliveryStore) GetSMSDeliveryStatus(messageID string) (*messaging.DeliveryStatus, error) {
	return nil, messaging.ErrDeliveryNotFound
}

func (t *runtimeUSSDTransport) ExecuteUSSD(ctx context.Context, req messaging.USSDRequest) (messaging.USSDResult, error) {
	t.executeRequests = append(t.executeRequests, req)
	return messaging.USSDResult{Text: "ok", Done: true}, nil
}

func (t *runtimeUSSDTransport) ContinueUSSD(ctx context.Context, req messaging.USSDRequest) (messaging.USSDResult, error) {
	return messaging.USSDResult{Text: "continued", Done: true}, nil
}

func (t *runtimeUSSDTransport) CancelUSSD(ctx context.Context, req messaging.USSDRequest) error {
	return nil
}

func (t *runtimeSMSTransport) SendSMSPart(ctx context.Context, req messaging.SMSSendRequest) (messaging.SMSSendResult, error) {
	t.requests = append(t.requests, req)
	return messaging.SMSSendResult{State: "sent"}, nil
}
