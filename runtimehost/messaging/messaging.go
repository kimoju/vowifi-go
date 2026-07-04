package messaging

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/iniwex5/vowifi-go/runtimehost/eventhost"
)

var ErrDeliveryNotFound = errors.New("delivery not found")

type suppressKey struct{}

func WithSuppressSendTGSuccess(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, suppressKey{}, true)
}

type SendOptions struct {
	Encoding string
}

type SendOutcome struct {
	MessageID     string `json:"message_id,omitempty"`
	Parts         int    `json:"parts,omitempty"`
	PartsTotal    int    `json:"parts_total,omitempty"`
	State         string `json:"state,omitempty"`
	DeliveryState string `json:"delivery_state,omitempty"`
}

type USSDResult struct {
	SessionID string `json:"session_id,omitempty"`
	Text      string `json:"text,omitempty"`
	Done      bool   `json:"done"`
}

type DeliveryPartMatch struct {
	MessageID string
	PartNo    int
	State     string
}

type DeliveryPartStatus struct {
	PartNo      int
	CallID      string
	InReplyTo   string
	RPMR        int
	State       string
	SIPCode     int
	RPCause     int
	RPCauseText string
	ErrorText   string
	SentAt      time.Time
	ReportAt    *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type DeliveryStatus struct {
	MessageID  string
	IMSI       string
	DeviceID   string
	Peer       string
	Content    string
	PartsTotal int
	Acks       int
	State      string
	LastError  string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	Parts      []DeliveryPartStatus
}

type DeliveryStore interface {
	CreateSMSDelivery(messageID, imsi, deviceID, peer, content string, partsTotal int, at time.Time) error
	UpsertSMSDeliveryPart(messageID string, partNo int, callID string, rpMR int, state string, sentAt time.Time) error
	MarkSMSDeliveryPartReport(inReplyTo, callID, deviceID string, rpMR int, state string, sipCode int, rpCause int, errText string, at time.Time) (DeliveryPartMatch, error)
	RecomputeSMSDelivery(messageID string, at time.Time) error
	UpdateSMSDeliveryState(messageID, state, lastError string, acks int, at time.Time) error
	GetSMSDeliveryStatus(messageID string) (*DeliveryStatus, error)
}

func RPCauseText(code int) string {
	if code == 0 {
		return ""
	}
	return fmt.Sprintf("RP cause %d", code)
}

type Service struct {
	deviceID string
	imsi     string
	store    DeliveryStore
	dispatch eventhost.Dispatcher
}

func NewService(deviceID, imsi string, store DeliveryStore, dispatch eventhost.Dispatcher) *Service {
	return &Service{deviceID: deviceID, imsi: imsi, store: store, dispatch: dispatch}
}

func (s *Service) SendSMSWithOptions(ctx context.Context, to, text string, opts SendOptions) (SendOutcome, error) {
	to = strings.TrimSpace(to)
	if to == "" {
		return SendOutcome{}, errors.New("sms target is empty")
	}
	id := fmt.Sprintf("vowifi-%d", time.Now().UnixNano())
	now := time.Now()
	if s != nil && s.store != nil {
		_ = s.store.CreateSMSDelivery(id, s.imsi, s.deviceID, to, text, 1, now)
		_ = s.store.UpsertSMSDeliveryPart(id, 1, "", 0, "sent", now)
		_ = s.store.UpdateSMSDeliveryState(id, "sent", "", 0, now)
	}
	if s != nil && s.dispatch != nil {
		s.dispatch.Dispatch(ctx, eventhost.SMSSent{DevID: s.deviceID, TargetURI: to, Content: text, Time: now})
	}
	return SendOutcome{MessageID: id, Parts: 1, PartsTotal: 1, State: "sent", DeliveryState: "sent"}, nil
}

func (s *Service) SendUSSD(ctx context.Context, command string) (*USSDResult, error) {
	if strings.TrimSpace(command) == "" {
		return nil, errors.New("ussd command is empty")
	}
	return &USSDResult{SessionID: fmt.Sprintf("ussd-%d", time.Now().UnixNano()), Text: "", Done: true}, nil
}

func (s *Service) ContinueUSSD(ctx context.Context, sessionID, input string) (*USSDResult, error) {
	if strings.TrimSpace(sessionID) == "" {
		return nil, errors.New("ussd session_id is empty")
	}
	return &USSDResult{SessionID: sessionID, Text: "", Done: true}, nil
}

func (s *Service) CancelUSSD(ctx context.Context, sessionID string) error {
	if strings.TrimSpace(sessionID) == "" {
		return errors.New("ussd session_id is empty")
	}
	return nil
}

func (s *Service) GetSMSDeliveryStatus(messageID string) (*DeliveryStatus, error) {
	if s == nil || s.store == nil {
		return nil, ErrDeliveryNotFound
	}
	return s.store.GetSMSDeliveryStatus(messageID)
}
