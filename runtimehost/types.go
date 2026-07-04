package runtimehost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	swusim "github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/runtimehost/eventhost"
	"github.com/iniwex5/vowifi-go/runtimehost/identity"
	"github.com/iniwex5/vowifi-go/runtimehost/messaging"
	"github.com/iniwex5/vowifi-go/runtimehost/voicehost"
)

var ErrAPDUBusy = errors.New("apdu busy")

type ctxKey string

const traceIDKey ctxKey = "trace_id"

func NewTraceID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("trace-%d", time.Now().UnixNano())
	}
	return "trace-" + hex.EncodeToString(b[:])
}

func WithTraceID(ctx context.Context, traceID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, traceIDKey, strings.TrimSpace(traceID))
}

func SetLogger(any) {}

type Phase string

const (
	PhaseStarting Phase = "starting"
	PhaseSIMReady Phase = "sim_ready"
	PhaseReady    Phase = "ready"
	PhaseStopped  Phase = "stopped"
	PhaseError    Phase = "error"
)

type State struct {
	DeviceID       string
	Phase          Phase
	DataplaneMode  string
	SIMReady       bool
	AccessReady    bool
	TunnelReady    bool
	IMSReady       bool
	SMSReady       bool
	RegStatus      int
	RegStatusText  string
	NetworkMode    string
	LastErrorClass string
	LastError      string
	LastReason     string
	UpdatedAt      time.Time
}

type Event struct {
	State State
}

type Observer interface {
	OnRuntimeEvent(context.Context, Event)
}

type ObserverFunc func(context.Context, Event)

func (f ObserverFunc) OnRuntimeEvent(ctx context.Context, ev Event) {
	if f != nil {
		f(ctx, ev)
	}
}

type Modem interface {
	DeviceID() string
	IsHealthy() bool
	IsSimInserted() bool
	QuerySIMInserted() (bool, error)
	GetRegStatus() (int, string)
	GetNetworkMode() string
	Stop()
}

type APDUAccess interface {
	ExecuteATSilent(cmd string, timeout time.Duration) (string, error)
	OpenLogicalChannel(aid string) (int, error)
	CloseLogicalChannel(channel int) error
	TransmitAPDU(channel int, hexAPDU string) (string, error)
}

type IdentityReader interface {
	GetISIMIdentity() (identity.Identity, error)
}

type ModemAccess interface {
	GetISIMIdentity() (identity.Identity, error)
	RuntimeModem() Modem
}

type modemAccessAdapter struct {
	modem Modem
}

func NewModemAccessAdapter(m Modem) ModemAccess {
	if m == nil {
		return nil
	}
	return &modemAccessAdapter{modem: m}
}

func (a *modemAccessAdapter) RuntimeModem() Modem {
	if a == nil {
		return nil
	}
	return a.modem
}

func (a *modemAccessAdapter) GetISIMIdentity() (identity.Identity, error) {
	if a == nil || a.modem == nil {
		return identity.Identity{}, errors.New("modem is nil")
	}
	if r, ok := a.modem.(IdentityReader); ok {
		return r.GetISIMIdentity()
	}
	return identity.Identity{}, errors.New("modem does not expose ISIM identity")
}

type SIMAdapter interface {
	GetIMSI() (string, error)
	CalculateAKA(rand16, autn16 []byte) (swusim.AKAResult, error)
	Close() error
}

type readerSIMAdapter struct {
	provider swusim.AKAProvider
}

func NewReaderSIMAdapter(provider swusim.AKAProvider) SIMAdapter {
	return &readerSIMAdapter{provider: provider}
}

func (a *readerSIMAdapter) GetIMSI() (string, error) { return "", nil }

func (a *readerSIMAdapter) CalculateAKA(rand16, autn16 []byte) (swusim.AKAResult, error) {
	if a == nil || a.provider == nil {
		return swusim.AKAResult{}, errors.New("aka provider is nil")
	}
	return a.provider.CalculateAKA(rand16, autn16)
}

func (a *readerSIMAdapter) Close() error { return nil }

type ProxyConfig struct {
	ID       string
	URL      string
	Address  string
	Addr     string
	Username string
	Password string
	Country  string
	Enabled  bool
}

type DataplanePolicy struct {
	Mode string
}

type SessionConfig struct {
	DeviceID      string
	TraceID       string
	Profile       identity.Profile
	Prepared      *identity.PreparedSession
	DataplaneMode string
	Proxy         *ProxyConfig
}

type IMSRegistrationConfig struct {
	DeviceID    string
	TraceID     string
	Profile     identity.Profile
	Prepared    *identity.PreparedSession
	SIM         SIMAdapter
	Access      ModemAccess
	NetworkMode string
	Dataplane   DataplanePolicy
	Proxy       *ProxyConfig
}

type IMSRegistrationResult struct {
	Registered bool
	StatusCode int
	Reason     string
	Server     string
}

type IMSRegistrar interface {
	RegisterIMS(context.Context, IMSRegistrationConfig) (IMSRegistrationResult, error)
}

const StartModeMain = "main"

type StartRequest struct {
	Mode          string
	DeviceID      string
	TraceID       string
	Profile       identity.Profile
	Prepared      *identity.PreparedSession
	NetworkMode   string
	VoiceGateway  *voicehost.Gateway
	SIM           SIMAdapter
	Access        ModemAccess
	Dataplane     DataplanePolicy
	Proxy         *ProxyConfig
	IMSRegistrar  IMSRegistrar
	SMSTransport  messaging.SMSTransport
	DeliveryStore messaging.DeliveryStore
	Dispatch      eventhost.Dispatcher
	BeforeStart   func(context.Context, SessionConfig) error
	ShouldRun     func() bool
}

type Instance struct {
	mu        sync.RWMutex
	state     State
	service   *messaging.Service
	observers []Observer
	notifier  func(string)
	smsNotify func(deviceID, sender, content string, ts time.Time)
	stopped   bool
}

func Start(ctx context.Context, req StartRequest) (*Instance, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(req.DeviceID) == "" {
		return nil, errors.New("device_id is empty")
	}
	if req.ShouldRun != nil && !req.ShouldRun() {
		return nil, errors.New("runtime start canceled")
	}
	cfg := SessionConfig{
		DeviceID:      req.DeviceID,
		TraceID:       req.TraceID,
		Profile:       req.Profile,
		Prepared:      req.Prepared,
		DataplaneMode: req.Dataplane.Mode,
		Proxy:         req.Proxy,
	}
	if req.BeforeStart != nil {
		if err := req.BeforeStart(ctx, cfg); err != nil {
			return nil, err
		}
	}
	regStatus, regText := 0, ""
	modem := Modem(nil)
	if req.Access != nil {
		modem = req.Access.RuntimeModem()
	}
	if modem != nil {
		regStatus, regText = modem.GetRegStatus()
	}
	imsReady := req.IMSRegistrar == nil
	imsReason := ""
	if req.IMSRegistrar != nil {
		res, err := req.IMSRegistrar.RegisterIMS(ctx, IMSRegistrationConfig{
			DeviceID:    req.DeviceID,
			TraceID:     req.TraceID,
			Profile:     req.Profile,
			Prepared:    req.Prepared,
			SIM:         req.SIM,
			Access:      req.Access,
			NetworkMode: req.NetworkMode,
			Dataplane:   req.Dataplane,
			Proxy:       req.Proxy,
		})
		if err != nil {
			return nil, fmt.Errorf("IMS registration failed: %w", err)
		}
		if !res.Registered {
			return nil, fmt.Errorf("IMS registration rejected: %d %s", res.StatusCode, strings.TrimSpace(res.Reason))
		}
		imsReady = true
		imsReason = firstRuntimeNonEmpty(res.Reason, res.Server)
	}
	state := State{
		DeviceID:      req.DeviceID,
		Phase:         PhaseReady,
		DataplaneMode: req.Dataplane.Mode,
		SIMReady:      req.SIM != nil,
		AccessReady:   modem != nil,
		TunnelReady:   false,
		IMSReady:      imsReady,
		SMSReady:      true,
		RegStatus:     regStatus,
		RegStatusText: regText,
		NetworkMode:   strings.TrimSpace(req.NetworkMode),
		LastReason:    firstRuntimeNonEmpty(imsReason, "started"),
		UpdatedAt:     time.Now(),
	}
	if state.NetworkMode == "" && modem != nil {
		state.NetworkMode = modem.GetNetworkMode()
	}
	svc := messaging.NewService(req.DeviceID, req.Profile.IMSI, req.DeliveryStore, req.Dispatch)
	svc.SetSMSTransport(req.SMSTransport)
	inst := &Instance{state: state, service: svc}
	if req.VoiceGateway != nil {
		req.VoiceGateway.RegisterAgent(req.DeviceID, inst)
	}
	inst.notify(ctx)
	return inst, nil
}

func (i *Instance) AddObserver(o Observer) {
	if i == nil || o == nil {
		return
	}
	i.mu.Lock()
	i.observers = append(i.observers, o)
	state := i.state
	i.mu.Unlock()
	o.OnRuntimeEvent(context.Background(), Event{State: state})
}

func (i *Instance) notify(ctx context.Context) {
	i.mu.RLock()
	observers := append([]Observer(nil), i.observers...)
	state := i.state
	i.mu.RUnlock()
	for _, o := range observers {
		o.OnRuntimeEvent(ctx, Event{State: state})
	}
}

func (i *Instance) Stop(ctx context.Context) error {
	if i == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	i.mu.Lock()
	i.stopped = true
	i.state.Phase = PhaseStopped
	i.state.LastReason = "stopped"
	i.state.UpdatedAt = time.Now()
	i.mu.Unlock()
	i.notify(ctx)
	return nil
}

func (i *Instance) Service() *messaging.Service {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.service
}

func (i *Instance) SendSMSWithOptions(ctx context.Context, to, text string, opts messaging.SendOptions) (messaging.SendOutcome, error) {
	svc := i.Service()
	if svc == nil {
		return messaging.SendOutcome{}, errors.New("messaging service is nil")
	}
	return svc.SendSMSWithOptions(ctx, to, text, opts)
}

func (i *Instance) GetSMSDeliveryStatus(messageID string) (*messaging.DeliveryStatus, error) {
	svc := i.Service()
	if svc == nil {
		return nil, errors.New("messaging service is nil")
	}
	if svc == nil {
		return nil, errors.New("messaging service is nil")
	}
	return svc.GetSMSDeliveryStatus(messageID)
}

func (i *Instance) State() State {
	if i == nil {
		return State{}
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.state
}

func (i *Instance) SetNotifier(fn func(string)) {
	if i == nil {
		return
	}
	i.mu.Lock()
	i.notifier = fn
	i.mu.Unlock()
}

func (i *Instance) SetSMSNotifier(fn func(deviceID, sender, content string, ts time.Time)) {
	if i == nil {
		return
	}
	i.mu.Lock()
	i.smsNotify = fn
	i.mu.Unlock()
}

func (i *Instance) TriggerMOBIKE(oldIP, newIP string) error {
	if i == nil {
		return errors.New("runtime instance is nil")
	}
	i.mu.Lock()
	i.state.LastReason = "mobike"
	i.state.UpdatedAt = time.Now()
	i.mu.Unlock()
	i.notify(context.Background())
	return nil
}

func (i *Instance) Status() string {
	if i == nil {
		return "VoWiFi: STOPPED"
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	if i.stopped {
		return "VoWiFi: STOPPED"
	}
	return "VoWiFi: " + string(i.state.Phase)
}

func (i *Instance) Obs() map[string]interface{} {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return map[string]interface{}{
		"device_id": i.state.DeviceID,
		"phase":     string(i.state.Phase),
		"sms_ready": i.state.SMSReady,
		"ims_ready": i.state.IMSReady,
		"updated":   i.state.UpdatedAt,
	}
}

type EventDispatcher = eventhost.Dispatcher
type ModuleEvent = eventhost.Event
type EventSMSReceived = eventhost.SMSReceived
type EventSMSSent = eventhost.SMSSent
type EventLocalNumberLearned = eventhost.LocalNumberLearned
type EventLogNotify = eventhost.LogNotify

type PrepareStartInput = identity.PrepareStartInput

func firstRuntimeNonEmpty(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}
