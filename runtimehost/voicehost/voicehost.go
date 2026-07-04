package voicehost

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"
)

const (
	DefaultSimulateCallHoldSeconds = 10
	MaxSimulateCallHoldSeconds     = 300
)

type ClientAdapter interface {
	GetClientContact(deviceID string) (contactURI string, contactIP string, username string, err error)
}

type Agent interface{}

type Gateway struct {
	mu       sync.RWMutex
	agents   map[string]Agent
	client   ClientAdapter
	notifier any
	started  bool
}

func NewGateway() *Gateway {
	return &Gateway{agents: make(map[string]Agent)}
}

func (g *Gateway) Start(ctx context.Context) error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	g.started = true
	g.mu.Unlock()
	return nil
}

func (g *Gateway) Stop() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	g.started = false
	g.mu.Unlock()
	return nil
}

func (g *Gateway) SetClientAdapter(a ClientAdapter) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.client = a
	g.mu.Unlock()
}

func (g *Gateway) SetNotifier(n any) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.notifier = n
	g.mu.Unlock()
}

func (g *Gateway) RegisterAgent(deviceID string, agent Agent) {
	if g == nil || strings.TrimSpace(deviceID) == "" {
		return
	}
	g.mu.Lock()
	if g.agents == nil {
		g.agents = make(map[string]Agent)
	}
	g.agents[strings.TrimSpace(deviceID)] = agent
	g.mu.Unlock()
}

func (g *Gateway) GetAgent(deviceID string) Agent {
	if g == nil {
		return nil
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.agents[strings.TrimSpace(deviceID)]
}

func (g *Gateway) DeviceStatus(deviceID string) map[string]interface{} {
	return map[string]interface{}{
		"ready":  g != nil && g.GetAgent(deviceID) != nil,
		"device": strings.TrimSpace(deviceID),
	}
}

type SimulateCallRequest struct {
	Callee      string `json:"callee"`
	HoldSeconds int    `json:"hold_seconds"`
	OnConnected func() `json:"-"`
}

type SimulateCallResult struct {
	Success    bool   `json:"success"`
	Reason     string `json:"reason,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}

func (g *Gateway) SimulateCall(ctx context.Context, deviceID string, req SimulateCallRequest) (SimulateCallResult, error) {
	if g == nil || g.GetAgent(deviceID) == nil {
		return SimulateCallResult{Success: false, Reason: "agent not ready"}, errors.New("voice agent not ready")
	}
	if strings.TrimSpace(req.Callee) == "" {
		return SimulateCallResult{Success: false, Reason: "callee empty"}, errors.New("callee is empty")
	}
	hold := req.HoldSeconds
	if hold <= 0 {
		hold = DefaultSimulateCallHoldSeconds
	}
	if hold > MaxSimulateCallHoldSeconds {
		hold = MaxSimulateCallHoldSeconds
	}
	if req.OnConnected != nil {
		req.OnConnected()
	}
	timer := time.NewTimer(time.Duration(hold) * time.Second)
	select {
	case <-ctx.Done():
		timer.Stop()
		return SimulateCallResult{Success: false, Reason: ctx.Err().Error()}, ctx.Err()
	case <-timer.C:
		return SimulateCallResult{Success: true, DurationMs: int64(hold) * 1000}, nil
	}
}

func (g *Gateway) HandleClientInvite(deviceID string, req *sip.Request, tx sip.ServerTransaction) {
	if tx != nil && req != nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi voice bridge unavailable", nil))
	}
}

func (g *Gateway) HandleClientCancel(deviceID string, req *sip.Request, tx sip.ServerTransaction) {
	if tx != nil && req != nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	}
}

func (g *Gateway) HandleClientPrack(deviceID string, req *sip.Request, tx sip.ServerTransaction) {
	if tx != nil && req != nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	}
}

func (g *Gateway) HandleClientAck(deviceID string, req *sip.Request, tx sip.ServerTransaction) {}

func (g *Gateway) HandleClientBye(deviceID string, req *sip.Request, tx sip.ServerTransaction) {
	if tx != nil && req != nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	}
}

type SDPInfo struct {
	ConnectionIP string
	MediaPort    int
}

var (
	sdpConnRE  = regexp.MustCompile(`(?m)^c=IN IP[46] ([^\r\n]+)`)
	sdpMediaRE = regexp.MustCompile(`(?m)^m=audio ([0-9]+) `)
)

func ParseSDP(body []byte) (SDPInfo, error) {
	text := string(body)
	var out SDPInfo
	if m := sdpConnRE.FindStringSubmatch(text); len(m) == 2 {
		out.ConnectionIP = strings.TrimSpace(m[1])
	}
	if out.ConnectionIP == "" {
		out.ConnectionIP = "127.0.0.1"
	}
	if ip := net.ParseIP(out.ConnectionIP); ip == nil {
		return SDPInfo{}, errors.New("invalid SDP connection IP")
	}
	if m := sdpMediaRE.FindStringSubmatch(text); len(m) == 2 {
		port, _ := strconv.Atoi(m[1])
		out.MediaPort = port
	}
	if out.MediaPort <= 0 {
		return SDPInfo{}, errors.New("missing SDP audio port")
	}
	return out, nil
}
