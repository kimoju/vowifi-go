package voicehost

import (
	"context"
	"errors"
	"fmt"
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

type OutboundCallAgent interface {
	StartOutboundCall(context.Context, OutboundCallRequest) (OutboundCallResult, error)
}

type DialogTerminator interface {
	EndVoiceCall(context.Context, DialogInfo) error
}

type DialogCanceller interface {
	CancelVoiceCall(context.Context, DialogInfo) error
}

type OutboundCallRequest struct {
	DeviceID  string
	CallID    string
	Callee    string
	RemoteSDP SDPInfo
	RawSDP    []byte
}

type OutboundCallResult struct {
	Accepted   bool
	StatusCode int
	Reason     string
	LocalSDP   SDPInfo
	RawSDP     []byte
}

type DialogInfo struct {
	DeviceID string
	CallID   string
	Callee   string
	State    DialogState
}

type DialogState string

const (
	DialogStateEarly       DialogState = "early"
	DialogStateEstablished DialogState = "established"
	DialogStateTerminated  DialogState = "terminated"
)

type Gateway struct {
	mu       sync.RWMutex
	agents   map[string]Agent
	dialogs  map[string]DialogInfo
	client   ClientAdapter
	notifier any
	started  bool
}

func NewGateway() *Gateway {
	return &Gateway{agents: make(map[string]Agent), dialogs: make(map[string]DialogInfo)}
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
	dialogs := 0
	if g != nil {
		g.mu.RLock()
		for _, d := range g.dialogs {
			if d.DeviceID == strings.TrimSpace(deviceID) && d.State != DialogStateTerminated {
				dialogs++
			}
		}
		g.mu.RUnlock()
	}
	return map[string]interface{}{
		"ready":          g != nil && g.GetAgent(deviceID) != nil,
		"device":         strings.TrimSpace(deviceID),
		"active_dialogs": dialogs,
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
	if tx == nil || req == nil {
		return
	}
	agent, _ := g.GetAgent(deviceID).(OutboundCallAgent)
	if agent == nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi voice bridge unavailable", nil))
		return
	}
	callID := sipCallID(req)
	if callID == "" {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Missing Call-ID", nil))
		return
	}
	remoteSDP, err := ParseSDP(req.Body())
	if err != nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 488, "Invalid SDP", nil))
		return
	}
	callee := sipCallee(req)
	if callee == "" {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Missing callee", nil))
		return
	}
	_ = tx.Respond(sip.NewResponseFromRequest(req, 100, "Trying", nil))
	g.recordDialog(DialogInfo{DeviceID: deviceID, CallID: callID, Callee: callee, State: DialogStateEarly})
	result, err := agent.StartOutboundCall(context.Background(), OutboundCallRequest{
		DeviceID:  strings.TrimSpace(deviceID),
		CallID:    callID,
		Callee:    callee,
		RemoteSDP: remoteSDP,
		RawSDP:    append([]byte(nil), req.Body()...),
	})
	if err != nil {
		g.recordDialog(DialogInfo{DeviceID: deviceID, CallID: callID, Callee: callee, State: DialogStateTerminated})
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi voice setup failed", nil))
		return
	}
	if !result.Accepted {
		g.recordDialog(DialogInfo{DeviceID: deviceID, CallID: callID, Callee: callee, State: DialogStateTerminated})
		reason := strings.TrimSpace(result.Reason)
		if reason == "" {
			reason = "Busy Here"
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, localFinalStatusCode(result.StatusCode, 486), reason, nil))
		return
	}
	body := append([]byte(nil), result.RawSDP...)
	if len(body) == 0 {
		body = BuildSDPAnswer(result.LocalSDP)
	}
	res := sip.NewResponseFromRequest(req, 200, "OK", body)
	res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	g.recordDialog(DialogInfo{DeviceID: deviceID, CallID: callID, Callee: callee, State: DialogStateEstablished})
	_ = tx.Respond(res)
}

func (g *Gateway) HandleClientCancel(deviceID string, req *sip.Request, tx sip.ServerTransaction) {
	if tx != nil && req != nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	}
	if req == nil {
		return
	}
	callID := sipCallID(req)
	if callID == "" {
		return
	}
	dialog := g.dialog(callID)
	dialog.DeviceID = firstVoiceNonEmpty(dialog.DeviceID, strings.TrimSpace(deviceID))
	dialog.State = DialogStateTerminated
	g.recordDialog(dialog)
	if canceller, ok := g.GetAgent(deviceID).(DialogCanceller); ok {
		_ = canceller.CancelVoiceCall(context.Background(), dialog)
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
	if req == nil {
		return
	}
	callID := sipCallID(req)
	if callID == "" {
		return
	}
	dialog := g.dialog(callID)
	dialog.State = DialogStateTerminated
	g.recordDialog(dialog)
	if terminator, ok := g.GetAgent(deviceID).(DialogTerminator); ok {
		_ = terminator.EndVoiceCall(context.Background(), dialog)
	}
}

type SDPInfo struct {
	ConnectionIP string
	MediaPort    int
	RTCPIP       string
	RTCPPort     int
	Payloads     []int
	Direction    string
}

var (
	sdpConnRE      = regexp.MustCompile(`(?m)^c=IN IP[46] ([^\r\n]+)`)
	sdpMediaRE     = regexp.MustCompile(`(?m)^m=audio ([0-9]+) [A-Z0-9/]+(.*)$`)
	sdpRTCPRE      = regexp.MustCompile(`(?m)^a=rtcp:([0-9]+)(?:\s+IN\s+IP[46]\s+([^\r\n]+))?`)
	sdpDirectionRE = regexp.MustCompile(`(?m)^a=(sendrecv|sendonly|recvonly|inactive)\s*$`)
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
	if m := sdpMediaRE.FindStringSubmatch(text); len(m) == 3 {
		port, _ := strconv.Atoi(m[1])
		out.MediaPort = port
		for _, part := range strings.Fields(m[2]) {
			payload, err := strconv.Atoi(part)
			if err == nil {
				out.Payloads = append(out.Payloads, payload)
			}
		}
	}
	if out.MediaPort <= 0 {
		return SDPInfo{}, errors.New("missing SDP audio port")
	}
	if m := sdpRTCPRE.FindStringSubmatch(text); len(m) >= 2 {
		port, _ := strconv.Atoi(m[1])
		out.RTCPPort = port
		if len(m) >= 3 && strings.TrimSpace(m[2]) != "" {
			out.RTCPIP = strings.TrimSpace(m[2])
		}
	}
	if m := sdpDirectionRE.FindStringSubmatch(text); len(m) == 2 {
		out.Direction = strings.TrimSpace(m[1])
	}
	if out.Direction == "" {
		out.Direction = "sendrecv"
	}
	return out, nil
}

func BuildSDPAnswer(info SDPInfo) []byte {
	ip := strings.TrimSpace(info.ConnectionIP)
	if ip == "" {
		ip = "127.0.0.1"
	}
	ipVersion := "IP4"
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		ipVersion = "IP6"
	}
	port := info.MediaPort
	if port <= 0 {
		port = 4000
	}
	payloads := info.Payloads
	if len(payloads) == 0 {
		payloads = []int{0, 8, 101}
	}
	direction := strings.TrimSpace(info.Direction)
	if direction == "" {
		direction = "sendrecv"
	}
	var b strings.Builder
	b.WriteString("v=0\r\n")
	b.WriteString("o=vowifi-go 0 0 IN " + ipVersion + " " + ip + "\r\n")
	b.WriteString("s=VoWiFi\r\n")
	b.WriteString("c=IN " + ipVersion + " " + ip + "\r\n")
	b.WriteString("t=0 0\r\n")
	b.WriteString("m=audio " + strconv.Itoa(port) + " RTP/AVP")
	for _, payload := range payloads {
		b.WriteString(" " + strconv.Itoa(payload))
	}
	b.WriteString("\r\n")
	if info.RTCPPort > 0 {
		rtcpIP := strings.TrimSpace(info.RTCPIP)
		if rtcpIP == "" {
			rtcpIP = ip
		}
		rtcpIPVersion := "IP4"
		if parsed := net.ParseIP(rtcpIP); parsed != nil && parsed.To4() == nil {
			rtcpIPVersion = "IP6"
		}
		b.WriteString("a=rtcp:" + strconv.Itoa(info.RTCPPort) + " IN " + rtcpIPVersion + " " + rtcpIP + "\r\n")
	}
	b.WriteString("a=" + direction + "\r\n")
	for _, payload := range payloads {
		switch payload {
		case 0:
			b.WriteString("a=rtpmap:0 PCMU/8000\r\n")
		case 8:
			b.WriteString("a=rtpmap:8 PCMA/8000\r\n")
		case 101:
			b.WriteString("a=rtpmap:101 telephone-event/8000\r\n")
			b.WriteString("a=fmtp:101 0-16\r\n")
		}
	}
	return []byte(b.String())
}

func (g *Gateway) recordDialog(info DialogInfo) {
	if g == nil || strings.TrimSpace(info.CallID) == "" {
		return
	}
	g.mu.Lock()
	if g.dialogs == nil {
		g.dialogs = make(map[string]DialogInfo)
	}
	g.dialogs[strings.TrimSpace(info.CallID)] = info
	g.mu.Unlock()
}

func (g *Gateway) dialog(callID string) DialogInfo {
	if g == nil {
		return DialogInfo{CallID: strings.TrimSpace(callID)}
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if d, ok := g.dialogs[strings.TrimSpace(callID)]; ok {
		return d
	}
	return DialogInfo{CallID: strings.TrimSpace(callID)}
}

func localFinalStatusCode(code, fallback int) int {
	if code >= 300 && code <= 699 {
		return code
	}
	return fallback
}

func sipCallID(req *sip.Request) string {
	if req == nil || req.CallID() == nil {
		return ""
	}
	return strings.TrimSpace(req.CallID().Value())
}

func sipCallee(req *sip.Request) string {
	if req == nil {
		return ""
	}
	if to := req.To(); to != nil {
		if user := strings.TrimSpace(to.Address.User); user != "" {
			return user
		}
	}
	if user := strings.TrimSpace(req.Recipient.User); user != "" {
		return user
	}
	return strings.TrimSpace(fmt.Sprint(req.Recipient))
}
