package voicehost

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/kimoju/vowifi-go/runtimehost/voiceclient"
)

type InboundCallInfo struct {
	DeviceID string    `json:"device_id"`
	CallID   string    `json:"call_id"`
	Caller   string    `json:"caller"`
	Callee   string    `json:"callee"`
	State    string    `json:"state"`
	RawSDP   []byte    `json:"-"`
	Created  time.Time `json:"created_at"`
}

type gatewayInboundCall struct {
	info     InboundCallInfo
	response chan voiceclient.SIPResponse
}

type gatewayClientTransport struct {
	gateway  *Gateway
	deviceID string
}

// SetInboundEnabled controls whether the browser client accepts new IMS calls.
// It is intentionally opt-in so applications that do not expose a call UI do
// not leave incoming INVITEs ringing until their network context expires.
func (g *Gateway) SetInboundEnabled(enabled bool) {
	if g == nil {
		return
	}
	var pending []*gatewayInboundCall
	g.mu.Lock()
	g.inboundEnabled = enabled
	if !enabled {
		for callID, call := range g.inbound {
			if call.info.State != "ringing" {
				continue
			}
			delete(g.inbound, callID)
			pending = append(pending, call)
		}
	}
	g.mu.Unlock()
	for _, call := range pending {
		select {
		case call.response <- voiceclient.SIPResponse{StatusCode: 480, Reason: "Temporarily Unavailable"}:
		default:
		}
	}
}

func (g *Gateway) ClientTransport(deviceID string) voiceclient.SIPRequestTransport {
	return &gatewayClientTransport{gateway: g, deviceID: strings.TrimSpace(deviceID)}
}

func (g *Gateway) ClientContactURI(deviceID string) string {
	deviceID = strings.NewReplacer(" ", "-", "@", "-", ":", "-").Replace(strings.TrimSpace(deviceID))
	if deviceID == "" {
		deviceID = "device"
	}
	return "sip:vohive-web-" + deviceID + "@127.0.0.1"
}

func (g *Gateway) InboundCalls(deviceID string) []InboundCallInfo {
	if g == nil {
		return nil
	}
	deviceID = strings.TrimSpace(deviceID)
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]InboundCallInfo, 0, len(g.inbound))
	for _, call := range g.inbound {
		if deviceID == "" || call.info.DeviceID == deviceID {
			info := call.info
			info.RawSDP = append([]byte(nil), info.RawSDP...)
			out = append(out, info)
		}
	}
	return out
}

func (g *Gateway) AnswerInboundCall(callID string, body []byte) error {
	return g.respondInboundCall(callID, voiceclient.SIPResponse{StatusCode: 200, Reason: "OK", Headers: map[string][]string{"Content-Type": {"application/sdp"}}, Body: append([]byte(nil), body...)}, false)
}

func (g *Gateway) RejectInboundCall(callID string) error {
	return g.respondInboundCall(callID, voiceclient.SIPResponse{StatusCode: 486, Reason: "Busy Here"}, true)
}

func (g *Gateway) respondInboundCall(callID string, response voiceclient.SIPResponse, remove bool) error {
	if g == nil {
		return errors.New("voice gateway unavailable")
	}
	callID = strings.TrimSpace(callID)
	g.mu.Lock()
	call := g.inbound[callID]
	if call != nil {
		call.info.State = "answering"
		if remove {
			delete(g.inbound, callID)
		}
	}
	g.mu.Unlock()
	if call == nil {
		return errors.New("inbound call not found")
	}
	select {
	case call.response <- response:
		return nil
	default:
		return errors.New("inbound call already answered")
	}
}

func (t *gatewayClientTransport) RoundTripInvite(ctx context.Context, msg voiceclient.SIPRequestMessage, onProvisional voiceclient.ProvisionalResponseHandler) (voiceclient.SIPResponse, error) {
	if t == nil || t.gateway == nil {
		return voiceclient.SIPResponse{}, errors.New("browser voice client unavailable")
	}
	callID := strings.TrimSpace(msg.Headers["Call-ID"])
	if callID == "" {
		return voiceclient.SIPResponse{}, errors.New("inbound call ID missing")
	}
	call := &gatewayInboundCall{info: InboundCallInfo{
		DeviceID: t.deviceID,
		CallID:   callID,
		Caller:   sipHeaderURI(msg.Headers["From"]),
		Callee:   sipHeaderURI(msg.Headers["To"]),
		State:    "ringing",
		RawSDP:   append([]byte(nil), msg.Body...),
		Created:  time.Now(),
	}, response: make(chan voiceclient.SIPResponse, 1)}
	t.gateway.mu.Lock()
	if !t.gateway.inboundEnabled {
		t.gateway.mu.Unlock()
		return voiceclient.SIPResponse{StatusCode: 480, Reason: "Temporarily Unavailable"}, nil
	}
	t.gateway.inbound[callID] = call
	t.gateway.mu.Unlock()
	if onProvisional != nil {
		_ = onProvisional(ctx, msg, voiceclient.SIPResponse{StatusCode: 180, Reason: "Ringing"})
	}
	select {
	case response := <-call.response:
		return response, nil
	case <-ctx.Done():
		t.gateway.removeInbound(callID)
		return voiceclient.SIPResponse{}, ctx.Err()
	}
}

func (t *gatewayClientTransport) RoundTripRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error) {
	method := strings.ToUpper(strings.TrimSpace(msg.Method))
	callID := strings.TrimSpace(msg.Headers["Call-ID"])
	switch method {
	case "INVITE":
		return t.RoundTripInvite(ctx, msg, nil)
	case "CANCEL":
		if t.gateway.cancelInbound(callID) {
			return voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"}, nil
		}
		return voiceclient.SIPResponse{StatusCode: 481, Reason: "Call Does Not Exist"}, nil
	case "BYE":
		t.gateway.removeInbound(callID)
		return voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"}, nil
	default:
		return voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"}, nil
	}
}

func (t *gatewayClientTransport) WriteRequest(_ context.Context, msg voiceclient.SIPRequestMessage) error {
	callID := strings.TrimSpace(msg.Headers["Call-ID"])
	if strings.EqualFold(strings.TrimSpace(msg.Method), "ACK") {
		t.gateway.mu.Lock()
		if call := t.gateway.inbound[callID]; call != nil {
			call.info.State = "connected"
		}
		t.gateway.mu.Unlock()
	}
	return nil
}

func (g *Gateway) cancelInbound(callID string) bool {
	g.mu.Lock()
	call := g.inbound[strings.TrimSpace(callID)]
	if call != nil {
		delete(g.inbound, strings.TrimSpace(callID))
	}
	g.mu.Unlock()
	if call == nil {
		return false
	}
	select {
	case call.response <- voiceclient.SIPResponse{StatusCode: 487, Reason: "Request Terminated"}:
	default:
	}
	return true
}

func (g *Gateway) removeInbound(callID string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	delete(g.inbound, strings.TrimSpace(callID))
	g.mu.Unlock()
}

var _ voiceclient.SIPInviteTransport = (*gatewayClientTransport)(nil)
