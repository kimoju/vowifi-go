package voicehost

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/iniwex5/vowifi-go/runtimehost/voiceclient"
)

var ErrIMSVoiceAgentNotReady = errors.New("ims voice agent not ready")

type IMSOutboundAgent struct {
	Transport       voiceclient.SIPRequestTransport
	Profile         voiceclient.IMSProfile
	Registration    voiceclient.RegistrationBinding
	Domain          string
	UserAgent       string
	LocalTag        string
	SessionExpires  int
	RemoteTargetURI string
	MediaRelay      *RTPRelayConfig

	mu      sync.Mutex
	dialogs map[string]imsDialogState
}

type imsDialogState struct {
	cfg    voiceclient.DialogRequestConfig
	invite voiceclient.SIPRequestMessage
	relay  *RTPRelaySession
	early  bool
}

func (a *IMSOutboundAgent) StartOutboundCall(ctx context.Context, req OutboundCallRequest) (OutboundCallResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.Transport == nil {
		return OutboundCallResult{Accepted: false, Reason: "IMS voice transport unavailable"}, ErrIMSVoiceAgentNotReady
	}
	if strings.TrimSpace(req.CallID) == "" {
		return OutboundCallResult{Accepted: false, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	remoteURI := a.remoteURI(req.Callee)
	if remoteURI == "" {
		return OutboundCallResult{Accepted: false, Reason: "callee empty"}, errors.New("callee is empty")
	}
	cfg := voiceclient.DialogRequestConfig{
		Profile:         a.Profile,
		Registration:    a.Registration,
		LocalURI:        firstVoiceNonEmpty(a.Registration.PublicIdentity, a.Profile.IMPU),
		ContactURI:      a.Registration.ContactURI,
		RemoteURI:       remoteURI,
		RemoteTargetURI: firstVoiceNonEmpty(a.RemoteTargetURI, remoteURI),
		CallID:          strings.TrimSpace(req.CallID),
		LocalTag:        firstVoiceNonEmpty(a.LocalTag, "vowifi-go"),
		CSeq:            1,
		UserAgent:       firstVoiceNonEmpty(a.UserAgent, a.Profile.UserAgent, "vowifi-go"),
		SessionExpires:  a.SessionExpires,
	}
	inviteBody := append([]byte(nil), req.RawSDP...)
	var relay *RTPRelaySession
	if a.MediaRelay != nil {
		createdRelay, relayErr := NewRTPRelaySession(ctx, *a.MediaRelay, req.RemoteSDP)
		if relayErr != nil {
			return OutboundCallResult{Accepted: false, Reason: "RTP relay setup failed"}, relayErr
		}
		relay = createdRelay
		inviteBody = RewriteSDPMediaEndpoint(req.RawSDP, relay.IMSEndpoint())
	}
	closeRelayOnError := true
	defer func() {
		if closeRelayOnError && relay != nil {
			_ = relay.Close()
		}
	}()
	invite, err := voiceclient.BuildInviteRequest(cfg, inviteBody)
	if err != nil {
		return OutboundCallResult{Accepted: false, Reason: "build IMS INVITE failed"}, err
	}
	a.storeDialog(strings.TrimSpace(req.CallID), imsDialogState{cfg: cfg, invite: invite, relay: relay, early: true})
	nextCSeq := cfg.CSeq + 1
	var provisionalSDP SDPInfo
	var provisionalAnswer []byte
	resp, err := a.roundTripInvite(ctx, invite, func(provisional voiceclient.SIPResponse) error {
		if body, info, ok, err := a.provisionalAnswer(provisional, relay); err != nil {
			return err
		} else if ok {
			provisionalAnswer = body
			provisionalSDP = info
		}
		prack, ok, err := buildReliableProvisionalPRACK(cfg, provisional, nextCSeq)
		if err != nil || !ok {
			return err
		}
		prackResp, err := a.Transport.RoundTripRequest(ctx, prack)
		if err != nil {
			return fmt.Errorf("IMS PRACK failed: %w", err)
		}
		if prackResp.StatusCode < 200 || prackResp.StatusCode >= 300 {
			return fmt.Errorf("IMS PRACK rejected: %d %s", prackResp.StatusCode, strings.TrimSpace(prackResp.Reason))
		}
		nextCSeq++
		return nil
	})
	if err != nil {
		a.deleteDialog(strings.TrimSpace(req.CallID))
		return OutboundCallResult{Accepted: false, Reason: "IMS INVITE failed"}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode >= 300 {
			if err := a.ackRejectedInvite(ctx, cfg, invite, resp); err != nil {
				a.deleteDialog(strings.TrimSpace(req.CallID))
				return OutboundCallResult{Accepted: false, Reason: "IMS INVITE rejected ACK failed"}, err
			}
		}
		a.deleteDialog(strings.TrimSpace(req.CallID))
		return OutboundCallResult{
			Accepted:   false,
			StatusCode: outboundStatusCode(resp.StatusCode, 486),
			Reason:     firstVoiceNonEmpty(resp.Reason, fmt.Sprintf("IMS rejected call: %d", resp.StatusCode)),
		}, nil
	}
	cfg.RemoteTag = sipHeaderTag(firstVoiceHeader(resp.Headers, "To"))
	if contact := sipHeaderURI(firstVoiceHeader(resp.Headers, "Contact")); contact != "" {
		cfg.RemoteTargetURI = contact
	}
	ack, err := voiceclient.BuildAckRequest(cfg)
	if err != nil {
		return OutboundCallResult{Accepted: false, Reason: "build IMS ACK failed"}, err
	}
	if err := a.Transport.WriteRequest(ctx, ack); err != nil {
		return OutboundCallResult{Accepted: false, Reason: "IMS ACK failed"}, err
	}
	answerBody := append([]byte(nil), resp.Body...)
	localSDP := provisionalSDP
	if len(answerBody) == 0 {
		answerBody = append([]byte(nil), provisionalAnswer...)
	}
	if len(resp.Body) > 0 {
		parsed, err := ParseSDP(resp.Body)
		if err != nil {
			a.deleteDialog(strings.TrimSpace(req.CallID))
			return OutboundCallResult{Accepted: false, Reason: "invalid IMS SDP answer"}, err
		}
		localSDP = parsed
	}
	if relay != nil && len(resp.Body) > 0 {
		if err := relay.SetIMSRemote(localSDP); err != nil {
			a.deleteDialog(strings.TrimSpace(req.CallID))
			return OutboundCallResult{Accepted: false, Reason: "RTP relay remote setup failed"}, err
		}
		answerBody = RewriteSDPMediaEndpoint(resp.Body, relay.ClientEndpoint())
		localSDP, err = ParseSDP(answerBody)
		if err != nil {
			a.deleteDialog(strings.TrimSpace(req.CallID))
			return OutboundCallResult{Accepted: false, Reason: "invalid RTP relay SDP answer"}, err
		}
	}
	if localSDP.MediaPort <= 0 || strings.TrimSpace(localSDP.ConnectionIP) == "" {
		parsed, err := ParseSDP(answerBody)
		if err != nil {
			a.deleteDialog(strings.TrimSpace(req.CallID))
			return OutboundCallResult{Accepted: false, Reason: "invalid IMS SDP answer"}, err
		}
		localSDP = parsed
	}
	byeCfg := cfg
	byeCfg.CSeq = nextCSeq
	a.storeDialog(strings.TrimSpace(req.CallID), imsDialogState{cfg: byeCfg, relay: relay})
	closeRelayOnError = false
	return OutboundCallResult{
		Accepted:   true,
		StatusCode: outboundStatusCode(resp.StatusCode, 200),
		Reason:     firstVoiceNonEmpty(resp.Reason, "OK"),
		LocalSDP:   localSDP,
		RawSDP:     answerBody,
	}, nil
}

func (a *IMSOutboundAgent) EndVoiceCall(ctx context.Context, info DialogInfo) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.Transport == nil {
		return ErrIMSVoiceAgentNotReady
	}
	callID := strings.TrimSpace(info.CallID)
	if callID == "" {
		return nil
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	a.mu.Unlock()
	if !ok {
		return nil
	}
	bye, err := voiceclient.BuildByeRequest(state.cfg)
	if err != nil {
		return err
	}
	resp, err := a.Transport.RoundTripRequest(ctx, bye)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("IMS BYE rejected: %d %s", resp.StatusCode, strings.TrimSpace(resp.Reason))
	}
	if state.relay != nil {
		_ = state.relay.Close()
	}
	a.mu.Lock()
	delete(a.dialogs, callID)
	a.mu.Unlock()
	return nil
}

func (a *IMSOutboundAgent) ackRejectedInvite(ctx context.Context, cfg voiceclient.DialogRequestConfig, invite voiceclient.SIPRequestMessage, resp voiceclient.SIPResponse) error {
	ackCfg := cfg
	ackCfg.RemoteTag = firstVoiceNonEmpty(sipHeaderTag(firstVoiceHeader(resp.Headers, "To")), cfg.RemoteTag)
	ack, err := voiceclient.BuildAckRequest(ackCfg)
	if err != nil {
		return err
	}
	copyDialogHeader(ack.Headers, invite.Headers, "Via")
	return a.Transport.WriteRequest(ctx, ack)
}

func (a *IMSOutboundAgent) CancelVoiceCall(ctx context.Context, info DialogInfo) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.Transport == nil {
		return ErrIMSVoiceAgentNotReady
	}
	callID := strings.TrimSpace(info.CallID)
	if callID == "" {
		return nil
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	a.mu.Unlock()
	if !ok || !state.early {
		return nil
	}
	cancel, err := voiceclient.BuildCancelRequest(state.cfg)
	if err != nil {
		return err
	}
	copyDialogHeader(cancel.Headers, state.invite.Headers, "Via")
	resp, err := a.Transport.RoundTripRequest(ctx, cancel)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("IMS CANCEL rejected: %d %s", resp.StatusCode, strings.TrimSpace(resp.Reason))
	}
	a.deleteDialog(callID)
	return nil
}

func (a *IMSOutboundAgent) provisionalAnswer(resp voiceclient.SIPResponse, relay *RTPRelaySession) ([]byte, SDPInfo, bool, error) {
	if len(resp.Body) == 0 {
		return nil, SDPInfo{}, false, nil
	}
	remoteSDP, err := ParseSDP(resp.Body)
	if err != nil {
		return nil, SDPInfo{}, false, fmt.Errorf("invalid IMS provisional SDP answer: %w", err)
	}
	answerBody := append([]byte(nil), resp.Body...)
	localSDP := remoteSDP
	if relay != nil {
		if err := relay.SetIMSRemote(remoteSDP); err != nil {
			return nil, SDPInfo{}, false, fmt.Errorf("RTP relay provisional remote setup failed: %w", err)
		}
		answerBody = RewriteSDPMediaEndpoint(resp.Body, relay.ClientEndpoint())
		localSDP, err = ParseSDP(answerBody)
		if err != nil {
			return nil, SDPInfo{}, false, fmt.Errorf("invalid RTP relay provisional SDP answer: %w", err)
		}
	}
	return answerBody, localSDP, true, nil
}

func (a *IMSOutboundAgent) storeDialog(callID string, state imsDialogState) {
	if a == nil || strings.TrimSpace(callID) == "" {
		return
	}
	a.mu.Lock()
	if a.dialogs == nil {
		a.dialogs = make(map[string]imsDialogState)
	}
	a.dialogs[strings.TrimSpace(callID)] = state
	a.mu.Unlock()
}

func (a *IMSOutboundAgent) deleteDialog(callID string) {
	if a == nil || strings.TrimSpace(callID) == "" {
		return
	}
	a.mu.Lock()
	state, ok := a.dialogs[strings.TrimSpace(callID)]
	if ok {
		delete(a.dialogs, strings.TrimSpace(callID))
	}
	a.mu.Unlock()
	if ok && state.relay != nil {
		_ = state.relay.Close()
	}
}

func (a *IMSOutboundAgent) roundTripInvite(ctx context.Context, invite voiceclient.SIPRequestMessage, onProvisional func(voiceclient.SIPResponse) error) (voiceclient.SIPResponse, error) {
	if a == nil || a.Transport == nil {
		return voiceclient.SIPResponse{}, ErrIMSVoiceAgentNotReady
	}
	if inviteTransport, ok := a.Transport.(voiceclient.SIPInviteTransport); ok {
		return inviteTransport.RoundTripInvite(ctx, invite, func(_ context.Context, _ voiceclient.SIPRequestMessage, resp voiceclient.SIPResponse) error {
			if onProvisional == nil {
				return nil
			}
			return onProvisional(resp)
		})
	}
	return a.Transport.RoundTripRequest(ctx, invite)
}

func buildReliableProvisionalPRACK(cfg voiceclient.DialogRequestConfig, resp voiceclient.SIPResponse, cseq int) (voiceclient.SIPRequestMessage, bool, error) {
	if resp.StatusCode <= 100 || resp.StatusCode >= 200 {
		return voiceclient.SIPRequestMessage{}, false, nil
	}
	rseq := firstVoiceHeader(resp.Headers, "RSeq")
	if strings.TrimSpace(rseq) == "" || !headerHasToken(resp.Headers, "Require", "100rel") {
		return voiceclient.SIPRequestMessage{}, false, nil
	}
	prackCfg := cfg
	prackCfg.CSeq = cseq
	prackCfg.RemoteTag = firstVoiceNonEmpty(sipHeaderTag(firstVoiceHeader(resp.Headers, "To")), cfg.RemoteTag)
	if contact := sipHeaderURI(firstVoiceHeader(resp.Headers, "Contact")); contact != "" {
		prackCfg.RemoteTargetURI = contact
	}
	prack, err := voiceclient.BuildPrackRequest(prackCfg, strings.TrimSpace(rseq)+" "+strconv.Itoa(outboundInviteCSeq(cfg.CSeq))+" INVITE")
	return prack, err == nil, err
}

func outboundInviteCSeq(cseq int) int {
	if cseq <= 0 {
		return 1
	}
	return cseq
}

func outboundStatusCode(code, fallback int) int {
	if code >= 100 && code <= 699 {
		return code
	}
	return fallback
}

func headerHasToken(headers map[string][]string, name, token string) bool {
	token = strings.ToLower(strings.TrimSpace(token))
	if token == "" {
		return false
	}
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		for _, value := range values {
			for _, part := range strings.Split(value, ",") {
				if strings.EqualFold(strings.TrimSpace(part), token) {
					return true
				}
			}
		}
	}
	return false
}

func copyDialogHeader(dst, src map[string]string, name string) {
	if dst == nil || src == nil || strings.TrimSpace(name) == "" {
		return
	}
	for key, value := range src {
		if strings.EqualFold(key, name) && strings.TrimSpace(value) != "" {
			dst[name] = strings.TrimSpace(value)
			return
		}
	}
}

func (a *IMSOutboundAgent) remoteURI(callee string) string {
	callee = strings.TrimSpace(callee)
	if callee == "" {
		return ""
	}
	lower := strings.ToLower(callee)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") || strings.HasPrefix(lower, "tel:") {
		return callee
	}
	domain := firstVoiceNonEmpty(a.Domain, a.Profile.Domain, domainFromURI(a.Registration.PublicIdentity))
	if domain == "" {
		return "sip:" + callee
	}
	return "sip:" + callee + "@" + domain
}

func firstVoiceHeader(headers map[string][]string, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return strings.TrimSpace(values[0])
		}
	}
	return ""
}

func sipHeaderURI(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if start := strings.IndexByte(value, '<'); start >= 0 {
		if end := strings.IndexByte(value[start+1:], '>'); end >= 0 {
			return strings.TrimSpace(value[start+1 : start+1+end])
		}
	}
	if semi := strings.IndexByte(value, ';'); semi >= 0 {
		value = value[:semi]
	}
	return strings.TrimSpace(strings.Trim(value, "<>"))
}

func sipHeaderTag(value string) string {
	for _, part := range strings.Split(value, ";") {
		key, raw, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "tag") {
			return strings.Trim(strings.TrimSpace(raw), `"`)
		}
	}
	return ""
}

func domainFromURI(uri string) string {
	uri = strings.TrimSpace(uri)
	if strings.HasPrefix(strings.ToLower(uri), "sip:") {
		uri = uri[4:]
	}
	if _, host, ok := strings.Cut(uri, "@"); ok {
		if semi := strings.IndexByte(host, ';'); semi >= 0 {
			host = host[:semi]
		}
		return strings.Trim(strings.TrimSpace(host), "<>")
	}
	return ""
}

func firstVoiceNonEmpty(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}
