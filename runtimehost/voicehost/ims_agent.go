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
	var invite voiceclient.SIPRequestMessage
	var resp voiceclient.SIPResponse
	var err error
	inviteCSeq := cfg.CSeq
	nextCSeq := inviteCSeq + 1
	retriedSessionInterval := false
	var provisionalSDP SDPInfo
	var provisionalAnswer []byte
	for {
		cfg.CSeq = inviteCSeq
		invite, err = voiceclient.BuildInviteRequest(cfg, inviteBody)
		if err != nil {
			return OutboundCallResult{Accepted: false, Reason: "build IMS INVITE failed"}, err
		}
		a.storeDialog(strings.TrimSpace(req.CallID), imsDialogState{cfg: cfg, invite: invite, relay: relay, early: true})
		provisionalSDP = SDPInfo{}
		provisionalAnswer = nil
		resp, err = a.roundTripInvite(ctx, invite, func(provisional voiceclient.SIPResponse) error {
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
		if resp.StatusCode == 422 && !retriedSessionInterval {
			if minSE := minSEHeader(resp.Headers); minSE > cfg.SessionExpires {
				if err := a.ackRejectedInvite(ctx, cfg, invite, resp); err != nil {
					a.deleteDialog(strings.TrimSpace(req.CallID))
					return OutboundCallResult{Accepted: false, Reason: "IMS INVITE session interval ACK failed"}, err
				}
				cfg.SessionExpires = minSE
				cfg.MinSE = minSE
				retriedSessionInterval = true
				inviteCSeq = nextCSeq
				nextCSeq++
				continue
			}
		}
		break
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

func (a *IMSOutboundAgent) SendDialogInfo(ctx context.Context, req DialogInfoRequest) (DialogInfoResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.Transport == nil {
		return DialogInfoResult{Accepted: false, Reason: "IMS voice transport unavailable"}, ErrIMSVoiceAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return DialogInfoResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return DialogInfoResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	cfg := state.cfg
	info, err := voiceclient.BuildInfoRequest(cfg, req.ContentType, req.Body)
	if err != nil {
		a.mu.Unlock()
		return DialogInfoResult{Accepted: false, StatusCode: 500, Reason: "build IMS INFO failed"}, err
	}
	applyDialogInfoHeaders(info.Headers, req.InfoPackage, req.Headers)
	state.cfg.CSeq = outboundNextCSeq(cfg.CSeq)
	a.dialogs[callID] = state
	a.mu.Unlock()
	resp, err := a.Transport.RoundTripRequest(ctx, info)
	if err != nil {
		return DialogInfoResult{Accepted: false, Reason: "IMS INFO failed"}, err
	}
	return DialogInfoResult{
		Accepted:    resp.StatusCode >= 200 && resp.StatusCode < 300,
		StatusCode:  outboundStatusCode(resp.StatusCode, 500),
		Reason:      firstVoiceNonEmpty(resp.Reason, "OK"),
		ContentType: firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:        append([]byte(nil), resp.Body...),
		Headers:     firstValueSIPHeaders(resp.Headers),
	}, nil
}

func (a *IMSOutboundAgent) SendDialogUpdate(ctx context.Context, req DialogUpdateRequest) (DialogUpdateResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.Transport == nil {
		return DialogUpdateResult{Accepted: false, Reason: "IMS voice transport unavailable"}, ErrIMSVoiceAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return DialogUpdateResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	body := append([]byte(nil), req.Body...)
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return DialogUpdateResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	cfg := state.cfg
	if len(body) > 0 && state.relay != nil {
		clientSDP, err := ParseSDP(body)
		if err != nil {
			a.mu.Unlock()
			return DialogUpdateResult{Accepted: false, StatusCode: 488, Reason: "invalid client UPDATE SDP"}, err
		}
		if err := state.relay.SetClientRemote(clientSDP); err != nil {
			a.mu.Unlock()
			return DialogUpdateResult{Accepted: false, StatusCode: 503, Reason: "RTP relay client update failed"}, err
		}
		body = RewriteSDPMediaEndpoint(body, state.relay.IMSEndpoint())
	}
	update, err := voiceclient.BuildUpdateRequest(cfg, body)
	if err != nil {
		a.mu.Unlock()
		return DialogUpdateResult{Accepted: false, StatusCode: 500, Reason: "build IMS UPDATE failed"}, err
	}
	if len(body) > 0 && strings.TrimSpace(req.ContentType) != "" {
		update.Headers["Content-Type"] = strings.TrimSpace(req.ContentType)
	}
	applyDialogUpdateHeaders(update.Headers, req.Headers)
	state.cfg.CSeq = outboundNextCSeq(cfg.CSeq)
	a.dialogs[callID] = state
	a.mu.Unlock()
	resp, err := a.Transport.RoundTripRequest(ctx, update)
	if err != nil {
		return DialogUpdateResult{Accepted: false, Reason: "IMS UPDATE failed"}, err
	}
	accepted := resp.StatusCode >= 200 && resp.StatusCode < 300
	resultBody := append([]byte(nil), resp.Body...)
	if accepted && len(resultBody) > 0 && state.relay != nil {
		imsSDP, err := ParseSDP(resultBody)
		if err != nil {
			return DialogUpdateResult{Accepted: false, StatusCode: 488, Reason: "invalid IMS UPDATE SDP answer"}, err
		}
		if err := state.relay.SetIMSRemote(imsSDP); err != nil {
			return DialogUpdateResult{Accepted: false, StatusCode: 503, Reason: "RTP relay IMS update failed"}, err
		}
		resultBody = RewriteSDPMediaEndpoint(resultBody, state.relay.ClientEndpoint())
	}
	if contact := sipHeaderURI(firstVoiceHeader(resp.Headers, "Contact")); accepted && contact != "" {
		a.mu.Lock()
		if latest, ok := a.dialogs[callID]; ok {
			latest.cfg.RemoteTargetURI = contact
			a.dialogs[callID] = latest
		}
		a.mu.Unlock()
	}
	return DialogUpdateResult{
		Accepted:    accepted,
		StatusCode:  outboundStatusCode(resp.StatusCode, 500),
		Reason:      firstVoiceNonEmpty(resp.Reason, "OK"),
		ContentType: firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:        resultBody,
		Headers:     firstValueSIPHeaders(resp.Headers),
	}, nil
}

func (a *IMSOutboundAgent) SendDialogReinvite(ctx context.Context, req DialogReinviteRequest) (DialogReinviteResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.Transport == nil {
		return DialogReinviteResult{Accepted: false, Reason: "IMS voice transport unavailable"}, ErrIMSVoiceAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return DialogReinviteResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	body := append([]byte(nil), req.Body...)
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return DialogReinviteResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	cfg := state.cfg
	nextCSeq := outboundNextCSeq(cfg.CSeq)
	if len(body) > 0 && state.relay != nil {
		clientSDP, err := ParseSDP(body)
		if err != nil {
			a.mu.Unlock()
			return DialogReinviteResult{Accepted: false, StatusCode: 488, Reason: "invalid client re-INVITE SDP"}, err
		}
		if err := state.relay.SetClientRemote(clientSDP); err != nil {
			a.mu.Unlock()
			return DialogReinviteResult{Accepted: false, StatusCode: 503, Reason: "RTP relay client re-INVITE failed"}, err
		}
		body = RewriteSDPMediaEndpoint(body, state.relay.IMSEndpoint())
	}
	invite, err := voiceclient.BuildInviteRequest(cfg, body)
	if err != nil {
		a.mu.Unlock()
		return DialogReinviteResult{Accepted: false, StatusCode: 500, Reason: "build IMS re-INVITE failed"}, err
	}
	if len(body) > 0 && strings.TrimSpace(req.ContentType) != "" {
		invite.Headers["Content-Type"] = strings.TrimSpace(req.ContentType)
	}
	applyDialogUpdateHeaders(invite.Headers, req.Headers)
	state.cfg.CSeq = nextCSeq
	a.dialogs[callID] = state
	a.mu.Unlock()
	resp, err := a.roundTripInvite(ctx, invite, func(provisional voiceclient.SIPResponse) error {
		prack, ok, err := buildReliableProvisionalPRACK(cfg, provisional, nextCSeq)
		if err != nil || !ok {
			return err
		}
		prackResp, err := a.Transport.RoundTripRequest(ctx, prack)
		if err != nil {
			return fmt.Errorf("IMS re-INVITE PRACK failed: %w", err)
		}
		if prackResp.StatusCode < 200 || prackResp.StatusCode >= 300 {
			return fmt.Errorf("IMS re-INVITE PRACK rejected: %d %s", prackResp.StatusCode, strings.TrimSpace(prackResp.Reason))
		}
		nextCSeq++
		a.mu.Lock()
		if latest, ok := a.dialogs[callID]; ok {
			latest.cfg.CSeq = nextCSeq
			a.dialogs[callID] = latest
		}
		a.mu.Unlock()
		return nil
	})
	if err != nil {
		return DialogReinviteResult{Accepted: false, Reason: "IMS re-INVITE failed"}, err
	}
	accepted := resp.StatusCode >= 200 && resp.StatusCode < 300
	if !accepted {
		if resp.StatusCode >= 300 {
			if err := a.ackRejectedInvite(ctx, cfg, invite, resp); err != nil {
				return DialogReinviteResult{Accepted: false, StatusCode: 500, Reason: "IMS re-INVITE rejected ACK failed"}, err
			}
		}
		return DialogReinviteResult{
			Accepted:   false,
			StatusCode: outboundStatusCode(resp.StatusCode, 488),
			Reason:     firstVoiceNonEmpty(resp.Reason, "re-INVITE rejected"),
			Headers:    firstValueSIPHeaders(resp.Headers),
		}, nil
	}
	ackCfg := cfg
	ackCfg.RemoteTag = firstVoiceNonEmpty(sipHeaderTag(firstVoiceHeader(resp.Headers, "To")), cfg.RemoteTag)
	if contact := sipHeaderURI(firstVoiceHeader(resp.Headers, "Contact")); contact != "" {
		ackCfg.RemoteTargetURI = contact
	}
	ack, err := voiceclient.BuildAckRequest(ackCfg)
	if err != nil {
		return DialogReinviteResult{Accepted: false, StatusCode: 500, Reason: "build IMS re-INVITE ACK failed"}, err
	}
	if err := a.Transport.WriteRequest(ctx, ack); err != nil {
		return DialogReinviteResult{Accepted: false, StatusCode: 503, Reason: "IMS re-INVITE ACK failed"}, err
	}
	resultBody := append([]byte(nil), resp.Body...)
	if len(resultBody) > 0 && state.relay != nil {
		imsSDP, err := ParseSDP(resultBody)
		if err != nil {
			return DialogReinviteResult{Accepted: false, StatusCode: 488, Reason: "invalid IMS re-INVITE SDP answer"}, err
		}
		if err := state.relay.SetIMSRemote(imsSDP); err != nil {
			return DialogReinviteResult{Accepted: false, StatusCode: 503, Reason: "RTP relay IMS re-INVITE failed"}, err
		}
		resultBody = RewriteSDPMediaEndpoint(resultBody, state.relay.ClientEndpoint())
	}
	if ackCfg.RemoteTargetURI != cfg.RemoteTargetURI || ackCfg.RemoteTag != cfg.RemoteTag {
		a.mu.Lock()
		if latest, ok := a.dialogs[callID]; ok {
			latest.cfg.RemoteTargetURI = ackCfg.RemoteTargetURI
			latest.cfg.RemoteTag = ackCfg.RemoteTag
			a.dialogs[callID] = latest
		}
		a.mu.Unlock()
	}
	return DialogReinviteResult{
		Accepted:    true,
		StatusCode:  outboundStatusCode(resp.StatusCode, 200),
		Reason:      firstVoiceNonEmpty(resp.Reason, "OK"),
		ContentType: firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:        resultBody,
		Headers:     firstValueSIPHeaders(resp.Headers),
	}, nil
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

func outboundNextCSeq(cseq int) int {
	if cseq <= 0 {
		return 2
	}
	return cseq + 1
}

func outboundStatusCode(code, fallback int) int {
	if code >= 100 && code <= 699 {
		return code
	}
	return fallback
}

func minSEHeader(headers map[string][]string) int {
	for key, values := range headers {
		if !strings.EqualFold(key, "Min-SE") {
			continue
		}
		for _, value := range values {
			for _, part := range strings.Split(value, ",") {
				part = strings.TrimSpace(part)
				if semi := strings.IndexByte(part, ';'); semi >= 0 {
					part = part[:semi]
				}
				n, err := strconv.Atoi(strings.TrimSpace(part))
				if err == nil && n > 0 {
					return n
				}
			}
		}
	}
	return 0
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

func applyDialogInfoHeaders(dst map[string]string, infoPackage string, headers map[string]string) {
	if dst == nil {
		return
	}
	if strings.TrimSpace(infoPackage) != "" {
		dst["Info-Package"] = strings.TrimSpace(infoPackage)
	}
	for key, value := range headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || isProtectedDialogHeader(key) {
			continue
		}
		dst[key] = value
	}
}

func applyDialogUpdateHeaders(dst map[string]string, headers map[string]string) {
	if dst == nil {
		return
	}
	for key, value := range headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || isProtectedDialogHeader(key) {
			continue
		}
		dst[key] = value
	}
}

func applyIncomingInfoHeaders(dst map[string]string, infoPackage string, headers map[string][]string) {
	if dst == nil {
		return
	}
	if strings.TrimSpace(infoPackage) != "" {
		dst["Info-Package"] = strings.TrimSpace(infoPackage)
	}
	for key, values := range headers {
		key = strings.TrimSpace(key)
		if key == "" || isProtectedDialogHeader(key) {
			continue
		}
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				dst[key] = strings.TrimSpace(value)
				break
			}
		}
	}
}

func isProtectedDialogHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "to", "from", "call-id", "cseq", "max-forwards", "route", "record-route", "via", "contact", "content-length", "content-type":
		return true
	default:
		return false
	}
}

func firstValueSIPHeaders(headers map[string][]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for key, values := range headers {
		for _, value := range values {
			if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
				out[strings.TrimSpace(key)] = strings.TrimSpace(value)
				break
			}
		}
	}
	return out
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
