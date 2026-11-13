package voicehost

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kimoju/vowifi-go/runtimehost/voiceclient"
)

var ErrIMSInboundAgentNotReady = errors.New("ims inbound voice agent not ready")

type IMSInboundAgent struct {
	DeviceID             string
	ClientTransport      voiceclient.SIPRequestTransport
	IMSTransport         voiceclient.SIPRequestTransport
	Profile              voiceclient.IMSProfile
	Registration         voiceclient.RegistrationBinding
	Domain               string
	ClientContactURI     string
	ResolveClientContact func(deviceID string) (string, error)
	LocalContactURI      string
	LocalTag             string
	UserAgent            string
	SessionExpires       int
	SessionRefresher     string
	SessionRefreshLead   time.Duration
	MediaRelay           *RTPRelayConfig
	OnDialogEvent        func(ctx context.Context, info DialogInfo, callerURI string, calleeURI string, statusCode int, reason string)

	mu                     sync.Mutex
	dialogs                map[string]imsInboundDialogState
	nextPendingOfferSerial uint64
}

func (a *IMSInboundAgent) UpdateIMSRegistration(update IMSRegistrationUpdate) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if update.Transport != nil {
		a.IMSTransport = update.Transport
	}
	if strings.TrimSpace(update.Profile.IMPU) != "" || strings.TrimSpace(update.Profile.IMPI) != "" {
		a.Profile = update.Profile
	}
	if strings.TrimSpace(update.Registration.ContactURI) != "" {
		a.Registration = update.Registration
		a.LocalContactURI = update.Registration.ContactURI
	}
	if strings.TrimSpace(update.Domain) != "" {
		a.Domain = strings.TrimSpace(update.Domain)
	}
	if strings.TrimSpace(update.UserAgent) != "" {
		a.UserAgent = strings.TrimSpace(update.UserAgent)
	}
	if update.SessionExpires > 0 {
		a.SessionExpires = update.SessionExpires
	}
	if refresher := normalizeSessionRefresher(update.SessionRefresher); refresher != "" {
		a.SessionRefresher = refresher
	}
	if update.SessionRefreshLead > 0 {
		a.SessionRefreshLead = update.SessionRefreshLead
	}
	if update.MediaRelay != nil {
		a.MediaRelay = update.MediaRelay
	}
}

func (a *IMSInboundAgent) UpdateLocalContact(contactURI string) {
	if a == nil || strings.TrimSpace(contactURI) == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	contactURI = strings.TrimSpace(contactURI)
	a.LocalContactURI = contactURI
	a.Registration.ContactURI = contactURI
}

func (a *IMSInboundAgent) LocalContact() string {
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return firstVoiceNonEmpty(a.LocalContactURI, a.Registration.ContactURI, a.Profile.IMPU)
}

func (a *IMSInboundAgent) DefaultLocalTag() string {
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return strings.TrimSpace(a.LocalTag)
}

func (a *IMSInboundAgent) HasInboundDialog(callID string) bool {
	return a.hasInboundDialog(callID)
}

func (a *IMSInboundAgent) InboundDialogLocalTag(callID string) string {
	if a == nil || strings.TrimSpace(callID) == "" {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if state, ok := a.dialogs[strings.TrimSpace(callID)]; ok {
		return firstVoiceNonEmpty(state.imsCfg.LocalTag, a.LocalTag)
	}
	return ""
}

func (a *IMSInboundAgent) currentClientTransport() voiceclient.SIPRequestTransport {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	transport := a.ClientTransport
	a.mu.Unlock()
	return transport
}

func (a *IMSInboundAgent) currentIMSTransport() voiceclient.SIPRequestTransport {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	transport := a.IMSTransport
	a.mu.Unlock()
	return transport
}

func (a *IMSInboundAgent) roundTripClientRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error) {
	transport := a.currentClientTransport()
	if transport == nil {
		return voiceclient.SIPResponse{}, ErrIMSInboundAgentNotReady
	}
	return transport.RoundTripRequest(ctx, msg)
}

func (a *IMSInboundAgent) writeClientRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) error {
	transport := a.currentClientTransport()
	if transport == nil {
		return ErrIMSInboundAgentNotReady
	}
	return transport.WriteRequest(ctx, msg)
}

func (a *IMSInboundAgent) roundTripIMSRequestWithResult(ctx context.Context, msg voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, voiceclient.SIPRequestMessage, error) {
	transport := a.currentIMSTransport()
	if a == nil || transport == nil {
		return voiceclient.SIPResponse{}, msg, ErrIMSInboundAgentNotReady
	}
	return voiceclient.RoundTripRequestWithDigestAuthResult(ctx, transport, msg)
}

func (a *IMSInboundAgent) roundTripIMSInvite(ctx context.Context, invite voiceclient.SIPRequestMessage, onProvisional func(voiceclient.SIPResponse) error) (voiceclient.SIPResponse, voiceclient.SIPRequestMessage, error) {
	transport := a.currentIMSTransport()
	if a == nil || transport == nil {
		return voiceclient.SIPResponse{}, invite, ErrIMSInboundAgentNotReady
	}
	if inviteTransport, ok := transport.(voiceclient.SIPInviteTransport); ok {
		resp, err := inviteTransport.RoundTripInvite(ctx, invite, func(_ context.Context, _ voiceclient.SIPRequestMessage, resp voiceclient.SIPResponse) error {
			if onProvisional == nil {
				return nil
			}
			return onProvisional(resp)
		})
		if err != nil {
			return resp, invite, err
		}
		if err := voiceclient.ApplyDigestAuthenticationInfo(invite, resp); err != nil {
			return resp, invite, err
		}
		return resp, invite, nil
	}
	return a.roundTripIMSRequestWithResult(ctx, invite)
}

func (a *IMSInboundAgent) writeIMSRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) error {
	transport := a.currentIMSTransport()
	if transport == nil {
		return ErrIMSInboundAgentNotReady
	}
	return transport.WriteRequest(ctx, msg)
}

func (a *IMSInboundAgent) emitDialogEvent(ctx context.Context, callID string, callee string, state DialogState, callerURI string, calleeURI string, statusCode int, reason string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	cb := a.OnDialogEvent
	devID := strings.TrimSpace(a.DeviceID)
	a.mu.Unlock()
	if cb == nil {
		return
	}
	cb(ctx, DialogInfo{
		DeviceID:  devID,
		CallID:    strings.TrimSpace(callID),
		Callee:    strings.TrimSpace(callee),
		Direction: "inbound",
		State:     state,
	}, strings.TrimSpace(callerURI), strings.TrimSpace(calleeURI), statusCode, strings.TrimSpace(reason))
}

type InboundCallRequest struct {
	DeviceID        string
	CallID          string
	CallerURI       string
	CalleeURI       string
	LocalTag        string
	RemoteTag       string
	RemoteTargetURI string
	CSeq            int
	RemoteSDP       SDPInfo
	RawSDP          []byte
	Headers         map[string][]string
	onProvisional   func(InboundCallResult) error
}

type InboundCallResult struct {
	Accepted   bool
	StatusCode int
	Reason     string
	LocalTag   string
	LocalSDP   SDPInfo
	RawSDP     []byte
	Headers    map[string]string

	sdpFromProvisional bool
}

type InboundDialogRequest struct {
	CallID            string
	CSeq              int
	ContentType       string
	Body              []byte
	RawSDP            []byte
	RemoteSDP         SDPInfo
	Headers           map[string][]string
	RAck              string
	ReferTo           string
	ReferredBy        string
	ReferSub          string
	Event             string
	Expires           string
	SubscriptionState string
}

type imsInboundDialogState struct {
	clientCfg           voiceclient.DialogRequestConfig
	imsCfg              voiceclient.DialogRequestConfig
	invite              voiceclient.SIPRequestMessage
	inviteCSeq          int
	relay               *RTPRelaySession
	srtpNegotiation     *inboundSDESRelayNegotiation
	clientSDPBody       []byte
	early               bool
	terminating         bool
	inviteInFlight      bool
	provisionalSeen     bool
	cancelRequested     bool
	cancelSent          bool
	canceled            bool
	pendingCancel       DialogInfo
	awaitingIMSAckOffer bool
	pendingIMSAckCfg    voiceclient.DialogRequestConfig
	hasPendingIMSAck    bool
	lastIMSRemoteCSeq   int
	sessionExpires      int
	sessionRole         string // "local" (we refresh) or "ims" (IMS refreshes, we watch expiry)
	sessionDeadline     time.Time
	refreshTimer        *time.Timer
	expiryTimer         *time.Timer
	refreshSeq          uint64
	pendingOffer        imsInboundPendingOffer
}

type imsInboundPendingOffer struct {
	active bool
	serial uint64
	method string
	cseq   int
}

type imsInboundDialogConcurrencyDecision struct {
	trackPendingOffer bool
	statusCode        int
	reason            string
}

func cloneInboundDialogStateSnapshot(state imsInboundDialogState) imsInboundDialogState {
	out := state
	out.clientCfg = cloneDialogRequestConfig(state.clientCfg)
	out.imsCfg = cloneDialogRequestConfig(state.imsCfg)
	out.invite = cloneSIPRequestMessage(state.invite)
	out.clientSDPBody = append([]byte(nil), state.clientSDPBody...)
	out.pendingCancel = cloneDialogInfo(state.pendingCancel)
	out.pendingIMSAckCfg = cloneDialogRequestConfig(state.pendingIMSAckCfg)
	return out
}

func (a *IMSInboundAgent) HandleInboundInvite(ctx context.Context, req InboundCallRequest) (InboundCallResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentClientTransport() == nil {
		return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "client voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return InboundCallResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	if _, ok := a.inboundDialog(callID); ok {
		return a.handleInboundReinvite(ctx, req)
	}
	a.mu.Lock()
	profile := a.Profile
	registration := a.Registration
	clientTarget := strings.TrimSpace(a.ClientContactURI)
	resolveClientContact := a.ResolveClientContact
	deviceID := firstVoiceNonEmpty(req.DeviceID, a.DeviceID)
	localContactURI := a.LocalContactURI
	localTag := a.LocalTag
	userAgent := a.UserAgent
	mediaRelay := effectiveMediaRelayForLocalIP(a.MediaRelay, profile.LocalIP)
	a.mu.Unlock()

	dialogLocalTag := firstVoiceNonEmpty(req.LocalTag, localTag, randomVoiceSIPTag())

	callerURI := strings.TrimSpace(req.CallerURI)
	if callerURI == "" {
		return InboundCallResult{Accepted: false, StatusCode: 400, Reason: "caller URI empty", LocalTag: dialogLocalTag}, errors.New("caller URI is empty")
	}
	calleeURI := firstVoiceNonEmpty(req.CalleeURI, registration.PublicIdentity, profile.IMPU)
	if calleeURI == "" {
		return InboundCallResult{Accepted: false, StatusCode: 400, Reason: "callee URI empty", LocalTag: dialogLocalTag}, errors.New("callee URI is empty")
	}
	if clientTarget == "" && resolveClientContact != nil {
		resolved, resolveErr := resolveClientContact(deviceID)
		clientTarget = strings.TrimSpace(resolved)
		if clientTarget == "" {
			a.emitDialogEvent(ctx, callID, calleeURI, DialogStateTerminated, callerURI, calleeURI, 480, "Temporarily Unavailable")
			if resolveErr != nil {
				return InboundCallResult{Accepted: false, StatusCode: 480, Reason: "Temporarily Unavailable", LocalTag: dialogLocalTag}, resolveErr
			}
			return InboundCallResult{Accepted: false, StatusCode: 480, Reason: "Temporarily Unavailable", LocalTag: dialogLocalTag}, ErrIMSInboundAgentNotReady
		}
	}
	if clientTarget == "" {
		return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "client contact unavailable", LocalTag: dialogLocalTag}, ErrIMSInboundAgentNotReady
	}

	hasOffer := inboundCallRequestHasOffer(req)
	var remoteSDP SDPInfo
	var offerBody []byte
	var imsOfferBody []byte
	var err error
	if hasOffer {
		remoteSDP, offerBody, err = inboundOfferSDP(req)
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid IMS SDP offer", LocalTag: dialogLocalTag}, err
		}
		imsOfferBody = append([]byte(nil), offerBody...)
	}

	var relay *RTPRelaySession
	var srtpNegotiation *inboundSDESRelayNegotiation
	closeRelayOnError := true
	defer func() {
		if closeRelayOnError && relay != nil {
			_ = relay.Close()
		}
	}()
	if hasOffer && mediaRelay != nil {
		createdRelay, relayErr := NewRTPRelaySessionForIMSRemote(ctx, *mediaRelay, remoteSDP)
		if relayErr != nil {
			return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "RTP relay setup failed", LocalTag: dialogLocalTag}, relayErr
		}
		relay = createdRelay
		offerBody = RewriteSDPMediaEndpoint(offerBody, relay.ClientEndpoint())
		if mediaRelay.SRTP != nil {
			negotiation, err := newInboundSDESRelayNegotiation(imsOfferBody, *mediaRelay.SRTP)
			if err != nil {
				return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "RTP relay SRTP negotiation failed", LocalTag: dialogLocalTag}, err
			}
			srtpNegotiation = negotiation
			offerBody = srtpNegotiation.RewriteClientOffer(offerBody)
		}
	}

	initialIMSRemoteCSeq := inboundCSeq(req.CSeq)
	cfg := voiceclient.DialogRequestConfig{
		Profile:         profile,
		Registration:    voiceclient.RegistrationBinding{},
		LocalURI:        callerURI,
		ContactURI:      firstVoiceNonEmpty(localContactURI, registration.ContactURI, profile.IMPU),
		RemoteURI:       calleeURI,
		RemoteTargetURI: clientTarget,
		CallID:          callID,
		LocalTag:        firstVoiceNonEmpty(req.RemoteTag, localTag, randomVoiceSIPTag()),
		CSeq:            initialIMSRemoteCSeq,
		UserAgent:       firstVoiceNonEmpty(userAgent, profile.UserAgent, "vowifi-go"),
	}
	applyInboundSessionIntervalHeaders(&cfg, req.Headers)

	imsCfg := voiceclient.DialogRequestConfig{
		Profile:         profile,
		Registration:    registration,
		LocalURI:        calleeURI,
		ContactURI:      firstVoiceNonEmpty(localContactURI, registration.ContactURI, profile.IMPU),
		RemoteURI:       callerURI,
		RemoteTargetURI: firstVoiceNonEmpty(req.RemoteTargetURI, callerURI),
		CallID:          callID,
		LocalTag:        dialogLocalTag,
		RemoteTag:       strings.TrimSpace(req.RemoteTag),
		RouteSet:        uasRecordRouteSet(req.Headers),
		CSeq:            1,
		UserAgent:       firstVoiceNonEmpty(userAgent, profile.UserAgent, "vowifi-go"),
	}

	a.emitDialogEvent(ctx, callID, calleeURI, DialogStateEarly, callerURI, calleeURI, 180, "Ringing")
	var invite voiceclient.SIPRequestMessage
	var resp voiceclient.SIPResponse
	retriedSessionInterval := false
	retriedPlaintextClient := false
	redirectRetries := 0
	var provisionalAnswer InboundCallResult
	for {
		invite, err = voiceclient.BuildInviteRequest(cfg, offerBody)
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 500, Reason: "build client INVITE failed", LocalTag: dialogLocalTag}, err
		}
		ensureInboundClientInviteVia(&invite, cfg)
		a.storeInFlightInboundDialog(callID, cfg, imsCfg, invite, relay, srtpNegotiation, initialIMSRemoteCSeq)
		provisionalAnswer = InboundCallResult{}
		resp, err = a.roundTripClientInvite(ctx, invite, a.inboundProvisionalHandler(ctx, callID, dialogLocalTag, imsOfferBody, relay, srtpNegotiation, func(result InboundCallResult) error {
			if len(result.RawSDP) > 0 {
				provisionalAnswer = cloneInboundCallResult(result)
			}
			if req.onProvisional != nil {
				return req.onProvisional(result)
			}
			return nil
		}))
		if err != nil {
			a.deleteInboundDialog(callID)
			a.emitDialogEvent(ctx, callID, calleeURI, DialogStateTerminated, callerURI, calleeURI, 503, "client INVITE failed")
			return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "client INVITE failed", LocalTag: dialogLocalTag}, err
		}
		if (resp.StatusCode == 488 || resp.StatusCode == 415) && !retriedPlaintextClient &&
			srtpNegotiation != nil && !srtpNegotiation.IsClientPlaintext() && relay != nil && len(imsOfferBody) > 0 &&
			!a.isInboundCancelRequested(callID) {
			if err := a.ackRejectedClientInvite(ctx, cfg, invite, resp); err != nil {
				a.deleteInboundDialog(callID)
				return InboundCallResult{Accepted: false, StatusCode: 500, Reason: "client INVITE SRTP fallback ACK failed", LocalTag: dialogLocalTag}, err
			}
			srtpNegotiation.ForceClientPlaintext()
			offerBody = srtpNegotiation.RewriteClientOffer(RewriteSDPMediaEndpoint(imsOfferBody, relay.ClientEndpoint()))
			cfg.CSeq = nextInboundClientCSeq(cfg.CSeq)
			retriedPlaintextClient = true
			continue
		}
		if resp.StatusCode == 422 && !retriedSessionInterval && !a.isInboundCancelRequested(callID) {
			if retryCfg, ok := retryDialogConfigForMinSE(cfg, invite.Headers, resp.Headers); ok {
				if err := a.ackRejectedClientInvite(ctx, cfg, invite, resp); err != nil {
					a.deleteInboundDialog(callID)
					return InboundCallResult{Accepted: false, StatusCode: 500, Reason: "client INVITE session interval ACK failed", LocalTag: dialogLocalTag}, err
				}
				cfg = retryCfg
				retriedSessionInterval = true
				continue
			}
		}
		if redirectRetries < maxIMSInviteRedirects && !a.isInboundCancelRequested(callID) {
			if retryCfg, ok := retryDialogConfigForRedirect(cfg, resp, nextInboundClientCSeq(cfg.CSeq)); ok {
				if err := a.ackRejectedClientInvite(ctx, cfg, invite, resp); err != nil {
					a.deleteInboundDialog(callID)
					return InboundCallResult{Accepted: false, StatusCode: 500, Reason: "client INVITE redirect ACK failed", LocalTag: dialogLocalTag}, err
				}
				cfg = retryCfg
				redirectRetries++
				continue
			}
		}
		break
	}
	if a.isInboundCancelRequested(callID) {
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			ackCfg := cfg
			ackCfg.RemoteTag = firstVoiceNonEmpty(sipHeaderTag(firstVoiceHeader(resp.Headers, "To")), cfg.RemoteTag)
			if contact := sipHeaderURI(firstVoiceHeader(resp.Headers, "Contact")); contact != "" {
				ackCfg.RemoteTargetURI = contact
			}
			if routeSet := recordRouteSet(resp.Headers); len(routeSet) > 0 {
				ackCfg.RouteSet = routeSet
			}
			if ack, ackErr := voiceclient.BuildAckRequest(ackCfg); ackErr == nil {
				_ = a.writeClientRequest(ctx, ack)
			}
			byeCfg := ackCfg
			byeCfg.CSeq = nextInboundClientCSeq(ackCfg.CSeq)
			if bye, byeErr := voiceclient.BuildByeRequestWithBody(byeCfg, "", nil); byeErr == nil {
				_, _ = a.roundTripClientRequest(ctx, bye)
			}
		} else if resp.StatusCode >= 300 {
			if err := a.ackRejectedClientInvite(ctx, cfg, invite, resp); err != nil {
				a.deleteInboundDialog(callID)
				a.emitDialogEvent(ctx, callID, calleeURI, DialogStateTerminated, callerURI, calleeURI, 500, "client INVITE canceled ACK failed")
				return InboundCallResult{Accepted: false, StatusCode: 500, Reason: "client INVITE canceled ACK failed", LocalTag: dialogLocalTag}, err
			}
		}
		a.deleteInboundDialog(callID)
		a.emitDialogEvent(ctx, callID, calleeURI, DialogStateTerminated, callerURI, calleeURI, 487, "Request Terminated")
		return InboundCallResult{Accepted: false, StatusCode: 487, Reason: "Request Terminated", LocalTag: dialogLocalTag}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode >= 300 {
			if err := a.ackRejectedClientInvite(ctx, cfg, invite, resp); err != nil {
				a.deleteInboundDialog(callID)
				a.emitDialogEvent(ctx, callID, calleeURI, DialogStateTerminated, callerURI, calleeURI, 500, "client INVITE rejected ACK failed")
				return InboundCallResult{Accepted: false, StatusCode: 500, Reason: "client INVITE rejected ACK failed", LocalTag: dialogLocalTag}, err
			}
		}
		a.deleteInboundDialog(callID)
		finalCode := inboundStatusCode(resp.StatusCode, 486)
		finalReason := firstVoiceNonEmpty(resp.Reason, "Busy Here")
		a.emitDialogEvent(ctx, callID, calleeURI, DialogStateTerminated, callerURI, calleeURI, finalCode, finalReason)
		return InboundCallResult{
			Accepted:   false,
			StatusCode: finalCode,
			Reason:     finalReason,
			LocalTag:   dialogLocalTag,
			Headers:    firstValueSIPHeaders(resp.Headers),
		}, nil
	}

	answerBody := append([]byte(nil), resp.Body...)
	var clientSDPBody []byte
	var localSDP SDPInfo
	sdpFromProvisional := false
	awaitingIMSAckOffer := false
	if len(resp.Body) == 0 && len(provisionalAnswer.RawSDP) > 0 {
		answerBody = append([]byte(nil), provisionalAnswer.RawSDP...)
		localSDP = provisionalAnswer.LocalSDP
		sdpFromProvisional = true
	} else {
		localSDP, err = ParseSDP(resp.Body)
		if err != nil {
			a.deleteInboundDialog(callID)
			return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid client SDP answer", LocalTag: dialogLocalTag}, err
		}
		clientSDPBody = append([]byte(nil), resp.Body...)
	}

	if !hasOffer {
		// Late-offer initial INVITE from IMS: client's 200 OK carries the SDP offer,
		// and IMS will supply the SDP answer in ACK (RFC 3261 §13.2.1).
		awaitingIMSAckOffer = true
		if mediaRelay != nil && len(resp.Body) > 0 {
			createdRelay, relayErr := NewRTPRelaySession(ctx, *mediaRelay, localSDP)
			if relayErr != nil {
				a.deleteInboundDialog(callID)
				return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "RTP relay late-offer setup failed", LocalTag: dialogLocalTag}, relayErr
			}
			relay = createdRelay
			answerBody = RewriteSDPMediaEndpoint(resp.Body, relay.IMSEndpoint())
			localSDP, err = ParseSDP(answerBody)
			if err != nil {
				a.deleteInboundDialog(callID)
				return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid RTP relay late-offer SDP", LocalTag: dialogLocalTag}, err
			}
		}
	} else if relay != nil && len(resp.Body) > 0 {
		if err := relay.SetClientRemote(localSDP); err != nil {
			a.deleteInboundDialog(callID)
			return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "RTP relay client setup failed", LocalTag: dialogLocalTag}, err
		}
		precondBody := RewriteSDPPreconditionsForAnswer(imsOfferBody, resp.Body)
		if srtpNegotiation != nil {
			answerBody, localSDP, err = srtpNegotiation.RewriteIMSAnswer(relay, precondBody, localSDP)
			if err != nil {
				a.deleteInboundDialog(callID)
				return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid RTP relay SRTP SDP answer", LocalTag: dialogLocalTag}, err
			}
		} else {
			answerBody = RewriteSDPMediaEndpoint(precondBody, relay.IMSEndpoint())
			localSDP, err = ParseSDP(answerBody)
			if err != nil {
				a.deleteInboundDialog(callID)
				return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid RTP relay SDP answer", LocalTag: dialogLocalTag}, err
			}
		}
	} else if len(imsOfferBody) > 0 && len(answerBody) > 0 && !sdpFromProvisional {
		answerBody = RewriteSDPPreconditionsForAnswer(imsOfferBody, answerBody)
	}

	cfg.RemoteTag = sipHeaderTag(firstVoiceHeader(resp.Headers, "To"))
	if contact := sipHeaderURI(firstVoiceHeader(resp.Headers, "Contact")); contact != "" {
		cfg.RemoteTargetURI = contact
	}
	if routeSet := recordRouteSet(resp.Headers); len(routeSet) > 0 {
		cfg.RouteSet = routeSet
	}
	applyInboundNegotiatedSessionInterval(&cfg, resp.Headers)

	sessionExpires, sessionRole := negotiatedInboundSessionState(req.Headers, resp.Headers)
	imsCfg.SessionExpires = sessionExpires
	if sessionRole == "local" {
		imsCfg.SessionRefresher = "uac"
	} else if sessionRole == "ims" {
		imsCfg.SessionRefresher = "uas"
	}
	var sessionDeadline time.Time
	if sessionExpires > 0 {
		sessionDeadline = time.Now().Add(sessionExpirationTimeout(sessionExpires))
	}

	a.storeInboundDialog(callID, imsInboundDialogState{
		clientCfg:           cfg,
		imsCfg:              imsCfg,
		invite:              cloneSIPRequestMessage(invite),
		inviteCSeq:          cfg.CSeq,
		relay:               relay,
		srtpNegotiation:     srtpNegotiation,
		clientSDPBody:       clientSDPBody,
		awaitingIMSAckOffer: awaitingIMSAckOffer,
		lastIMSRemoteCSeq:   initialIMSRemoteCSeq,
		sessionExpires:      sessionExpires,
		sessionRole:         sessionRole,
		sessionDeadline:     sessionDeadline,
	})
	a.scheduleInboundSessionRefresh(callID)
	closeRelayOnError = false
	a.emitDialogEvent(ctx, callID, calleeURI, DialogStateEstablished, callerURI, calleeURI, inboundStatusCode(resp.StatusCode, 200), firstVoiceNonEmpty(resp.Reason, "OK"))
	return InboundCallResult{
		Accepted:   true,
		StatusCode: inboundStatusCode(resp.StatusCode, 200),
		Reason:     firstVoiceNonEmpty(resp.Reason, "OK"),
		LocalTag:   dialogLocalTag,
		LocalSDP:   localSDP,
		RawSDP:     answerBody,
		Headers:    firstValueSIPHeaders(resp.Headers),

		sdpFromProvisional: sdpFromProvisional,
	}, nil
}

func (a *IMSInboundAgent) storeInFlightInboundDialog(callID string, clientCfg, imsCfg voiceclient.DialogRequestConfig, invite voiceclient.SIPRequestMessage, relay *RTPRelaySession, srtpNegotiation *inboundSDESRelayNegotiation, lastIMSRemoteCSeq int) {
	if a == nil || strings.TrimSpace(callID) == "" {
		return
	}
	callID = strings.TrimSpace(callID)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dialogs == nil {
		a.dialogs = make(map[string]imsInboundDialogState)
	}
	prev, hadPrev := a.dialogs[callID]
	state := imsInboundDialogState{
		clientCfg:         cloneDialogRequestConfig(clientCfg),
		imsCfg:            cloneDialogRequestConfig(imsCfg),
		invite:            cloneSIPRequestMessage(invite),
		inviteCSeq:        clientCfg.CSeq,
		relay:             relay,
		srtpNegotiation:   srtpNegotiation,
		early:             true,
		inviteInFlight:    true,
		lastIMSRemoteCSeq: lastIMSRemoteCSeq,
	}
	if hadPrev {
		state.cancelRequested = prev.cancelRequested
		state.canceled = prev.canceled
		state.pendingCancel = cloneDialogInfo(prev.pendingCancel)
	}
	a.dialogs[callID] = state
}

func (a *IMSInboundAgent) isInboundCancelRequested(callID string) bool {
	if a == nil || strings.TrimSpace(callID) == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	state, ok := a.dialogs[strings.TrimSpace(callID)]
	return ok && (state.cancelRequested || state.canceled)
}

func (a *IMSInboundAgent) handleInboundReinvite(ctx context.Context, req InboundCallRequest) (InboundCallResult, error) {
	callID := strings.TrimSpace(req.CallID)
	hasOffer := inboundCallRequestHasOffer(req)
	state, clientCSeq, decision, ok := a.beginInboundDialogOfferWithHeaders(callID, "INVITE", req.CSeq, req.Headers, hasOffer)
	if !ok {
		return InboundCallResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	localTag := firstVoiceNonEmpty(state.imsCfg.LocalTag, a.DefaultLocalTag())
	if decision.statusCode > 0 {
		return InboundCallResult{Accepted: false, StatusCode: decision.statusCode, Reason: decision.reason, LocalTag: localTag}, nil
	}
	if decision.trackPendingOffer {
		serial := state.pendingOffer.serial
		defer a.releaseInboundPendingOffer(callID, serial)
	}
	cfg := state.clientCfg
	cfg.CSeq = clientCSeq
	applyInboundSessionIntervalHeaders(&cfg, req.Headers)
	body := append([]byte(nil), req.RawSDP...)
	var imsOfferBody []byte
	var srtpNegotiation *inboundSDESRelayNegotiation
	if hasOffer && state.relay != nil {
		remoteSDP, offerBody, err := inboundOfferSDP(req)
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid IMS re-INVITE SDP", LocalTag: localTag}, err
		}
		if err := state.relay.SetIMSRemote(remoteSDP); err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "RTP relay IMS re-INVITE failed", LocalTag: localTag}, err
		}
		imsOfferBody = append([]byte(nil), offerBody...)
		body = RewriteSDPMediaEndpoint(offerBody, state.relay.ClientEndpoint())
		negotiation, err := a.prepareInboundMidDialogSDES(imsOfferBody, state)
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "RTP relay SRTP re-INVITE negotiation failed", LocalTag: localTag}, err
		}
		if negotiation != nil {
			srtpNegotiation = negotiation
			body = srtpNegotiation.RewriteClientOffer(body)
		}
	} else if hasOffer {
		_, offerBody, err := inboundOfferSDP(req)
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid IMS re-INVITE SDP", LocalTag: localTag}, err
		}
		imsOfferBody = append([]byte(nil), offerBody...)
		body = offerBody
	}
	var invite voiceclient.SIPRequestMessage
	var resp voiceclient.SIPResponse
	var err error
	retriedSessionInterval := false
	redirectRetries := 0
	var provisionalAnswer InboundCallResult
	for {
		invite, err = voiceclient.BuildInviteRequest(cfg, body)
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 500, Reason: "build client re-INVITE failed", LocalTag: localTag}, err
		}
		ensureInboundClientInviteVia(&invite, cfg)
		a.updateInboundDialogClientAttempt(callID, cfg, srtpNegotiation)
		provisionalAnswer = InboundCallResult{}
		resp, err = a.roundTripClientInvite(ctx, invite, a.inboundProvisionalHandler(ctx, callID, localTag, imsOfferBody, state.relay, srtpNegotiation, func(result InboundCallResult) error {
			if len(result.RawSDP) > 0 {
				provisionalAnswer = cloneInboundCallResult(result)
			}
			if req.onProvisional != nil {
				return req.onProvisional(result)
			}
			return nil
		}))
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "client re-INVITE failed", LocalTag: localTag}, err
		}
		if resp.StatusCode == 422 && !retriedSessionInterval {
			if retryCfg, ok := retryDialogConfigForMinSE(cfg, invite.Headers, resp.Headers); ok {
				if err := a.ackRejectedClientInvite(ctx, cfg, invite, resp); err != nil {
					return InboundCallResult{Accepted: false, StatusCode: 500, Reason: "client re-INVITE session interval ACK failed", LocalTag: localTag}, err
				}
				retryCfg.CSeq = a.allocateInboundClientCSeq(callID)
				cfg = retryCfg
				retriedSessionInterval = true
				continue
			}
		}
		if redirectRetries < maxIMSInviteRedirects {
			if retryCfg, ok := retryDialogConfigForRedirect(cfg, resp, 0); ok {
				if err := a.ackRejectedClientInvite(ctx, cfg, invite, resp); err != nil {
					return InboundCallResult{Accepted: false, StatusCode: 500, Reason: "client re-INVITE redirect ACK failed", LocalTag: localTag}, err
				}
				retryCfg.CSeq = a.allocateInboundClientCSeq(callID)
				cfg = retryCfg
				redirectRetries++
				continue
			}
		}
		break
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode >= 300 {
			if err := a.ackRejectedClientInvite(ctx, cfg, invite, resp); err != nil {
				return InboundCallResult{Accepted: false, StatusCode: 500, Reason: "client re-INVITE rejected ACK failed", LocalTag: localTag}, err
			}
		}
		return InboundCallResult{Accepted: false, StatusCode: inboundStatusCode(resp.StatusCode, 488), Reason: firstVoiceNonEmpty(resp.Reason, "re-INVITE rejected"), LocalTag: localTag, Headers: firstValueSIPHeaders(resp.Headers)}, nil
	}
	result := InboundCallResult{
		Accepted:   true,
		StatusCode: inboundStatusCode(resp.StatusCode, 200),
		Reason:     firstVoiceNonEmpty(resp.Reason, "OK"),
		LocalTag:   localTag,
		RawSDP:     append([]byte(nil), resp.Body...),
		Headers:    firstValueSIPHeaders(resp.Headers),
	}
	var newClientSDP []byte
	awaitingAckOffer := !hasOffer && len(resp.Body) > 0
	if len(resp.Body) > 0 {
		localSDP, err := ParseSDP(resp.Body)
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid client re-INVITE SDP answer", LocalTag: localTag}, err
		}
		newClientSDP = append([]byte(nil), resp.Body...)
		if state.relay != nil {
			if err := state.relay.SetClientRemote(localSDP); err != nil {
				return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "RTP relay client re-INVITE failed", LocalTag: localTag}, err
			}
			precondBody := RewriteSDPPreconditionsForAnswer(imsOfferBody, resp.Body)
			if srtpNegotiation != nil && hasOffer {
				result.RawSDP, localSDP, err = srtpNegotiation.RewriteIMSAnswer(state.relay, precondBody, localSDP)
				if err != nil {
					return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid RTP relay SRTP re-INVITE SDP answer", LocalTag: localTag}, err
				}
			} else if state.srtpNegotiation != nil && !hasOffer {
				rewritten := RewriteSDPMediaEndpoint(precondBody, state.relay.IMSEndpoint())
				if srtpOffer, srtpErr := state.srtpNegotiation.RewriteIMSMidDialogOfferFromClient(state.relay, rewritten); srtpErr == nil {
					rewritten = srtpOffer
				}
				result.RawSDP = rewritten
				localSDP, err = ParseSDP(result.RawSDP)
				if err != nil {
					return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid RTP relay late-offer re-INVITE SDP", LocalTag: localTag}, err
				}
			} else {
				result.RawSDP = RewriteSDPMediaEndpoint(precondBody, state.relay.IMSEndpoint())
				localSDP, err = ParseSDP(result.RawSDP)
				if err != nil {
					return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid RTP relay re-INVITE SDP answer", LocalTag: localTag}, err
				}
			}
		} else if len(imsOfferBody) > 0 {
			result.RawSDP = RewriteSDPPreconditionsForAnswer(imsOfferBody, result.RawSDP)
		}
		result.LocalSDP = localSDP
	} else if len(provisionalAnswer.RawSDP) > 0 {
		result.RawSDP = append([]byte(nil), provisionalAnswer.RawSDP...)
		result.LocalSDP = provisionalAnswer.LocalSDP
		result.sdpFromProvisional = true
	}
	if contact := sipHeaderURI(firstVoiceHeader(resp.Headers, "Contact")); contact != "" {
		cfg.RemoteTargetURI = contact
	}
	applyInboundNegotiatedSessionInterval(&cfg, resp.Headers)
	imsContact := sipHeaderURI(firstVoiceHeader(req.Headers, "Contact"))
	sessionExpires, sessionRole := negotiatedInboundSessionState(req.Headers, resp.Headers)

	a.mu.Lock()
	if latest, exists := a.dialogs[callID]; exists {
		cfg.CSeq = maxInboundCSeq(latest.clientCfg.CSeq, cfg.CSeq)
		latest.clientCfg = cfg
		latest.inviteCSeq = cfg.CSeq
		latest.awaitingIMSAckOffer = awaitingAckOffer
		if len(newClientSDP) > 0 {
			latest.clientSDPBody = newClientSDP
		}
		if srtpNegotiation != nil {
			latest.srtpNegotiation = srtpNegotiation
		}
		if imsContact != "" {
			latest.imsCfg.RemoteTargetURI = imsContact
		}
		if sessionExpires > 0 {
			latest.sessionExpires = sessionExpires
			latest.sessionRole = sessionRole
			latest.sessionDeadline = time.Now().Add(sessionExpirationTimeout(sessionExpires))
		}
		a.dialogs[callID] = latest
	}
	a.mu.Unlock()
	a.scheduleInboundSessionRefresh(callID)
	return result, nil
}

func (a *IMSInboundAgent) AckInboundCall(ctx context.Context, info DialogInfo) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentClientTransport() == nil {
		return ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(info.CallID)
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return nil
	}
	cfg := cloneDialogRequestConfig(state.clientCfg)
	if state.inviteCSeq > 0 {
		cfg.CSeq = state.inviteCSeq
	}
	awaitingOffer := state.awaitingIMSAckOffer
	relay := state.relay
	srtpNeg := state.srtpNegotiation
	state.awaitingIMSAckOffer = false
	a.dialogs[callID] = state
	a.mu.Unlock()

	var ackBody []byte
	if len(info.Body) > 0 {
		ackBody = append([]byte(nil), info.Body...)
		if awaitingOffer && relay != nil {
			imsSDP, err := ParseSDP(ackBody)
			if err != nil {
				return err
			}
			if err := relay.SetIMSRemote(imsSDP); err != nil {
				return err
			}
			if srtpNeg != nil {
				rewritten, _, rwErr := srtpNeg.RewriteClientMidDialogAnswerFromIMS(relay, ackBody, imsSDP)
				if rwErr != nil {
					return rwErr
				}
				ackBody = rewritten
			} else {
				ackBody = RewriteSDPMediaEndpoint(ackBody, relay.ClientEndpoint())
			}
		}
	}
	ack, err := buildDialogAckWithOptionalSDP(cfg, ackBody)
	if err != nil {
		return err
	}
	return a.writeClientRequest(ctx, ack)
}

func (a *IMSInboundAgent) ackRejectedClientInvite(ctx context.Context, cfg voiceclient.DialogRequestConfig, invite voiceclient.SIPRequestMessage, resp voiceclient.SIPResponse) error {
	if strings.TrimSpace(invite.URI) != "" && len(invite.Headers) > 0 {
		if ack, err := voiceclient.BuildNon2xxInviteAck(invite, resp); err == nil {
			return a.writeClientRequest(ctx, ack)
		}
	}
	ackCfg := cfg
	ackCfg.RemoteTag = firstVoiceNonEmpty(sipHeaderTag(firstVoiceHeader(resp.Headers, "To")), cfg.RemoteTag)
	ack, err := voiceclient.BuildAckRequest(ackCfg)
	if err != nil {
		return err
	}
	copyDialogHeader(ack.Headers, invite.Headers, "Via")
	return a.writeClientRequest(ctx, ack)
}

func ensureInboundClientInviteVia(invite *voiceclient.SIPRequestMessage, cfg voiceclient.DialogRequestConfig) {
	voiceclient.EnsureDialogRequestVia(invite, cfg)
}

func cloneSIPRequestMessage(msg voiceclient.SIPRequestMessage) voiceclient.SIPRequestMessage {
	out := msg
	out.Body = append([]byte(nil), msg.Body...)
	if msg.Headers != nil {
		out.Headers = make(map[string]string, len(msg.Headers))
		for key, value := range msg.Headers {
			out.Headers[key] = value
		}
	}
	return out
}

func cloneInboundCallResult(result InboundCallResult) InboundCallResult {
	out := result
	out.RawSDP = append([]byte(nil), result.RawSDP...)
	if result.Headers != nil {
		out.Headers = make(map[string]string, len(result.Headers))
		for key, value := range result.Headers {
			out.Headers[key] = value
		}
	}
	return out
}

func (a *IMSInboundAgent) prepareInboundMidDialogSDES(imsOfferBody []byte, state imsInboundDialogState) (*inboundSDESRelayNegotiation, error) {
	if state.srtpNegotiation != nil {
		return state.srtpNegotiation.PrepareIMSMidDialogOffer(imsOfferBody)
	}
	return a.newInboundSDESRelayNegotiation(imsOfferBody, state)
}

func (a *IMSInboundAgent) newInboundSDESRelayNegotiation(body []byte, state imsInboundDialogState) (*inboundSDESRelayNegotiation, error) {
	cfg, ok := a.inboundSDESRelayConfig(state)
	if !ok {
		return nil, nil
	}
	return newInboundSDESRelayNegotiation(body, cfg)
}

func (a *IMSInboundAgent) inboundSDESRelayConfig(state imsInboundDialogState) (RTPRelaySRTPConfig, bool) {
	if a != nil {
		a.mu.Lock()
		mediaRelay := a.MediaRelay
		a.mu.Unlock()
		if mediaRelay != nil && mediaRelay.SRTP != nil {
			return *mediaRelay.SRTP, true
		}
	}
	if state.srtpNegotiation != nil {
		return state.srtpNegotiation.cfg, true
	}
	return RTPRelaySRTPConfig{}, false
}

func (a *IMSInboundAgent) inboundProvisionalHandler(ctx context.Context, callID string, localTag string, imsOfferBody []byte, relay *RTPRelaySession, srtpNegotiation *inboundSDESRelayNegotiation, onProvisional func(InboundCallResult) error) func(voiceclient.SIPResponse) error {
	return func(resp voiceclient.SIPResponse) error {
		if resp.StatusCode < 100 || resp.StatusCode >= 200 {
			return nil
		}
		var sendDeferredCancel bool
		var cancelCfg voiceclient.DialogRequestConfig
		var cancelInv voiceclient.SIPRequestMessage
		var cancelInfo DialogInfo
		a.mu.Lock()
		if st, exists := a.dialogs[callID]; exists {
			st.provisionalSeen = true
			if resp.StatusCode > 100 {
				if tag := sipHeaderTag(firstVoiceHeader(resp.Headers, "To")); tag != "" {
					st.clientCfg.RemoteTag = tag
				}
				if contact := sipHeaderURI(firstVoiceHeader(resp.Headers, "Contact")); contact != "" {
					st.clientCfg.RemoteTargetURI = contact
				}
				if routeSet := recordRouteSet(resp.Headers); len(routeSet) > 0 {
					st.clientCfg.RouteSet = routeSet
				}
			}
			if st.cancelRequested && !st.cancelSent {
				st.cancelSent = true
				sendDeferredCancel = true
				cancelCfg = cloneDialogRequestConfig(st.clientCfg)
				cancelInv = cloneSIPRequestMessage(st.invite)
				cancelInfo = cloneDialogInfo(st.pendingCancel)
			}
			a.dialogs[callID] = st
		}
		a.mu.Unlock()
		if sendDeferredCancel {
			_, _ = a.sendInboundClientCancelWire(ctx, callID, cancelCfg, cancelInv, cancelInfo, true)
		}
		if resp.StatusCode == 100 {
			return nil
		}
		result := InboundCallResult{
			Accepted:   false,
			StatusCode: inboundStatusCode(resp.StatusCode, 180),
			Reason:     firstVoiceNonEmpty(resp.Reason, "Ringing"),
			LocalTag:   localTag,
			RawSDP:     append([]byte(nil), resp.Body...),
			Headers:    firstValueSIPHeaders(resp.Headers),
		}
		if len(resp.Body) > 0 {
			localSDP, err := ParseSDP(resp.Body)
			if err != nil {
				return fmt.Errorf("invalid client provisional SDP answer: %w", err)
			}
			precondBody := RewriteSDPPreconditionsForAnswer(imsOfferBody, resp.Body)
			if relay != nil {
				if err := relay.SetClientRemote(localSDP); err != nil {
					return fmt.Errorf("RTP relay client provisional setup failed: %w", err)
				}
				if srtpNegotiation != nil {
					result.RawSDP, localSDP, err = srtpNegotiation.RewriteIMSAnswer(relay, precondBody, localSDP)
					if err != nil {
						return fmt.Errorf("invalid RTP relay SRTP provisional SDP answer: %w", err)
					}
				} else {
					result.RawSDP = RewriteSDPMediaEndpoint(precondBody, relay.IMSEndpoint())
					localSDP, err = ParseSDP(result.RawSDP)
					if err != nil {
						return fmt.Errorf("invalid RTP relay provisional SDP answer: %w", err)
					}
				}
			} else {
				result.RawSDP = precondBody
			}
			result.LocalSDP = localSDP
		}
		if onProvisional == nil {
			return nil
		}
		return onProvisional(result)
	}
}

func applyInboundSessionIntervalHeaders(cfg *voiceclient.DialogRequestConfig, headers map[string][]string) {
	if cfg == nil {
		return
	}
	cfg.SessionExpires = 0
	cfg.SessionRefresher = ""
	cfg.MinSE = 0
	if interval := sessionExpiresResponseHeader(headers); interval.Expires > 0 {
		cfg.SessionExpires = interval.Expires
		cfg.SessionRefresher = interval.Refresher
	}
	if minSE := minSEHeader(headers); minSE > 0 {
		cfg.MinSE = minSE
	}
}

func applyInboundNegotiatedSessionInterval(cfg *voiceclient.DialogRequestConfig, headers map[string][]string) {
	if cfg == nil {
		return
	}
	applyNegotiatedSessionInterval(cfg, headers)
	if minSE := minSEHeader(headers); minSE > 0 {
		cfg.MinSE = minSE
	}
}

func negotiatedInboundSessionState(reqHeaders, respHeaders map[string][]string) (int, string) {
	respInt := sessionExpiresResponseHeader(respHeaders)
	reqInt := sessionExpiresResponseHeader(reqHeaders)
	if respInt.Expires <= 0 {
		return 0, ""
	}
	refresher := normalizeSessionRefresher(respInt.Refresher)
	if refresher == "" {
		refresher = firstVoiceNonEmpty(normalizeSessionRefresher(reqInt.Refresher), "uac")
	}
	if refresher == "uas" {
		return respInt.Expires, "local"
	}
	return respInt.Expires, "ims"
}

func inboundIMSDialogTagsMatch(imsCfg voiceclient.DialogRequestConfig, headers map[string][]string) bool {
	localTag := strings.TrimSpace(imsCfg.LocalTag)
	remoteTag := strings.TrimSpace(imsCfg.RemoteTag)
	if localTag == "" && remoteTag == "" {
		return true
	}
	from := firstVoiceHeader(headers, "From")
	to := firstVoiceHeader(headers, "To")
	if from == "" && to == "" {
		return true
	}
	if localTag != "" && sipHeaderTag(to) != localTag {
		return false
	}
	if remoteTag != "" && sipHeaderTag(from) != remoteTag {
		return false
	}
	return true
}

func inboundIMSDialogTagsMatchStringMap(imsCfg voiceclient.DialogRequestConfig, headers map[string]string) bool {
	if len(headers) == 0 {
		return true
	}
	return inboundIMSDialogTagsMatch(imsCfg, stringToSliceHeaders(headers))
}

func (a *IMSInboundAgent) validateInboundIMSRemoteCSeqLocked(callID string, state *imsInboundDialogState, cseq int) bool {
	if cseq <= 0 {
		return true
	}
	if state.lastIMSRemoteCSeq > 0 && cseq <= state.lastIMSRemoteCSeq {
		return false
	}
	state.lastIMSRemoteCSeq = cseq
	a.dialogs[callID] = *state
	return true
}

func (a *IMSInboundAgent) reserveInboundClientLeg(callID string, imsCSeq int, headers map[string][]string) (imsInboundDialogState, int, int, string, bool) {
	callID = strings.TrimSpace(callID)
	if a == nil || callID == "" {
		return imsInboundDialogState{}, 0, 0, "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	state, ok := a.dialogs[callID]
	if !ok {
		return imsInboundDialogState{}, 0, 0, "", false
	}
	if !inboundIMSDialogTagsMatch(state.imsCfg, headers) {
		return cloneInboundDialogStateSnapshot(state), 0, 481, "Call/Transaction Does Not Exist", true
	}
	if !a.validateInboundIMSRemoteCSeqLocked(callID, &state, imsCSeq) {
		return cloneInboundDialogStateSnapshot(state), 0, 500, "CSeq Out of Order", true
	}
	allocCSeq := maxInboundCSeq(nextInboundClientCSeq(state.clientCfg.CSeq), inboundCSeq(imsCSeq))
	state.clientCfg.CSeq = allocCSeq
	a.dialogs[callID] = state
	return cloneInboundDialogStateSnapshot(state), allocCSeq, 0, "", true
}

func (a *IMSInboundAgent) allocateInboundClientCSeq(callID string) int {
	callID = strings.TrimSpace(callID)
	a.mu.Lock()
	defer a.mu.Unlock()
	state, ok := a.dialogs[callID]
	if !ok {
		return 2
	}
	next := nextInboundClientCSeq(state.clientCfg.CSeq)
	state.clientCfg.CSeq = next
	a.dialogs[callID] = state
	return next
}

func (a *IMSInboundAgent) updateInboundDialogClientAttempt(callID string, cfg voiceclient.DialogRequestConfig, srtpNeg *inboundSDESRelayNegotiation) {
	callID = strings.TrimSpace(callID)
	a.mu.Lock()
	if latest, ok := a.dialogs[callID]; ok {
		latest.clientCfg.CSeq = maxInboundCSeq(latest.clientCfg.CSeq, cfg.CSeq)
		latest.clientCfg.RemoteTargetURI = cfg.RemoteTargetURI
		if srtpNeg != nil {
			latest.srtpNegotiation = srtpNeg
		}
		a.dialogs[callID] = latest
	}
	a.mu.Unlock()
}

func (a *IMSInboundAgent) updateInboundDialogClientContact(callID string, headers map[string][]string) {
	contact := sipHeaderURI(firstVoiceHeader(headers, "Contact"))
	if contact == "" {
		return
	}
	callID = strings.TrimSpace(callID)
	a.mu.Lock()
	if latest, ok := a.dialogs[callID]; ok {
		latest.clientCfg.RemoteTargetURI = contact
		a.dialogs[callID] = latest
	}
	a.mu.Unlock()
}

func (a *IMSInboundAgent) HandleInboundUpdate(ctx context.Context, req InboundDialogRequest) (InboundCallResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentClientTransport() == nil {
		return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "client voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return InboundCallResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	hasOffer := inboundDialogRequestHasOffer(req)
	state, clientCSeq, decision, ok := a.beginInboundDialogOfferWithHeaders(callID, "UPDATE", req.CSeq, req.Headers, hasOffer)
	if !ok {
		return InboundCallResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	if decision.statusCode > 0 {
		return InboundCallResult{Accepted: false, StatusCode: decision.statusCode, Reason: decision.reason}, nil
	}
	if decision.trackPendingOffer {
		serial := state.pendingOffer.serial
		defer a.releaseInboundPendingOffer(callID, serial)
	}
	cfg := state.clientCfg
	cfg.CSeq = clientCSeq
	applyInboundSessionIntervalHeaders(&cfg, req.Headers)
	body := inboundDialogBody(req)
	var imsOfferBody []byte
	var srtpNegotiation *inboundSDESRelayNegotiation
	if hasOffer && state.relay != nil {
		remoteSDP, offerBody, err := inboundDialogSDP(req)
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid IMS UPDATE SDP"}, err
		}
		if err := state.relay.SetIMSRemote(remoteSDP); err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "RTP relay IMS update failed"}, err
		}
		imsOfferBody = append([]byte(nil), offerBody...)
		body = RewriteSDPMediaEndpoint(offerBody, state.relay.ClientEndpoint())
		negotiation, err := a.prepareInboundMidDialogSDES(imsOfferBody, state)
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "RTP relay SRTP UPDATE negotiation failed"}, err
		}
		if negotiation != nil {
			srtpNegotiation = negotiation
			body = srtpNegotiation.RewriteClientOffer(body)
		}
	} else if hasOffer {
		_, offerBody, err := inboundDialogSDP(req)
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid IMS UPDATE SDP"}, err
		}
		imsOfferBody = append([]byte(nil), offerBody...)
		body = offerBody
	}
	var update voiceclient.SIPRequestMessage
	var resp voiceclient.SIPResponse
	var err error
	retriedSessionInterval := false
	redirectRetries := 0
	for {
		update, err = voiceclient.BuildUpdateRequest(cfg, body)
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 500, Reason: "build client UPDATE failed"}, err
		}
		a.updateInboundDialogClientAttempt(callID, cfg, srtpNegotiation)
		resp, err = a.roundTripClientRequest(ctx, update)
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "client UPDATE failed"}, err
		}
		if resp.StatusCode == 422 && !retriedSessionInterval {
			if retryCfg, ok := retryDialogConfigForMinSE(cfg, update.Headers, resp.Headers); ok {
				retryCfg.CSeq = a.allocateInboundClientCSeq(callID)
				cfg = retryCfg
				retriedSessionInterval = true
				continue
			}
		}
		if redirectRetries < maxIMSInviteRedirects {
			if retryCfg, ok := retryDialogConfigForRedirect(cfg, resp, 0); ok {
				retryCfg.CSeq = a.allocateInboundClientCSeq(callID)
				cfg = retryCfg
				redirectRetries++
				continue
			}
		}
		break
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return InboundCallResult{Accepted: false, StatusCode: inboundStatusCode(resp.StatusCode, 488), Reason: firstVoiceNonEmpty(resp.Reason, "UPDATE rejected"), Headers: firstValueSIPHeaders(resp.Headers)}, nil
	}
	result := InboundCallResult{Accepted: true, StatusCode: inboundStatusCode(resp.StatusCode, 200), Reason: firstVoiceNonEmpty(resp.Reason, "OK"), RawSDP: append([]byte(nil), resp.Body...), Headers: firstValueSIPHeaders(resp.Headers)}
	var newClientSDP []byte
	if len(resp.Body) > 0 {
		localSDP, err := ParseSDP(resp.Body)
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid client UPDATE SDP answer"}, err
		}
		newClientSDP = append([]byte(nil), resp.Body...)
		precondBody := RewriteSDPPreconditionsForAnswer(imsOfferBody, resp.Body)
		if state.relay != nil {
			if err := state.relay.SetClientRemote(localSDP); err != nil {
				return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "RTP relay client update failed"}, err
			}
			if srtpNegotiation != nil {
				result.RawSDP, localSDP, err = srtpNegotiation.RewriteIMSAnswer(state.relay, precondBody, localSDP)
				if err != nil {
					return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid RTP relay SRTP UPDATE SDP answer"}, err
				}
			} else {
				result.RawSDP = RewriteSDPMediaEndpoint(precondBody, state.relay.IMSEndpoint())
				localSDP, err = ParseSDP(result.RawSDP)
				if err != nil {
					return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid RTP relay UPDATE SDP answer"}, err
				}
			}
		} else if len(imsOfferBody) > 0 {
			result.RawSDP = precondBody
		}
		result.LocalSDP = localSDP
	}
	if contact := sipHeaderURI(firstVoiceHeader(resp.Headers, "Contact")); contact != "" {
		cfg.RemoteTargetURI = contact
	}
	applyInboundNegotiatedSessionInterval(&cfg, resp.Headers)
	imsContact := sipHeaderURI(firstVoiceHeader(req.Headers, "Contact"))
	sessionExpires, sessionRole := negotiatedInboundSessionState(req.Headers, resp.Headers)

	a.mu.Lock()
	if latest, exists := a.dialogs[callID]; exists {
		cfg.CSeq = maxInboundCSeq(latest.clientCfg.CSeq, cfg.CSeq)
		latest.clientCfg = cfg
		if len(newClientSDP) > 0 {
			latest.clientSDPBody = newClientSDP
		}
		if srtpNegotiation != nil {
			latest.srtpNegotiation = srtpNegotiation
		}
		if imsContact != "" {
			latest.imsCfg.RemoteTargetURI = imsContact
		}
		if sessionExpires > 0 {
			latest.sessionExpires = sessionExpires
			latest.sessionRole = sessionRole
			latest.sessionDeadline = time.Now().Add(sessionExpirationTimeout(sessionExpires))
		}
		a.dialogs[callID] = latest
	}
	a.mu.Unlock()
	a.scheduleInboundSessionRefresh(callID)
	return result, nil
}

func (a *IMSInboundAgent) HandleInboundPrack(ctx context.Context, req InboundDialogRequest) (InboundCallResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentClientTransport() == nil {
		return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "client voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return InboundCallResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	state, clientCSeq, rejectCode, rejectReason, ok := a.reserveInboundClientLeg(callID, req.CSeq, req.Headers)
	if !ok {
		return InboundCallResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	if rejectCode > 0 {
		return InboundCallResult{Accepted: false, StatusCode: rejectCode, Reason: rejectReason}, nil
	}
	cfg := state.clientCfg
	cfg.CSeq = clientCSeq
	rack := firstVoiceNonEmpty(req.RAck, firstVoiceHeader(req.Headers, "RAck"))
	body := inboundDialogBody(req)
	contentType := firstVoiceNonEmpty(req.ContentType, firstVoiceHeader(req.Headers, "Content-Type"))
	var imsOfferBody []byte
	var srtpNegotiation *inboundSDESRelayNegotiation
	if len(body) > 0 {
		remoteSDP, offerBody, err := inboundDialogSDP(req)
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid IMS PRACK SDP"}, err
		}
		imsOfferBody = append([]byte(nil), offerBody...)
		body = offerBody
		if state.relay != nil {
			if err := state.relay.SetIMSRemote(remoteSDP); err != nil {
				return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "RTP relay IMS PRACK failed"}, err
			}
			body = RewriteSDPMediaEndpoint(offerBody, state.relay.ClientEndpoint())
			negotiation, err := a.prepareInboundMidDialogSDES(imsOfferBody, state)
			if err != nil {
				return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "RTP relay SRTP PRACK negotiation failed"}, err
			}
			if negotiation != nil {
				srtpNegotiation = negotiation
				body = srtpNegotiation.RewriteClientOffer(body)
			}
		}
	}
	var resp voiceclient.SIPResponse
	var prack voiceclient.SIPRequestMessage
	var err error
	redirectRetries := 0
	for {
		prack, err = voiceclient.BuildPrackRequestWithBody(cfg, rack, contentType, body)
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 500, Reason: "build client PRACK failed"}, err
		}
		a.updateInboundDialogClientAttempt(callID, cfg, srtpNegotiation)
		resp, err = a.roundTripClientRequest(ctx, prack)
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "client PRACK failed"}, err
		}
		if redirectRetries < maxIMSInviteRedirects {
			if retryCfg, ok := retryDialogConfigForRedirect(cfg, resp, 0); ok {
				retryCfg.CSeq = a.allocateInboundClientCSeq(callID)
				cfg = retryCfg
				redirectRetries++
				continue
			}
		}
		break
	}
	a.updateInboundDialogClientContact(callID, resp.Headers)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return InboundCallResult{Accepted: false, StatusCode: inboundStatusCode(resp.StatusCode, 500), Reason: firstVoiceNonEmpty(resp.Reason, "PRACK rejected")}, nil
	}
	if len(resp.Body) == 0 && srtpNegotiation != nil {
		return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "missing client PRACK SDP answer"}, ErrSDPSecurityNegotiation
	}
	result := InboundCallResult{Accepted: true, StatusCode: inboundStatusCode(resp.StatusCode, 200), Reason: firstVoiceNonEmpty(resp.Reason, "OK"), RawSDP: append([]byte(nil), resp.Body...), Headers: firstValueSIPHeaders(resp.Headers)}
	if len(resp.Body) > 0 && state.relay != nil {
		localSDP, err := ParseSDP(resp.Body)
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid client PRACK SDP answer"}, err
		}
		if err := state.relay.SetClientRemote(localSDP); err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "RTP relay client PRACK failed"}, err
		}
		precondBody := RewriteSDPPreconditionsForAnswer(imsOfferBody, resp.Body)
		if srtpNegotiation != nil {
			result.RawSDP, localSDP, err = srtpNegotiation.RewriteIMSAnswer(state.relay, precondBody, localSDP)
			if err != nil {
				return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid RTP relay SRTP PRACK SDP answer"}, err
			}
		} else if _, ok := a.inboundSDESRelayConfig(state); ok {
			return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "RTP relay SRTP PRACK negotiation unavailable"}, ErrSDPSecurityNegotiation
		} else {
			result.RawSDP = RewriteSDPMediaEndpoint(precondBody, state.relay.IMSEndpoint())
			localSDP, err = ParseSDP(result.RawSDP)
			if err != nil {
				return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "invalid RTP relay PRACK SDP answer"}, err
			}
		}
		result.LocalSDP = localSDP
	} else if len(imsOfferBody) > 0 && len(result.RawSDP) > 0 {
		result.RawSDP = RewriteSDPPreconditionsForAnswer(imsOfferBody, result.RawSDP)
	}
	if srtpNegotiation != nil {
		a.updateInboundDialogClientAttempt(callID, cfg, srtpNegotiation)
	}
	return result, nil
}

func (a *IMSInboundAgent) HandleInboundRefer(ctx context.Context, req InboundDialogRequest) (InboundCallResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentClientTransport() == nil {
		return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "client voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return InboundCallResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	referTo := firstVoiceNonEmpty(req.ReferTo, firstVoiceHeader(req.Headers, "Refer-To"))
	if strings.TrimSpace(referTo) == "" {
		return InboundCallResult{Accepted: false, StatusCode: 400, Reason: "Refer-To empty"}, errors.New("Refer-To is empty")
	}
	referSub, ok := normalizeReferSub(firstVoiceNonEmpty(req.ReferSub, firstVoiceHeader(req.Headers, "Refer-Sub")))
	if !ok {
		return InboundCallResult{Accepted: false, StatusCode: 400, Reason: "Refer-Sub invalid"}, errors.New("Refer-Sub must be true or false")
	}
	effectiveReferSub := firstVoiceNonEmpty(referSub, voiceclient.DefaultReferSub)
	state, clientCSeq, rejectCode, rejectReason, ok := a.reserveInboundClientLeg(callID, req.CSeq, req.Headers)
	if !ok {
		return InboundCallResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	if rejectCode > 0 {
		return InboundCallResult{Accepted: false, StatusCode: rejectCode, Reason: rejectReason}, nil
	}
	cfg := state.clientCfg
	cfg.CSeq = clientCSeq
	var resp voiceclient.SIPResponse
	var refer voiceclient.SIPRequestMessage
	var err error
	redirectRetries := 0
	for {
		refer, err = voiceclient.BuildReferRequestWithOptions(cfg, referTo, voiceclient.ReferRequestOptions{
			ReferredBy: firstVoiceNonEmpty(req.ReferredBy, firstVoiceHeader(req.Headers, "Referred-By")),
			ReferSub:   effectiveReferSub,
		})
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 500, Reason: "build client REFER failed"}, err
		}
		applyIncomingInfoHeaders(refer.Headers, "", req.Headers)
		refer.Headers["Refer-Sub"] = effectiveReferSub
		a.updateInboundDialogClientAttempt(callID, cfg, nil)
		resp, err = a.roundTripClientRequest(ctx, refer)
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "client REFER failed"}, err
		}
		if redirectRetries < maxIMSInviteRedirects {
			if retryCfg, ok := retryDialogConfigForRedirect(cfg, resp, 0); ok {
				retryCfg.CSeq = a.allocateInboundClientCSeq(callID)
				cfg = retryCfg
				redirectRetries++
				continue
			}
		}
		break
	}
	a.updateInboundDialogClientContact(callID, resp.Headers)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return InboundCallResult{Accepted: false, StatusCode: inboundStatusCode(resp.StatusCode, 500), Reason: firstVoiceNonEmpty(resp.Reason, "REFER rejected"), Headers: firstValueSIPHeaders(resp.Headers)}, nil
	}
	return InboundCallResult{Accepted: true, StatusCode: inboundStatusCode(resp.StatusCode, 202), Reason: firstVoiceNonEmpty(resp.Reason, "Accepted"), Headers: firstValueSIPHeaders(resp.Headers)}, nil
}

func (a *IMSInboundAgent) HandleInboundNotify(ctx context.Context, req InboundDialogRequest) (IMSInfoResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentClientTransport() == nil {
		return IMSInfoResult{Handled: true, StatusCode: 503, Reason: "client voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return IMSInfoResult{Handled: true, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	event := firstVoiceNonEmpty(req.Event, firstVoiceHeader(req.Headers, "Event"))
	if strings.TrimSpace(event) == "" {
		return IMSInfoResult{Handled: true, StatusCode: 400, Reason: "Event empty"}, errors.New("Event is empty")
	}
	subscriptionState := firstVoiceNonEmpty(req.SubscriptionState, firstVoiceHeader(req.Headers, "Subscription-State"))
	if strings.TrimSpace(subscriptionState) == "" {
		return IMSInfoResult{Handled: true, StatusCode: 400, Reason: "Subscription-State empty"}, errors.New("Subscription-State is empty")
	}
	state, clientCSeq, rejectCode, rejectReason, ok := a.reserveInboundClientLeg(callID, req.CSeq, req.Headers)
	if !ok {
		return IMSInfoResult{Handled: true, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	if rejectCode > 0 {
		return IMSInfoResult{Handled: true, StatusCode: rejectCode, Reason: rejectReason}, nil
	}
	cfg := state.clientCfg
	cfg.CSeq = clientCSeq
	var resp voiceclient.SIPResponse
	var notify voiceclient.SIPRequestMessage
	var err error
	redirectRetries := 0
	for {
		notify, err = voiceclient.BuildNotifyRequest(cfg, event, subscriptionState, req.ContentType, req.Body)
		if err != nil {
			return IMSInfoResult{Handled: true, StatusCode: 500, Reason: "build client NOTIFY failed"}, err
		}
		applyIncomingInfoHeaders(notify.Headers, "", req.Headers)
		a.updateInboundDialogClientAttempt(callID, cfg, nil)
		resp, err = a.roundTripClientRequest(ctx, notify)
		if err != nil {
			return IMSInfoResult{Handled: true, StatusCode: 503, Reason: "client NOTIFY failed"}, err
		}
		if redirectRetries < maxIMSInviteRedirects {
			if retryCfg, ok := retryDialogConfigForRedirect(cfg, resp, 0); ok {
				retryCfg.CSeq = a.allocateInboundClientCSeq(callID)
				cfg = retryCfg
				redirectRetries++
				continue
			}
		}
		break
	}
	a.updateInboundDialogClientContact(callID, resp.Headers)
	return IMSInfoResult{
		Handled:     true,
		StatusCode:  inboundStatusCode(resp.StatusCode, 500),
		Reason:      firstVoiceNonEmpty(resp.Reason, "OK"),
		ContentType: firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:        append([]byte(nil), resp.Body...),
		Headers:     firstValueSIPHeaders(resp.Headers),
	}, nil
}

func (a *IMSInboundAgent) HandleInboundSubscribe(ctx context.Context, req InboundDialogRequest) (IMSInfoResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentClientTransport() == nil {
		return IMSInfoResult{Handled: true, StatusCode: 503, Reason: "client voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return IMSInfoResult{Handled: true, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	event := firstVoiceNonEmpty(req.Event, firstVoiceHeader(req.Headers, "Event"))
	if strings.TrimSpace(event) == "" {
		return IMSInfoResult{Handled: true, StatusCode: 400, Reason: "Event empty"}, errors.New("Event is empty")
	}
	expires := firstVoiceNonEmpty(req.Expires, firstVoiceHeader(req.Headers, "Expires"))
	state, clientCSeq, rejectCode, rejectReason, ok := a.reserveInboundClientLeg(callID, req.CSeq, req.Headers)
	if !ok {
		return IMSInfoResult{Handled: true, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	if rejectCode > 0 {
		return IMSInfoResult{Handled: true, StatusCode: rejectCode, Reason: rejectReason}, nil
	}
	cfg := state.clientCfg
	cfg.CSeq = clientCSeq
	var resp voiceclient.SIPResponse
	var subscribe voiceclient.SIPRequestMessage
	var err error
	redirectRetries := 0
	retriedMinExpires := false
	for {
		subscribe, err = voiceclient.BuildSubscribeRequest(cfg, event, expires, req.ContentType, req.Body)
		if err != nil {
			return IMSInfoResult{Handled: true, StatusCode: 500, Reason: "build client SUBSCRIBE failed"}, err
		}
		applyIncomingInfoHeaders(subscribe.Headers, "", req.Headers)
		subscribe.Headers["Event"] = event
		if strings.TrimSpace(expires) != "" {
			subscribe.Headers["Expires"] = strings.TrimSpace(expires)
		}
		a.updateInboundDialogClientAttempt(callID, cfg, nil)
		resp, err = a.roundTripClientRequest(ctx, subscribe)
		if err != nil {
			return IMSInfoResult{Handled: true, StatusCode: 503, Reason: "client SUBSCRIBE failed"}, err
		}
		if resp.StatusCode == 423 && !retriedMinExpires {
			if retryCfg, retryExpires, ok := retryDialogConfigForMinExpires(cfg, subscribe.Headers, resp.Headers); ok {
				retryCfg.CSeq = a.allocateInboundClientCSeq(callID)
				cfg = retryCfg
				expires = retryExpires
				retriedMinExpires = true
				continue
			}
		}
		if redirectRetries < maxIMSInviteRedirects {
			if retryCfg, ok := retryDialogConfigForRedirect(cfg, resp, 0); ok {
				retryCfg.CSeq = a.allocateInboundClientCSeq(callID)
				cfg = retryCfg
				redirectRetries++
				continue
			}
		}
		break
	}
	a.updateInboundDialogClientContact(callID, resp.Headers)
	return IMSInfoResult{
		Handled:     true,
		StatusCode:  inboundStatusCode(resp.StatusCode, 500),
		Reason:      firstVoiceNonEmpty(resp.Reason, "OK"),
		ContentType: firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:        append([]byte(nil), resp.Body...),
		Headers:     firstValueSIPHeaders(resp.Headers),
	}, nil
}

func (a *IMSInboundAgent) HandleInboundMessage(ctx context.Context, req IMSMessageRequest) (IMSInfoResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentClientTransport() == nil {
		return IMSInfoResult{Handled: true, StatusCode: 503, Reason: "client voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return IMSInfoResult{Handled: true, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	state, clientCSeq, rejectCode, rejectReason, ok := a.reserveInboundClientLeg(callID, req.CSeq, req.Headers)
	if !ok {
		return IMSInfoResult{Handled: true, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	if rejectCode > 0 {
		return IMSInfoResult{Handled: true, StatusCode: rejectCode, Reason: rejectReason}, nil
	}
	cfg := state.clientCfg
	cfg.CSeq = clientCSeq
	var resp voiceclient.SIPResponse
	var msg voiceclient.SIPRequestMessage
	var err error
	redirectRetries := 0
	for {
		msg, err = voiceclient.BuildDialogMessageRequest(cfg, req.ContentType, req.Body)
		if err != nil {
			return IMSInfoResult{Handled: true, StatusCode: 500, Reason: "build client MESSAGE failed"}, err
		}
		applyIncomingInfoHeaders(msg.Headers, "", req.Headers)
		a.updateInboundDialogClientAttempt(callID, cfg, nil)
		resp, err = a.roundTripClientRequest(ctx, msg)
		if err != nil {
			return IMSInfoResult{Handled: true, StatusCode: 503, Reason: "client MESSAGE failed"}, err
		}
		if redirectRetries < maxIMSInviteRedirects {
			if retryCfg, ok := retryDialogConfigForRedirect(cfg, resp, 0); ok {
				retryCfg.CSeq = a.allocateInboundClientCSeq(callID)
				cfg = retryCfg
				redirectRetries++
				continue
			}
		}
		break
	}
	a.updateInboundDialogClientContact(callID, resp.Headers)
	return IMSInfoResult{
		Handled:     true,
		StatusCode:  inboundStatusCode(resp.StatusCode, 500),
		Reason:      firstVoiceNonEmpty(resp.Reason, "OK"),
		ContentType: firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:        append([]byte(nil), resp.Body...),
		Headers:     firstValueSIPHeaders(resp.Headers),
	}, nil
}

func (a *IMSInboundAgent) HandleInboundInfo(ctx context.Context, req IMSInfoRequest) (IMSInfoResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentClientTransport() == nil {
		return IMSInfoResult{Handled: true, StatusCode: 503, Reason: "client voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return IMSInfoResult{Handled: true, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	state, clientCSeq, rejectCode, rejectReason, ok := a.reserveInboundClientLeg(callID, req.CSeq, req.Headers)
	if !ok {
		return IMSInfoResult{Handled: true, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	if rejectCode > 0 {
		return IMSInfoResult{Handled: true, StatusCode: rejectCode, Reason: rejectReason}, nil
	}
	cfg := state.clientCfg
	cfg.CSeq = clientCSeq
	var resp voiceclient.SIPResponse
	var info voiceclient.SIPRequestMessage
	var err error
	redirectRetries := 0
	for {
		info, err = voiceclient.BuildInfoRequest(cfg, req.ContentType, req.Body)
		if err != nil {
			return IMSInfoResult{Handled: true, StatusCode: 500, Reason: "build client INFO failed"}, err
		}
		applyIncomingInfoHeaders(info.Headers, req.InfoPackage, req.Headers)
		a.updateInboundDialogClientAttempt(callID, cfg, nil)
		resp, err = a.roundTripClientRequest(ctx, info)
		if err != nil {
			return IMSInfoResult{Handled: true, StatusCode: 503, Reason: "client INFO failed"}, err
		}
		if redirectRetries < maxIMSInviteRedirects {
			if retryCfg, ok := retryDialogConfigForRedirect(cfg, resp, 0); ok {
				retryCfg.CSeq = a.allocateInboundClientCSeq(callID)
				cfg = retryCfg
				redirectRetries++
				continue
			}
		}
		break
	}
	a.updateInboundDialogClientContact(callID, resp.Headers)
	return IMSInfoResult{
		Handled:     true,
		StatusCode:  inboundStatusCode(resp.StatusCode, 500),
		Reason:      firstVoiceNonEmpty(resp.Reason, "OK"),
		ContentType: firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:        append([]byte(nil), resp.Body...),
		Headers:     firstValueSIPHeaders(resp.Headers),
	}, nil
}

func (a *IMSInboundAgent) CancelInboundCall(ctx context.Context, info DialogInfo) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentClientTransport() == nil {
		return ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(info.CallID)
	if callID == "" {
		return nil
	}
	state, ok := a.inboundDialog(callID)
	if !ok || !state.early || state.canceled {
		return nil
	}
	_, err := a.CancelInboundCallWithResult(ctx, info)
	return err
}

func (a *IMSInboundAgent) CancelInboundCallWithResult(ctx context.Context, info DialogInfo) (DialogInfoResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentClientTransport() == nil {
		return DialogInfoResult{Accepted: false, StatusCode: 503, Reason: "client voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(info.CallID)
	if callID == "" {
		return DialogInfoResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok || !state.early {
		a.mu.Unlock()
		return DialogInfoResult{Accepted: false, StatusCode: 481, Reason: "Call/Transaction Does Not Exist"}, nil
	}
	if state.canceled {
		a.mu.Unlock()
		return DialogInfoResult{Accepted: true, StatusCode: 200, Reason: "OK"}, nil
	}
	if state.inviteInFlight && !state.provisionalSeen {
		state.cancelRequested = true
		state.pendingCancel = cloneDialogInfo(info)
		state.pendingOffer = imsInboundPendingOffer{}
		a.dialogs[callID] = state
		a.mu.Unlock()
		return DialogInfoResult{Accepted: true, StatusCode: 200, Reason: "OK"}, nil
	}
	inFlight := state.inviteInFlight
	cancelCfg := cloneDialogRequestConfig(state.clientCfg)
	cancelInv := cloneSIPRequestMessage(state.invite)
	state.cancelRequested = true
	state.cancelSent = true
	state.pendingOffer = imsInboundPendingOffer{}
	a.dialogs[callID] = state
	a.mu.Unlock()
	return a.sendInboundClientCancelWire(ctx, callID, cancelCfg, cancelInv, info, inFlight)
}

func (a *IMSInboundAgent) sendInboundClientCancelWire(ctx context.Context, callID string, cancelCfg voiceclient.DialogRequestConfig, cancelInv voiceclient.SIPRequestMessage, info DialogInfo, inFlight bool) (DialogInfoResult, error) {
	cancel, err := voiceclient.BuildCancelRequestWithBody(cancelCfg, info.ContentType, info.Body)
	if err != nil {
		return DialogInfoResult{Accepted: false, StatusCode: 500, Reason: "build client CANCEL failed"}, err
	}
	applyDialogUpdateHeaders(cancel.Headers, info.Headers)
	copyDialogHeader(cancel.Headers, cancelInv.Headers, "Via")
	resp, err := a.roundTripClientRequest(ctx, cancel)
	if err != nil {
		if !inFlight {
			a.mu.Lock()
			if st, ok := a.dialogs[callID]; ok {
				st.cancelRequested = false
				st.cancelSent = false
				a.dialogs[callID] = st
			}
			a.mu.Unlock()
		}
		return DialogInfoResult{Accepted: false, StatusCode: 503, Reason: "client CANCEL failed"}, err
	}
	defaultReason := "OK"
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defaultReason = "Client CANCEL Rejected"
	}
	result := DialogInfoResult{
		Accepted:    resp.StatusCode >= 200 && resp.StatusCode < 300,
		StatusCode:  inboundStatusCode(resp.StatusCode, 500),
		Reason:      firstVoiceNonEmpty(resp.Reason, defaultReason),
		ContentType: firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:        append([]byte(nil), resp.Body...),
		Headers:     firstValueSIPHeaders(resp.Headers),
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if !inFlight {
			a.mu.Lock()
			if st, ok := a.dialogs[callID]; ok {
				st.cancelRequested = false
				st.cancelSent = false
				a.dialogs[callID] = st
			}
			a.mu.Unlock()
		}
		return result, fmt.Errorf("client CANCEL rejected: %d %s", resp.StatusCode, strings.TrimSpace(resp.Reason))
	}
	a.mu.Lock()
	if st, ok := a.dialogs[callID]; ok {
		st.canceled = true
		st.cancelRequested = true
		st.pendingOffer = imsInboundPendingOffer{}
		a.dialogs[callID] = st
	}
	a.mu.Unlock()
	return result, nil
}

func (a *IMSInboundAgent) EndInboundCall(ctx context.Context, info DialogInfo) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentClientTransport() == nil {
		return ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(info.CallID)
	if callID == "" {
		return nil
	}
	if _, ok := a.inboundDialog(callID); !ok {
		return nil
	}
	result, err := a.EndInboundCallWithResult(ctx, info)
	if err != nil {
		return err
	}
	if result.StatusCode > 0 && (result.StatusCode < 200 || result.StatusCode >= 300) {
		return fmt.Errorf("client BYE rejected: %d %s", result.StatusCode, strings.TrimSpace(result.Reason))
	}
	return nil
}

func (a *IMSInboundAgent) EndInboundCallWithResult(ctx context.Context, info DialogInfo) (DialogInfoResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentClientTransport() == nil {
		return DialogInfoResult{Accepted: false, StatusCode: 503, Reason: "client voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(info.CallID)
	if callID == "" {
		return DialogInfoResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return DialogInfoResult{Accepted: false, StatusCode: 481, Reason: "Call/Transaction Does Not Exist"}, nil
	}
	if !inboundIMSDialogTagsMatchStringMap(state.imsCfg, info.Headers) {
		a.mu.Unlock()
		return DialogInfoResult{Accepted: false, StatusCode: 481, Reason: "Call/Transaction Does Not Exist"}, nil
	}
	if info.CSeq > 0 && !a.validateInboundIMSRemoteCSeqLocked(callID, &state, info.CSeq) {
		a.mu.Unlock()
		return DialogInfoResult{Accepted: false, StatusCode: 500, Reason: "CSeq Out of Order"}, nil
	}
	cfg := cloneDialogRequestConfig(state.clientCfg)
	if info.CSeq > 0 {
		cfg.CSeq = maxInboundCSeq(nextInboundClientCSeq(cfg.CSeq), info.CSeq)
	} else {
		cfg.CSeq = nextInboundClientCSeq(cfg.CSeq)
	}
	state.clientCfg = cfg
	a.dialogs[callID] = state
	a.mu.Unlock()

	bye, err := voiceclient.BuildByeRequestWithBody(cfg, info.ContentType, info.Body)
	if err != nil {
		return DialogInfoResult{Accepted: false, StatusCode: 500, Reason: "build client BYE failed"}, err
	}
	applyDialogUpdateHeaders(bye.Headers, info.Headers)
	resp, err := a.roundTripClientRequest(ctx, bye)
	if err != nil {
		return DialogInfoResult{Accepted: false, StatusCode: 503, Reason: "client BYE failed"}, err
	}
	defaultReason := "OK"
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defaultReason = "Client BYE Rejected"
	}
	result := DialogInfoResult{
		Accepted:    resp.StatusCode >= 200 && resp.StatusCode < 300,
		StatusCode:  inboundStatusCode(resp.StatusCode, 500),
		Reason:      firstVoiceNonEmpty(resp.Reason, defaultReason),
		ContentType: firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:        append([]byte(nil), resp.Body...),
		Headers:     firstValueSIPHeaders(resp.Headers),
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, fmt.Errorf("client BYE rejected: %d %s", resp.StatusCode, strings.TrimSpace(resp.Reason))
	}
	a.closeInboundDialog(callID)
	a.emitDialogEvent(ctx, callID, cfg.RemoteURI, DialogStateTerminated, cfg.LocalURI, cfg.RemoteURI, 200, "remote BYE")
	return result, nil
}

// --- Client-to-IMS UAC leg methods (VH-01) ---

func (a *IMSInboundAgent) syncSentIMSDialogCSeq(callID string, sent voiceclient.SIPRequestMessage) {
	sentCSeq := voiceclient.ParseSIPCSeqNumber(sent.Headers["CSeq"])
	if sentCSeq <= 0 {
		return
	}
	after := outboundNextCSeq(sentCSeq)
	a.mu.Lock()
	if latest, ok := a.dialogs[callID]; ok && after > latest.imsCfg.CSeq {
		latest.imsCfg.CSeq = after
		a.dialogs[callID] = latest
	}
	a.mu.Unlock()
}

func (a *IMSInboundAgent) allocateIMSDialogCSeq(callID string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	latest, ok := a.dialogs[callID]
	if !ok {
		return 2
	}
	cseq := outboundInviteCSeq(latest.imsCfg.CSeq)
	latest.imsCfg.CSeq = outboundNextCSeq(cseq)
	a.dialogs[callID] = latest
	return cseq
}

func (a *IMSInboundAgent) updateIMSDialogContact(callID string, headers map[string][]string) {
	contact := sipHeaderURI(firstVoiceHeader(headers, "Contact"))
	if contact == "" {
		return
	}
	a.mu.Lock()
	if latest, ok := a.dialogs[callID]; ok {
		latest.imsCfg.RemoteTargetURI = contact
		a.dialogs[callID] = latest
	}
	a.mu.Unlock()
}

func (a *IMSInboundAgent) EndVoiceCall(ctx context.Context, info DialogInfo) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentIMSTransport() == nil {
		return ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(info.CallID)
	if callID == "" {
		return nil
	}
	if _, ok := a.inboundDialog(callID); !ok {
		return nil
	}
	result, err := a.EndVoiceCallWithResult(ctx, info)
	if err != nil {
		return err
	}
	if result.StatusCode > 0 && (result.StatusCode < 200 || result.StatusCode >= 300) {
		return fmt.Errorf("IMS BYE rejected: %d %s", result.StatusCode, strings.TrimSpace(result.Reason))
	}
	return nil
}

func (a *IMSInboundAgent) EndVoiceCallWithResult(ctx context.Context, info DialogInfo) (DialogInfoResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentIMSTransport() == nil {
		return DialogInfoResult{Accepted: false, StatusCode: 503, Reason: "IMS voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(info.CallID)
	if callID == "" {
		return DialogInfoResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return DialogInfoResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	cfg := cloneDialogRequestConfig(state.imsCfg)
	bye, err := voiceclient.BuildByeRequestWithBody(cfg, info.ContentType, info.Body)
	if err != nil {
		a.mu.Unlock()
		return DialogInfoResult{Accepted: false, StatusCode: 500, Reason: "build IMS BYE failed"}, err
	}
	applyDialogUpdateHeaders(bye.Headers, info.Headers)
	state.imsCfg.CSeq = outboundNextCSeq(cfg.CSeq)
	state.terminating = true
	stopInboundSessionRefresh(&state)
	a.dialogs[callID] = state
	callerURI := state.clientCfg.LocalURI
	calleeURI := state.clientCfg.RemoteURI
	a.mu.Unlock()

	resp, sentBye, err := a.roundTripIMSRequestWithResult(ctx, bye)
	a.syncSentIMSDialogCSeq(callID, sentBye)
	if err != nil {
		a.resumeInboundSessionRefreshAfterTerminating(callID)
		return DialogInfoResult{Accepted: false, StatusCode: 503, Reason: "IMS BYE failed", RegistrationRecoveryNeeded: true}, err
	}
	defaultReason := "OK"
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defaultReason = "IMS BYE rejected"
	}
	result := DialogInfoResult{
		Accepted:                   resp.StatusCode >= 200 && resp.StatusCode < 300,
		StatusCode:                 outboundStatusCode(resp.StatusCode, 500),
		Reason:                     firstVoiceNonEmpty(resp.Reason, defaultReason),
		RegistrationRecoveryNeeded: imsRegistrationRecoveryNeededStatus(resp.StatusCode),
		RetryAfter:                 voiceclient.SIPResponseRetryAfter(resp),
		ContentType:                firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:                       append([]byte(nil), resp.Body...),
		Headers:                    firstValueSIPHeaders(resp.Headers),
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == 481 {
			a.closeInboundDialog(callID)
			a.emitDialogEvent(ctx, callID, calleeURI, DialogStateTerminated, callerURI, calleeURI, 481, "local BYE")
			return result, fmt.Errorf("IMS BYE rejected: %d %s", resp.StatusCode, strings.TrimSpace(resp.Reason))
		}
		a.resumeInboundSessionRefreshAfterTerminating(callID)
		return result, fmt.Errorf("IMS BYE rejected: %d %s", resp.StatusCode, strings.TrimSpace(resp.Reason))
	}
	a.closeInboundDialog(callID)
	a.emitDialogEvent(ctx, callID, calleeURI, DialogStateTerminated, callerURI, calleeURI, 200, "local BYE")
	return result, nil
}

func (a *IMSInboundAgent) SendDialogInfo(ctx context.Context, req DialogInfoRequest) (DialogInfoResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentIMSTransport() == nil {
		return DialogInfoResult{Accepted: false, StatusCode: 503, Reason: "IMS voice transport unavailable"}, ErrIMSInboundAgentNotReady
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
	cfg := cloneDialogRequestConfig(state.imsCfg)
	state.imsCfg.CSeq = outboundNextCSeq(cfg.CSeq)
	a.dialogs[callID] = state
	a.mu.Unlock()

	var resp voiceclient.SIPResponse
	redirectRetries := 0
	for {
		info, err := voiceclient.BuildInfoRequest(cfg, req.ContentType, req.Body)
		if err != nil {
			return DialogInfoResult{Accepted: false, StatusCode: 500, Reason: "build IMS INFO failed"}, err
		}
		applyDialogInfoHeaders(info.Headers, req.InfoPackage, req.Headers)
		var sent voiceclient.SIPRequestMessage
		resp, sent, err = a.roundTripIMSRequestWithResult(ctx, info)
		a.syncSentIMSDialogCSeq(callID, sent)
		if err != nil {
			return DialogInfoResult{Accepted: false, StatusCode: 503, Reason: "IMS INFO failed", RegistrationRecoveryNeeded: true}, err
		}
		if redirectRetries < maxIMSInviteRedirects {
			if target := firstIMSRedirectContactURI(resp); target != "" {
				cfg.RemoteTargetURI = target
				cfg.CSeq = a.allocateIMSDialogCSeq(callID)
				redirectRetries++
				continue
			}
		}
		break
	}
	accepted := resp.StatusCode >= 200 && resp.StatusCode < 300
	if accepted {
		a.updateIMSDialogContact(callID, resp.Headers)
	}
	return DialogInfoResult{
		Accepted:                   accepted,
		StatusCode:                 outboundStatusCode(resp.StatusCode, 500),
		Reason:                     firstVoiceNonEmpty(resp.Reason, "OK"),
		RegistrationRecoveryNeeded: imsRegistrationRecoveryNeededStatus(resp.StatusCode),
		RetryAfter:                 voiceclient.SIPResponseRetryAfter(resp),
		ContentType:                firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:                       append([]byte(nil), resp.Body...),
		Headers:                    firstValueSIPHeaders(resp.Headers),
	}, nil
}

func (a *IMSInboundAgent) SendDialogMessage(ctx context.Context, req DialogMessageRequest) (DialogMessageResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentIMSTransport() == nil {
		return DialogMessageResult{Accepted: false, StatusCode: 503, Reason: "IMS voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return DialogMessageResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return DialogMessageResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	cfg := cloneDialogRequestConfig(state.imsCfg)
	state.imsCfg.CSeq = outboundNextCSeq(cfg.CSeq)
	a.dialogs[callID] = state
	a.mu.Unlock()

	var resp voiceclient.SIPResponse
	redirectRetries := 0
	for {
		msg, err := voiceclient.BuildDialogMessageRequest(cfg, req.ContentType, req.Body)
		if err != nil {
			return DialogMessageResult{Accepted: false, StatusCode: 500, Reason: "build IMS MESSAGE failed"}, err
		}
		applyDialogUpdateHeaders(msg.Headers, req.Headers)
		var sent voiceclient.SIPRequestMessage
		resp, sent, err = a.roundTripIMSRequestWithResult(ctx, msg)
		a.syncSentIMSDialogCSeq(callID, sent)
		if err != nil {
			return DialogMessageResult{Accepted: false, StatusCode: 503, Reason: "IMS MESSAGE failed", RegistrationRecoveryNeeded: true}, err
		}
		if redirectRetries < maxIMSInviteRedirects {
			if target := firstIMSRedirectContactURI(resp); target != "" {
				cfg.RemoteTargetURI = target
				cfg.CSeq = a.allocateIMSDialogCSeq(callID)
				redirectRetries++
				continue
			}
		}
		break
	}
	accepted := resp.StatusCode >= 200 && resp.StatusCode < 300
	if accepted {
		a.updateIMSDialogContact(callID, resp.Headers)
	}
	return DialogMessageResult{
		Accepted:                   accepted,
		StatusCode:                 outboundStatusCode(resp.StatusCode, 500),
		Reason:                     firstVoiceNonEmpty(resp.Reason, "OK"),
		RegistrationRecoveryNeeded: imsRegistrationRecoveryNeededStatus(resp.StatusCode),
		RetryAfter:                 voiceclient.SIPResponseRetryAfter(resp),
		ContentType:                firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:                       append([]byte(nil), resp.Body...),
		Headers:                    firstValueSIPHeaders(resp.Headers),
	}, nil
}

func (a *IMSInboundAgent) SendDialogPrack(ctx context.Context, req DialogPrackRequest) (DialogPrackResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentIMSTransport() == nil {
		return DialogPrackResult{Accepted: false, StatusCode: 503, Reason: "IMS voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return DialogPrackResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	rack := strings.TrimSpace(req.RAck)
	if rack == "" {
		return DialogPrackResult{Accepted: false, StatusCode: 400, Reason: "RAck empty"}, errors.New("RAck is empty")
	}
	body := append([]byte(nil), req.Body...)
	clientSDPBody := append([]byte(nil), req.Body...)
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return DialogPrackResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	relay := state.relay
	srtpNeg := state.srtpNegotiation
	if len(body) > 0 && relay != nil {
		clientSDP, err := ParseSDP(body)
		if err != nil {
			a.mu.Unlock()
			return DialogPrackResult{Accepted: false, StatusCode: 488, Reason: "invalid client PRACK SDP"}, err
		}
		if err := relay.SetClientRemote(clientSDP); err != nil {
			a.mu.Unlock()
			return DialogPrackResult{Accepted: false, StatusCode: 503, Reason: "RTP relay client PRACK failed"}, err
		}
		body = RewriteSDPMediaEndpoint(body, relay.IMSEndpoint())
		if srtpNeg != nil {
			rewritten, err := srtpNeg.RewriteIMSMidDialogOfferFromClient(relay, body)
			if err != nil {
				a.mu.Unlock()
				return DialogPrackResult{Accepted: false, StatusCode: 488, Reason: "invalid RTP relay SRTP PRACK SDP"}, err
			}
			body = rewritten
		}
	}
	cfg := cloneDialogRequestConfig(state.imsCfg)
	state.imsCfg.CSeq = outboundNextCSeq(cfg.CSeq)
	a.dialogs[callID] = state
	a.mu.Unlock()

	prack, err := voiceclient.BuildPrackRequestWithBody(cfg, rack, req.ContentType, body)
	if err != nil {
		return DialogPrackResult{Accepted: false, StatusCode: 500, Reason: "build IMS PRACK failed"}, err
	}
	applyDialogUpdateHeaders(prack.Headers, req.Headers)
	resp, sent, err := a.roundTripIMSRequestWithResult(ctx, prack)
	a.syncSentIMSDialogCSeq(callID, sent)
	if err != nil {
		return DialogPrackResult{Accepted: false, StatusCode: 503, Reason: "IMS PRACK failed", RegistrationRecoveryNeeded: true}, err
	}
	accepted := resp.StatusCode >= 200 && resp.StatusCode < 300
	resultBody := append([]byte(nil), resp.Body...)
	if accepted && len(resultBody) > 0 && relay != nil {
		imsSDP, err := ParseSDP(resultBody)
		if err != nil {
			return DialogPrackResult{Accepted: false, StatusCode: 488, Reason: "invalid IMS PRACK SDP answer"}, err
		}
		if err := relay.SetIMSRemote(imsSDP); err != nil {
			return DialogPrackResult{Accepted: false, StatusCode: 503, Reason: "RTP relay IMS PRACK failed"}, err
		}
		if srtpNeg != nil {
			resultBody, _, err = srtpNeg.RewriteClientMidDialogAnswerFromIMS(relay, resp.Body, imsSDP)
			if err != nil {
				return DialogPrackResult{Accepted: false, StatusCode: 488, Reason: "invalid RTP relay SRTP PRACK SDP answer"}, err
			}
		} else {
			resultBody = RewriteSDPMediaEndpoint(resultBody, relay.ClientEndpoint())
		}
	}
	if accepted {
		a.mu.Lock()
		if latest, ok := a.dialogs[callID]; ok {
			if contact := sipHeaderURI(firstVoiceHeader(resp.Headers, "Contact")); contact != "" {
				latest.imsCfg.RemoteTargetURI = contact
			}
			if len(clientSDPBody) > 0 {
				latest.clientSDPBody = clientSDPBody
			}
			a.dialogs[callID] = latest
		}
		a.mu.Unlock()
	}
	return DialogPrackResult{
		Accepted:                   accepted,
		StatusCode:                 outboundStatusCode(resp.StatusCode, 500),
		Reason:                     firstVoiceNonEmpty(resp.Reason, "OK"),
		RegistrationRecoveryNeeded: imsRegistrationRecoveryNeededStatus(resp.StatusCode),
		RetryAfter:                 voiceclient.SIPResponseRetryAfter(resp),
		ContentType:                firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:                       resultBody,
		Headers:                    firstValueSIPHeaders(resp.Headers),
	}, nil
}

func (a *IMSInboundAgent) SendDialogOptions(ctx context.Context, req DialogOptionsRequest) (DialogOptionsResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentIMSTransport() == nil {
		return DialogOptionsResult{Accepted: false, StatusCode: 503, Reason: "IMS voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return DialogOptionsResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return DialogOptionsResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	cfg := cloneDialogRequestConfig(state.imsCfg)
	state.imsCfg.CSeq = outboundNextCSeq(cfg.CSeq)
	a.dialogs[callID] = state
	a.mu.Unlock()

	options, err := voiceclient.BuildOptionsRequest(cfg)
	if err != nil {
		return DialogOptionsResult{Accepted: false, StatusCode: 500, Reason: "build IMS OPTIONS failed"}, err
	}
	applyDialogUpdateHeaders(options.Headers, req.Headers)
	resp, sent, err := a.roundTripIMSRequestWithResult(ctx, options)
	a.syncSentIMSDialogCSeq(callID, sent)
	if err != nil {
		return DialogOptionsResult{Accepted: false, StatusCode: 503, Reason: "IMS OPTIONS failed", RegistrationRecoveryNeeded: true}, err
	}
	accepted := resp.StatusCode >= 200 && resp.StatusCode < 300
	if accepted {
		a.updateIMSDialogContact(callID, resp.Headers)
	}
	return DialogOptionsResult{
		Accepted:                   accepted,
		StatusCode:                 outboundStatusCode(resp.StatusCode, 500),
		Reason:                     firstVoiceNonEmpty(resp.Reason, "OK"),
		RegistrationRecoveryNeeded: imsRegistrationRecoveryNeededStatus(resp.StatusCode),
		RetryAfter:                 voiceclient.SIPResponseRetryAfter(resp),
		ContentType:                firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:                       append([]byte(nil), resp.Body...),
		Headers:                    firstValueSIPHeaders(resp.Headers),
	}, nil
}

func (a *IMSInboundAgent) SendDialogRefer(ctx context.Context, req DialogReferRequest) (DialogReferResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentIMSTransport() == nil {
		return DialogReferResult{Accepted: false, StatusCode: 503, Reason: "IMS voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return DialogReferResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	referTo := strings.TrimSpace(req.ReferTo)
	if referTo == "" {
		return DialogReferResult{Accepted: false, StatusCode: 400, Reason: "Refer-To empty"}, errors.New("Refer-To is empty")
	}
	referSub, ok := normalizeReferSub(req.ReferSub)
	if !ok {
		return DialogReferResult{Accepted: false, StatusCode: 400, Reason: "Refer-Sub invalid"}, errors.New("Refer-Sub must be true or false")
	}
	effectiveReferSub := firstVoiceNonEmpty(referSub, voiceclient.DefaultReferSub)
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return DialogReferResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	cfg := cloneDialogRequestConfig(state.imsCfg)
	state.imsCfg.CSeq = outboundNextCSeq(cfg.CSeq)
	a.dialogs[callID] = state
	a.mu.Unlock()

	refer, err := voiceclient.BuildReferRequestWithOptions(cfg, referTo, voiceclient.ReferRequestOptions{
		ReferredBy: req.ReferredBy,
		ReferSub:   effectiveReferSub,
	})
	if err != nil {
		return DialogReferResult{Accepted: false, StatusCode: 500, Reason: "build IMS REFER failed"}, err
	}
	applyDialogUpdateHeaders(refer.Headers, req.Headers)
	refer.Headers["Refer-Sub"] = effectiveReferSub
	resp, sent, err := a.roundTripIMSRequestWithResult(ctx, refer)
	a.syncSentIMSDialogCSeq(callID, sent)
	if err != nil {
		return DialogReferResult{Accepted: false, StatusCode: 503, Reason: "IMS REFER failed", RegistrationRecoveryNeeded: true}, err
	}
	accepted := resp.StatusCode >= 200 && resp.StatusCode < 300
	if accepted {
		a.updateIMSDialogContact(callID, resp.Headers)
	}
	return DialogReferResult{
		Accepted:                   accepted,
		StatusCode:                 outboundStatusCode(resp.StatusCode, 500),
		Reason:                     firstVoiceNonEmpty(resp.Reason, "Accepted"),
		RegistrationRecoveryNeeded: imsRegistrationRecoveryNeededStatus(resp.StatusCode),
		RetryAfter:                 voiceclient.SIPResponseRetryAfter(resp),
		ContentType:                firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:                       append([]byte(nil), resp.Body...),
		Headers:                    firstValueSIPHeaders(resp.Headers),
	}, nil
}

func (a *IMSInboundAgent) SendDialogNotify(ctx context.Context, req DialogNotifyRequest) (DialogNotifyResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentIMSTransport() == nil {
		return DialogNotifyResult{Accepted: false, StatusCode: 503, Reason: "IMS voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return DialogNotifyResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	event := strings.TrimSpace(req.Event)
	if event == "" {
		return DialogNotifyResult{Accepted: false, StatusCode: 400, Reason: "Event empty"}, errors.New("Event is empty")
	}
	subscriptionState := strings.TrimSpace(req.SubscriptionState)
	if subscriptionState == "" {
		return DialogNotifyResult{Accepted: false, StatusCode: 400, Reason: "Subscription-State empty"}, errors.New("Subscription-State is empty")
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return DialogNotifyResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	cfg := cloneDialogRequestConfig(state.imsCfg)
	state.imsCfg.CSeq = outboundNextCSeq(cfg.CSeq)
	a.dialogs[callID] = state
	a.mu.Unlock()

	notify, err := voiceclient.BuildNotifyRequest(cfg, event, subscriptionState, req.ContentType, req.Body)
	if err != nil {
		return DialogNotifyResult{Accepted: false, StatusCode: 500, Reason: "build IMS NOTIFY failed"}, err
	}
	applyDialogUpdateHeaders(notify.Headers, req.Headers)
	resp, sent, err := a.roundTripIMSRequestWithResult(ctx, notify)
	a.syncSentIMSDialogCSeq(callID, sent)
	if err != nil {
		return DialogNotifyResult{Accepted: false, StatusCode: 503, Reason: "IMS NOTIFY failed", RegistrationRecoveryNeeded: true}, err
	}
	accepted := resp.StatusCode >= 200 && resp.StatusCode < 300
	if accepted {
		a.updateIMSDialogContact(callID, resp.Headers)
	}
	return DialogNotifyResult{
		Accepted:                   accepted,
		StatusCode:                 outboundStatusCode(resp.StatusCode, 500),
		Reason:                     firstVoiceNonEmpty(resp.Reason, "OK"),
		RegistrationRecoveryNeeded: imsRegistrationRecoveryNeededStatus(resp.StatusCode),
		RetryAfter:                 voiceclient.SIPResponseRetryAfter(resp),
		ContentType:                firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:                       append([]byte(nil), resp.Body...),
		Headers:                    firstValueSIPHeaders(resp.Headers),
	}, nil
}

func (a *IMSInboundAgent) SendDialogSubscribe(ctx context.Context, req DialogSubscribeRequest) (DialogSubscribeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentIMSTransport() == nil {
		return DialogSubscribeResult{Accepted: false, StatusCode: 503, Reason: "IMS voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return DialogSubscribeResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	event := strings.TrimSpace(req.Event)
	if event == "" {
		return DialogSubscribeResult{Accepted: false, StatusCode: 400, Reason: "Event empty"}, errors.New("Event is empty")
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return DialogSubscribeResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	cfg := cloneDialogRequestConfig(state.imsCfg)
	state.imsCfg.CSeq = outboundNextCSeq(cfg.CSeq)
	a.dialogs[callID] = state
	a.mu.Unlock()

	var resp voiceclient.SIPResponse
	retriedMinExpires := false
	subscribeExpires := strings.TrimSpace(req.Expires)
	for {
		subscribe, err := voiceclient.BuildSubscribeRequest(cfg, event, subscribeExpires, req.ContentType, req.Body)
		if err != nil {
			return DialogSubscribeResult{Accepted: false, StatusCode: 500, Reason: "build IMS SUBSCRIBE failed"}, err
		}
		applyDialogUpdateHeaders(subscribe.Headers, req.Headers)
		subscribe.Headers["Event"] = event
		if subscribeExpires != "" {
			subscribe.Headers["Expires"] = subscribeExpires
		}
		var sent voiceclient.SIPRequestMessage
		resp, sent, err = a.roundTripIMSRequestWithResult(ctx, subscribe)
		a.syncSentIMSDialogCSeq(callID, sent)
		if err != nil {
			return DialogSubscribeResult{Accepted: false, StatusCode: 503, Reason: "IMS SUBSCRIBE failed", RegistrationRecoveryNeeded: true}, err
		}
		if resp.StatusCode == 423 && !retriedMinExpires {
			if retryCfg, retryExpires, ok := retryDialogConfigForMinExpires(cfg, subscribe.Headers, resp.Headers); ok {
				retryCfg.CSeq = a.allocateIMSDialogCSeq(callID)
				cfg = retryCfg
				subscribeExpires = retryExpires
				retriedMinExpires = true
				continue
			}
		}
		break
	}
	accepted := resp.StatusCode >= 200 && resp.StatusCode < 300
	if accepted {
		a.updateIMSDialogContact(callID, resp.Headers)
	}
	return DialogSubscribeResult{
		Accepted:                   accepted,
		StatusCode:                 outboundStatusCode(resp.StatusCode, 500),
		Reason:                     firstVoiceNonEmpty(resp.Reason, "OK"),
		RegistrationRecoveryNeeded: imsRegistrationRecoveryNeededStatus(resp.StatusCode),
		RetryAfter:                 voiceclient.SIPResponseRetryAfter(resp),
		ContentType:                firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:                       append([]byte(nil), resp.Body...),
		Headers:                    firstValueSIPHeaders(resp.Headers),
	}, nil
}

func (a *IMSInboundAgent) SendDialogUpdate(ctx context.Context, req DialogUpdateRequest) (DialogUpdateResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentIMSTransport() == nil {
		return DialogUpdateResult{Accepted: false, StatusCode: 503, Reason: "IMS voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return DialogUpdateResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	body := append([]byte(nil), req.Body...)
	clientSDPBody := append([]byte(nil), req.Body...)
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return DialogUpdateResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	relay := state.relay
	srtpNeg := state.srtpNegotiation
	if len(body) > 0 && relay != nil {
		clientSDP, err := ParseSDP(body)
		if err != nil {
			a.mu.Unlock()
			return DialogUpdateResult{Accepted: false, StatusCode: 488, Reason: "invalid client UPDATE SDP"}, err
		}
		if err := relay.SetClientRemote(clientSDP); err != nil {
			a.mu.Unlock()
			return DialogUpdateResult{Accepted: false, StatusCode: 503, Reason: "RTP relay client update failed"}, err
		}
		body = RewriteSDPMediaEndpoint(body, relay.IMSEndpoint())
		if srtpNeg != nil {
			rewritten, err := srtpNeg.RewriteIMSMidDialogOfferFromClient(relay, body)
			if err != nil {
				a.mu.Unlock()
				return DialogUpdateResult{Accepted: false, StatusCode: 488, Reason: "invalid RTP relay SRTP UPDATE SDP"}, err
			}
			body = rewritten
		}
	}
	cfg := cloneDialogRequestConfig(state.imsCfg)
	state.imsCfg.CSeq = outboundNextCSeq(cfg.CSeq)
	a.dialogs[callID] = state
	a.mu.Unlock()

	var resp voiceclient.SIPResponse
	retriedSessionInterval := false
	forceSessionHeaders := false
	redirectRetries := 0
	for {
		update, err := voiceclient.BuildUpdateRequest(cfg, body)
		if err != nil {
			return DialogUpdateResult{Accepted: false, StatusCode: 500, Reason: "build IMS UPDATE failed"}, err
		}
		if len(body) > 0 && strings.TrimSpace(req.ContentType) != "" {
			update.Headers["Content-Type"] = strings.TrimSpace(req.ContentType)
		}
		applyDialogUpdateHeaders(update.Headers, req.Headers)
		if forceSessionHeaders {
			applySessionIntervalHeaders(update.Headers, cfg)
		}
		var sent voiceclient.SIPRequestMessage
		resp, sent, err = a.roundTripIMSRequestWithResult(ctx, update)
		a.syncSentIMSDialogCSeq(callID, sent)
		if err != nil {
			return DialogUpdateResult{Accepted: false, StatusCode: 503, Reason: "IMS UPDATE failed", RegistrationRecoveryNeeded: true}, err
		}
		if resp.StatusCode == 422 && !retriedSessionInterval {
			if retryCfg, ok := retryDialogConfigForMinSE(cfg, update.Headers, resp.Headers); ok {
				retryCfg.CSeq = a.allocateIMSDialogCSeq(callID)
				cfg = retryCfg
				retriedSessionInterval = true
				forceSessionHeaders = true
				continue
			}
		}
		if redirectRetries < maxIMSInviteRedirects {
			if target := firstIMSRedirectContactURI(resp); target != "" {
				cfg.RemoteTargetURI = target
				cfg.CSeq = a.allocateIMSDialogCSeq(callID)
				redirectRetries++
				continue
			}
		}
		break
	}
	accepted := resp.StatusCode >= 200 && resp.StatusCode < 300
	resultBody := append([]byte(nil), resp.Body...)
	if accepted && len(resultBody) > 0 && relay != nil {
		imsSDP, err := ParseSDP(resultBody)
		if err != nil {
			return DialogUpdateResult{Accepted: false, StatusCode: 488, Reason: "invalid IMS UPDATE SDP answer"}, err
		}
		if err := relay.SetIMSRemote(imsSDP); err != nil {
			return DialogUpdateResult{Accepted: false, StatusCode: 503, Reason: "RTP relay IMS update failed"}, err
		}
		if srtpNeg != nil {
			resultBody, _, err = srtpNeg.RewriteClientMidDialogAnswerFromIMS(relay, resp.Body, imsSDP)
			if err != nil {
				return DialogUpdateResult{Accepted: false, StatusCode: 488, Reason: "invalid RTP relay SRTP UPDATE SDP answer"}, err
			}
		} else {
			resultBody = RewriteSDPMediaEndpoint(resultBody, relay.ClientEndpoint())
		}
	}
	if accepted {
		a.mu.Lock()
		if latest, ok := a.dialogs[callID]; ok {
			if contact := sipHeaderURI(firstVoiceHeader(resp.Headers, "Contact")); contact != "" {
				latest.imsCfg.RemoteTargetURI = contact
			}
			if len(clientSDPBody) > 0 {
				latest.clientSDPBody = clientSDPBody
			}
			defaultRef := firstVoiceNonEmpty(normalizeSessionRefresher(latest.imsCfg.SessionRefresher), "uac")
			if applyNegotiatedSessionIntervalWithDefault(&latest.imsCfg, resp.Headers, defaultRef) {
				latest.sessionExpires = latest.imsCfg.SessionExpires
				if latest.imsCfg.SessionRefresher == "uac" {
					latest.sessionRole = "local"
				} else {
					latest.sessionRole = "ims"
				}
				latest.sessionDeadline = time.Now().Add(sessionExpirationTimeout(latest.sessionExpires))
			}
			a.dialogs[callID] = latest
		}
		a.mu.Unlock()
		a.scheduleInboundSessionRefresh(callID)
	}
	return DialogUpdateResult{
		Accepted:                   accepted,
		StatusCode:                 outboundStatusCode(resp.StatusCode, 500),
		Reason:                     firstVoiceNonEmpty(resp.Reason, "OK"),
		RegistrationRecoveryNeeded: imsRegistrationRecoveryNeededStatus(resp.StatusCode),
		RetryAfter:                 voiceclient.SIPResponseRetryAfter(resp),
		ContentType:                firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:                       resultBody,
		Headers:                    firstValueSIPHeaders(resp.Headers),
	}, nil
}

func (a *IMSInboundAgent) SendDialogHold(ctx context.Context, req DialogHoldRequest) (DialogUpdateResult, error) {
	direction := strings.TrimSpace(req.Direction)
	if direction == "" {
		direction = "sendonly"
	}
	return a.sendInboundClientDirectionUpdate(ctx, req.CallID, direction, firstVoiceNonEmpty(req.ContentType, "application/sdp"), req.Headers)
}

func (a *IMSInboundAgent) SendDialogResume(ctx context.Context, req DialogResumeRequest) (DialogUpdateResult, error) {
	return a.sendInboundClientDirectionUpdate(ctx, req.CallID, "sendrecv", firstVoiceNonEmpty(req.ContentType, "application/sdp"), req.Headers)
}

func (a *IMSInboundAgent) sendInboundClientDirectionUpdate(ctx context.Context, callID, direction, contentType string, headers map[string]string) (DialogUpdateResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentIMSTransport() == nil {
		return DialogUpdateResult{Accepted: false, StatusCode: 503, Reason: "IMS voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID = strings.TrimSpace(callID)
	if callID == "" {
		return DialogUpdateResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return DialogUpdateResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	if state.early {
		a.mu.Unlock()
		return DialogUpdateResult{Accepted: false, StatusCode: 491, Reason: "dialog not established"}, nil
	}
	body := append([]byte(nil), state.clientSDPBody...)
	a.mu.Unlock()
	if len(body) == 0 {
		return DialogUpdateResult{Accepted: false, StatusCode: 488, Reason: "dialog SDP unavailable"}, errors.New("dialog SDP unavailable")
	}
	body, err := RewriteSDPMediaDirection(body, direction)
	if err != nil {
		return DialogUpdateResult{Accepted: false, StatusCode: 400, Reason: err.Error()}, err
	}
	return a.SendDialogUpdate(ctx, DialogUpdateRequest{
		CallID:      callID,
		ContentType: contentType,
		Body:        body,
		Headers:     headers,
	})
}

func (a *IMSInboundAgent) SendDialogReinvite(ctx context.Context, req DialogReinviteRequest) (DialogReinviteResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentIMSTransport() == nil {
		return DialogReinviteResult{Accepted: false, StatusCode: 503, Reason: "IMS voice transport unavailable"}, ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return DialogReinviteResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	body := append([]byte(nil), req.Body...)
	clientSDPBody := append([]byte(nil), req.Body...)
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return DialogReinviteResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	relay := state.relay
	srtpNeg := state.srtpNegotiation
	cfg := cloneDialogRequestConfig(state.imsCfg)
	nextCSeq := outboundNextCSeq(cfg.CSeq)
	if len(body) > 0 && relay != nil {
		clientSDP, err := ParseSDP(body)
		if err != nil {
			a.mu.Unlock()
			return DialogReinviteResult{Accepted: false, StatusCode: 488, Reason: "invalid client re-INVITE SDP"}, err
		}
		if err := relay.SetClientRemote(clientSDP); err != nil {
			a.mu.Unlock()
			return DialogReinviteResult{Accepted: false, StatusCode: 503, Reason: "RTP relay client re-INVITE failed"}, err
		}
		body = RewriteSDPMediaEndpoint(body, relay.IMSEndpoint())
		if srtpNeg != nil {
			rewritten, err := srtpNeg.RewriteIMSMidDialogOfferFromClient(relay, body)
			if err != nil {
				a.mu.Unlock()
				return DialogReinviteResult{Accepted: false, StatusCode: 488, Reason: "invalid RTP relay SRTP re-INVITE SDP"}, err
			}
			body = rewritten
		}
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
	voiceclient.EnsureDialogRequestVia(&invite, cfg)
	state.imsCfg.CSeq = nextCSeq
	a.dialogs[callID] = state
	a.mu.Unlock()

	activeCfg := cfg
	activeInvite := invite
	syncSentInvite := func(sent voiceclient.SIPRequestMessage) {
		if sentCSeq := voiceclient.ParseSIPCSeqNumber(sent.Headers["CSeq"]); sentCSeq > 0 {
			activeCfg.CSeq = sentCSeq
			activeInvite = cloneSIPRequestMessage(sent)
			if after := outboundNextCSeq(sentCSeq); after > nextCSeq {
				nextCSeq = after
			}
			a.syncSentIMSDialogCSeq(callID, sent)
		}
	}
	ackRejectedIMS := func(sendCfg voiceclient.DialogRequestConfig, sendInv voiceclient.SIPRequestMessage, r voiceclient.SIPResponse) error {
		if ack, ackErr := voiceclient.BuildNon2xxInviteAck(sendInv, r); ackErr == nil {
			return a.writeIMSRequest(ctx, ack)
		}
		ackCfg := sendCfg
		ackCfg.RemoteTag = firstVoiceNonEmpty(sipHeaderTag(firstVoiceHeader(r.Headers, "To")), sendCfg.RemoteTag)
		ack, ackErr := voiceclient.BuildAckRequest(ackCfg)
		if ackErr != nil {
			return ackErr
		}
		copyDialogHeader(ack.Headers, sendInv.Headers, "Via")
		return a.writeIMSRequest(ctx, ack)
	}

	resp, sentInvite, err := a.roundTripIMSInvite(ctx, invite, nil)
	if err != nil {
		return DialogReinviteResult{Accepted: false, StatusCode: 503, Reason: "IMS re-INVITE failed", RegistrationRecoveryNeeded: true}, err
	}
	syncSentInvite(sentInvite)

	if isInviteDigestChallenge(resp) && invite.AuthSession != nil {
		if err := ackRejectedIMS(activeCfg, activeInvite, resp); err != nil {
			return DialogReinviteResult{Accepted: false, StatusCode: 500, Reason: "IMS re-INVITE challenge ACK failed"}, err
		}
		authz, ok, authErr := invite.AuthSession.AuthorizeChallengeWithResult(resp, "INVITE", activeInvite.URI, activeInvite.Body)
		if authErr != nil {
			return DialogReinviteResult{Accepted: false, StatusCode: 500, Reason: "IMS re-INVITE challenge auth failed"}, authErr
		}
		if ok {
			retryCfg := activeCfg
			retryCfg.CSeq = a.allocateIMSDialogCSeq(callID)
			wireCfg := retryCfg
			wireCfg.AuthSession = nil
			wireCfg.AuthHeaderName = authz.HeaderName
			wireCfg.AuthHeader = authz.Header
			wireCfg.Registration.AuthSession = nil
			retryInvite, buildErr := voiceclient.BuildInviteRequest(wireCfg, body)
			if buildErr != nil {
				return DialogReinviteResult{Accepted: false, StatusCode: 500, Reason: "build IMS re-INVITE auth retry failed"}, buildErr
			}
			if len(body) > 0 && strings.TrimSpace(req.ContentType) != "" {
				retryInvite.Headers["Content-Type"] = strings.TrimSpace(req.ContentType)
			}
			applyDialogUpdateHeaders(retryInvite.Headers, req.Headers)
			voiceclient.EnsureDialogRequestVia(&retryInvite, retryCfg)
			retryInvite.AuthSession = invite.AuthSession
			activeCfg = retryCfg
			activeInvite = retryInvite
			nextCSeq = outboundNextCSeq(retryCfg.CSeq)
			resp, sentInvite, err = a.roundTripIMSInvite(ctx, retryInvite, nil)
			if err != nil {
				return DialogReinviteResult{Accepted: false, StatusCode: 503, Reason: "IMS re-INVITE auth retry failed", RegistrationRecoveryNeeded: true}, err
			}
			syncSentInvite(sentInvite)
		}
	}

	accepted := resp.StatusCode >= 200 && resp.StatusCode < 300
	if !accepted {
		if resp.StatusCode >= 300 {
			if err := ackRejectedIMS(activeCfg, activeInvite, resp); err != nil {
				return DialogReinviteResult{Accepted: false, StatusCode: 500, Reason: "IMS re-INVITE rejected ACK failed"}, err
			}
		}
		return DialogReinviteResult{
			Accepted:                   false,
			StatusCode:                 outboundStatusCode(resp.StatusCode, 488),
			Reason:                     firstVoiceNonEmpty(resp.Reason, "re-INVITE rejected"),
			RegistrationRecoveryNeeded: imsRegistrationRecoveryNeededStatus(resp.StatusCode),
			RetryAfter:                 voiceclient.SIPResponseRetryAfter(resp),
			Headers:                    firstValueSIPHeaders(resp.Headers),
		}, nil
	}

	ackCfg := activeCfg
	ackCfg.RemoteTag = firstVoiceNonEmpty(sipHeaderTag(firstVoiceHeader(resp.Headers, "To")), activeCfg.RemoteTag)
	if contact := sipHeaderURI(firstVoiceHeader(resp.Headers, "Contact")); contact != "" {
		ackCfg.RemoteTargetURI = contact
	}
	lateOffer200 := len(req.Body) == 0 && len(resp.Body) > 0
	deferAck := req.DeferAck && lateOffer200
	if !deferAck {
		var ackBody []byte
		if lateOffer200 {
			a.mu.Lock()
			if latest, ok := a.dialogs[callID]; ok && len(latest.clientSDPBody) > 0 {
				ackBody = append([]byte(nil), latest.clientSDPBody...)
			}
			a.mu.Unlock()
			if len(ackBody) > 0 && relay != nil {
				ackBody = RewriteSDPMediaEndpoint(ackBody, relay.IMSEndpoint())
				if srtpNeg != nil {
					if rewritten, rwErr := srtpNeg.RewriteIMSMidDialogOfferFromClient(relay, ackBody); rwErr == nil {
						ackBody = rewritten
					}
				}
			}
		}
		ack, ackErr := buildDialogAckWithOptionalSDP(ackCfg, ackBody)
		if ackErr != nil {
			return DialogReinviteResult{Accepted: false, StatusCode: 500, Reason: "build IMS re-INVITE ACK failed"}, ackErr
		}
		if err := a.writeIMSRequest(ctx, ack); err != nil {
			return DialogReinviteResult{Accepted: false, StatusCode: 503, Reason: "IMS re-INVITE ACK failed"}, err
		}
	}

	resultBody := append([]byte(nil), resp.Body...)
	if len(resultBody) > 0 && relay != nil {
		imsSDP, err := ParseSDP(resultBody)
		if err != nil {
			return DialogReinviteResult{Accepted: false, StatusCode: 488, Reason: "invalid IMS re-INVITE SDP answer"}, err
		}
		if err := relay.SetIMSRemote(imsSDP); err != nil {
			return DialogReinviteResult{Accepted: false, StatusCode: 503, Reason: "RTP relay IMS re-INVITE failed"}, err
		}
		if srtpNeg != nil {
			resultBody, _, err = srtpNeg.RewriteClientMidDialogAnswerFromIMS(relay, resp.Body, imsSDP)
			if err != nil {
				return DialogReinviteResult{Accepted: false, StatusCode: 488, Reason: "invalid RTP relay SRTP re-INVITE SDP answer"}, err
			}
		} else {
			resultBody = RewriteSDPMediaEndpoint(resultBody, relay.ClientEndpoint())
		}
	}

	a.mu.Lock()
	if latest, ok := a.dialogs[callID]; ok {
		latest.imsCfg.RemoteTargetURI = ackCfg.RemoteTargetURI
		latest.imsCfg.RemoteTag = ackCfg.RemoteTag
		if nextCSeq > latest.imsCfg.CSeq {
			latest.imsCfg.CSeq = nextCSeq
		}
		if len(clientSDPBody) > 0 {
			latest.clientSDPBody = clientSDPBody
		}
		if deferAck {
			latest.pendingIMSAckCfg = cloneDialogRequestConfig(ackCfg)
			latest.hasPendingIMSAck = true
		} else {
			latest.hasPendingIMSAck = false
		}
		defaultRef := firstVoiceNonEmpty(normalizeSessionRefresher(latest.imsCfg.SessionRefresher), "uac")
		if applyNegotiatedSessionIntervalWithDefault(&latest.imsCfg, resp.Headers, defaultRef) {
			latest.sessionExpires = latest.imsCfg.SessionExpires
			if latest.imsCfg.SessionRefresher == "uac" {
				latest.sessionRole = "local"
			} else {
				latest.sessionRole = "ims"
			}
			latest.sessionDeadline = time.Now().Add(sessionExpirationTimeout(latest.sessionExpires))
		}
		a.dialogs[callID] = latest
	}
	a.mu.Unlock()
	a.scheduleInboundSessionRefresh(callID)
	return DialogReinviteResult{
		Accepted:    true,
		StatusCode:  outboundStatusCode(resp.StatusCode, 200),
		Reason:      firstVoiceNonEmpty(resp.Reason, "OK"),
		ContentType: firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:        resultBody,
		Headers:     firstValueSIPHeaders(resp.Headers),
	}, nil
}

func (a *IMSInboundAgent) AckDialog(ctx context.Context, req DialogAckRequest) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentIMSTransport() == nil {
		return ErrIMSInboundAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return nil
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok || !state.hasPendingIMSAck {
		a.mu.Unlock()
		return nil
	}
	ackCfg := cloneDialogRequestConfig(state.pendingIMSAckCfg)
	relay := state.relay
	srtpNeg := state.srtpNegotiation
	state.hasPendingIMSAck = false
	if len(req.Body) > 0 {
		state.clientSDPBody = append([]byte(nil), req.Body...)
	}
	a.dialogs[callID] = state
	a.mu.Unlock()

	ackBody := append([]byte(nil), req.Body...)
	if len(ackBody) > 0 && relay != nil {
		clientSDP, err := ParseSDP(ackBody)
		if err != nil {
			return err
		}
		if err := relay.SetClientRemote(clientSDP); err != nil {
			return err
		}
		ackBody = RewriteSDPMediaEndpoint(ackBody, relay.IMSEndpoint())
		if srtpNeg != nil {
			ackBody, err = srtpNeg.RewriteIMSMidDialogOfferFromClient(relay, ackBody)
			if err != nil {
				return err
			}
		}
	}
	ack, err := buildDialogAckWithOptionalSDP(ackCfg, ackBody)
	if err != nil {
		return err
	}
	applyDialogUpdateHeaders(ack.Headers, req.Headers)
	return a.writeIMSRequest(ctx, ack)
}

// --- RFC 4028 Session Timer Refresh & Expiry Watchdog (VH-09) ---

func stopInboundSessionRefresh(state *imsInboundDialogState) {
	if state == nil {
		return
	}
	if state.refreshTimer != nil {
		state.refreshTimer.Stop()
		state.refreshTimer = nil
	}
	if state.expiryTimer != nil {
		state.expiryTimer.Stop()
		state.expiryTimer = nil
	}
	state.refreshSeq++
}

func (a *IMSInboundAgent) StopSessionTimers() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for callID, state := range a.dialogs {
		stopInboundSessionRefresh(&state)
		a.dialogs[callID] = state
	}
}

func (a *IMSInboundAgent) resumeInboundSessionRefreshAfterTerminating(callID string) {
	callID = strings.TrimSpace(callID)
	if a == nil || callID == "" {
		return
	}
	a.mu.Lock()
	if state, ok := a.dialogs[callID]; ok {
		state.terminating = false
		a.dialogs[callID] = state
	}
	a.mu.Unlock()
	a.scheduleInboundSessionRefresh(callID)
}

func (a *IMSInboundAgent) scheduleInboundSessionRefresh(callID string) {
	a.scheduleInboundSessionRefreshAfter(callID, 0)
}

func (a *IMSInboundAgent) scheduleInboundSessionRefreshAfter(callID string, customDelay time.Duration) {
	callID = strings.TrimSpace(callID)
	if a == nil || callID == "" {
		return
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return
	}
	stopInboundSessionRefresh(&state)
	seq := state.refreshSeq
	delay := customDelay
	if delay <= 0 && state.sessionExpires > 0 {
		switch state.sessionRole {
		case "local":
			delay = sessionRefreshDelay(state.sessionExpires, "uac", a.SessionRefreshLead)
		case "ims":
			delay = sessionExpirationTimeout(state.sessionExpires)
		}
	}
	if delay <= 0 || state.early || state.terminating || state.sessionExpires <= 0 {
		a.dialogs[callID] = state
		a.mu.Unlock()
		return
	}
	if state.sessionRole == "ims" && customDelay <= 0 {
		state.expiryTimer = time.AfterFunc(delay, func() {
			a.runInboundSessionRefresh(callID, seq)
		})
	} else {
		state.refreshTimer = time.AfterFunc(delay, func() {
			a.runInboundSessionRefresh(callID, seq)
		})
	}
	a.dialogs[callID] = state
	a.mu.Unlock()
}

func (a *IMSInboundAgent) runInboundSessionRefresh(callID string, seq uint64) {
	callID = strings.TrimSpace(callID)
	if a == nil || callID == "" {
		return
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok || state.refreshSeq != seq || state.early || state.terminating || state.sessionExpires <= 0 {
		a.mu.Unlock()
		return
	}
	role := state.sessionRole
	deadline := state.sessionDeadline
	expires := state.sessionExpires
	clientSDP := append([]byte(nil), state.clientSDPBody...)
	hasIMSTransport := a.IMSTransport != nil
	a.mu.Unlock()

	if role == "ims" {
		a.terminateExpiredInboundSession(callID, "session expired")
		return
	}
	if role != "local" {
		return
	}
	if hasIMSTransport {
		updRes, updErr := a.SendDialogUpdate(context.Background(), DialogUpdateRequest{CallID: callID})
		if updErr == nil && updRes.Accepted {
			return
		}
		if updRes.StatusCode == 405 || updRes.StatusCode == 501 {
			reReq := DialogReinviteRequest{CallID: callID}
			if len(clientSDP) > 0 {
				reReq.ContentType = "application/sdp"
				reReq.Body = clientSDP
			}
			reRes, reErr := a.SendDialogReinvite(context.Background(), reReq)
			if reErr == nil && reRes.Accepted {
				return
			}
			if reRes.StatusCode == 481 {
				a.terminateExpiredInboundSession(callID, "session refresh 481")
				return
			}
		}
		if updRes.StatusCode == 481 {
			a.terminateExpiredInboundSession(callID, "session refresh 481")
			return
		}
	} else {
		// Refresh the local client leg if no IMS transport is attached.
		updRes, updErr := a.HandleInboundUpdate(context.Background(), InboundDialogRequest{CallID: callID})
		if updErr == nil && updRes.Accepted {
			return
		}
		if updRes.StatusCode == 481 {
			a.terminateExpiredInboundSession(callID, "session refresh 481")
			return
		}
	}
	now := time.Now()
	if deadline.IsZero() && expires > 0 {
		deadline = now.Add(sessionExpirationTimeout(expires) / 2)
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		a.terminateExpiredInboundSession(callID, "session expired")
		return
	}
	retryDelay := remaining / 2
	if retryDelay > 10*time.Second {
		retryDelay = 10 * time.Second
	}
	if retryDelay < 50*time.Millisecond {
		retryDelay = 50 * time.Millisecond
	}
	a.scheduleInboundSessionRefreshAfter(callID, retryDelay)
}

func (a *IMSInboundAgent) terminateExpiredInboundSession(callID string, reason string) {
	callID = strings.TrimSpace(callID)
	if a == nil || callID == "" {
		return
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return
	}
	stopInboundSessionRefresh(&state)
	delete(a.dialogs, callID)
	clientTransport := a.ClientTransport
	imsTransport := a.IMSTransport
	a.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if clientTransport != nil {
		byeCfg := state.clientCfg
		byeCfg.CSeq = nextInboundClientCSeq(byeCfg.CSeq)
		if byeReq, err := voiceclient.BuildByeRequestWithBody(byeCfg, "", nil); err == nil {
			_, _ = clientTransport.RoundTripRequest(ctx, byeReq)
		}
	}
	if imsTransport != nil && strings.TrimSpace(state.imsCfg.RemoteTargetURI) != "" {
		if byeReq, err := voiceclient.BuildByeRequestWithBody(state.imsCfg, "", nil); err == nil {
			_, _ = voiceclient.RoundTripRequestWithDigestAuth(ctx, imsTransport, byeReq)
		}
	}
	if state.relay != nil {
		_ = state.relay.Close()
	}
	a.emitDialogEvent(context.Background(), callID, state.clientCfg.RemoteURI, DialogStateTerminated, state.clientCfg.LocalURI, state.clientCfg.RemoteURI, 408, reason)
}

// --- SDP helpers & state management ---

func inboundOfferSDP(req InboundCallRequest) (SDPInfo, []byte, error) {
	body := append([]byte(nil), req.RawSDP...)
	info := req.RemoteSDP
	if info.MediaPort <= 0 || strings.TrimSpace(info.ConnectionIP) == "" {
		parsed, err := ParseSDP(body)
		if err != nil {
			return SDPInfo{}, nil, err
		}
		info = parsed
	}
	if len(body) == 0 {
		body = BuildSDPAnswer(info)
	}
	return info, body, nil
}

func inboundDialogSDP(req InboundDialogRequest) (SDPInfo, []byte, error) {
	body := inboundDialogBody(req)
	info := req.RemoteSDP
	if info.MediaPort <= 0 || strings.TrimSpace(info.ConnectionIP) == "" {
		parsed, err := ParseSDP(body)
		if err != nil {
			return SDPInfo{}, nil, err
		}
		info = parsed
	}
	if len(body) == 0 {
		body = BuildSDPAnswer(info)
	}
	return info, body, nil
}

func inboundDialogBody(req InboundDialogRequest) []byte {
	if len(req.RawSDP) > 0 {
		return append([]byte(nil), req.RawSDP...)
	}
	return append([]byte(nil), req.Body...)
}

func inboundCallRequestHasOffer(req InboundCallRequest) bool {
	return len(req.RawSDP) > 0 || inboundSDPInfoPresent(req.RemoteSDP)
}

func inboundDialogRequestHasOffer(req InboundDialogRequest) bool {
	return len(req.RawSDP) > 0 || inboundSDPInfoPresent(req.RemoteSDP)
}

func inboundSDPInfoPresent(info SDPInfo) bool {
	return strings.TrimSpace(info.ConnectionIP) != "" || info.MediaPort > 0
}

func inboundCSeq(cseq int) int {
	if cseq <= 0 {
		return 1
	}
	return cseq
}

func nextInboundClientCSeq(cseq int) int {
	if cseq <= 0 {
		return 1
	}
	return cseq + 1
}

func maxInboundCSeq(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func inboundStatusCode(code, fallback int) int {
	if code > 0 {
		return code
	}
	return fallback
}

func (a *IMSInboundAgent) beginInboundDialogOfferWithHeaders(callID, method string, imsCSeq int, headers map[string][]string, hasOffer bool) (imsInboundDialogState, int, imsInboundDialogConcurrencyDecision, bool) {
	if a == nil {
		return imsInboundDialogState{}, 0, imsInboundDialogConcurrencyDecision{}, false
	}
	callID = strings.TrimSpace(callID)
	if callID == "" {
		return imsInboundDialogState{}, 0, imsInboundDialogConcurrencyDecision{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	state, ok := a.dialogs[callID]
	if !ok {
		return imsInboundDialogState{}, 0, imsInboundDialogConcurrencyDecision{}, false
	}
	if !inboundIMSDialogTagsMatch(state.imsCfg, headers) {
		return cloneInboundDialogStateSnapshot(state), 0, imsInboundDialogConcurrencyDecision{statusCode: 481, reason: "Call/Transaction Does Not Exist"}, true
	}
	if !a.validateInboundIMSRemoteCSeqLocked(callID, &state, imsCSeq) {
		return cloneInboundDialogStateSnapshot(state), 0, imsInboundDialogConcurrencyDecision{statusCode: 500, reason: "CSeq Out of Order"}, true
	}
	if hasOffer && state.pendingOffer.active {
		return cloneInboundDialogStateSnapshot(state), 0, imsInboundDialogConcurrencyDecision{statusCode: 491, reason: "Request Pending"}, true
	}
	allocCSeq := maxInboundCSeq(nextInboundClientCSeq(state.clientCfg.CSeq), inboundCSeq(imsCSeq))
	state.clientCfg.CSeq = allocCSeq
	decision := imsInboundDialogConcurrencyDecision{}
	if hasOffer {
		a.nextPendingOfferSerial++
		if a.nextPendingOfferSerial == 0 {
			a.nextPendingOfferSerial++
		}
		state.pendingOffer = imsInboundPendingOffer{
			active: true,
			serial: a.nextPendingOfferSerial,
			method: strings.ToUpper(strings.TrimSpace(method)),
			cseq:   allocCSeq,
		}
		decision.trackPendingOffer = true
	}
	a.dialogs[callID] = state
	return cloneInboundDialogStateSnapshot(state), allocCSeq, decision, true
}

func (a *IMSInboundAgent) releaseInboundPendingOffer(callID string, serial uint64) {
	if a == nil || serial == 0 {
		return
	}
	callID = strings.TrimSpace(callID)
	if callID == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	state, ok := a.dialogs[callID]
	if !ok || !state.pendingOffer.active || state.pendingOffer.serial != serial {
		return
	}
	state.pendingOffer = imsInboundPendingOffer{}
	a.dialogs[callID] = state
}

func (a *IMSInboundAgent) storeInboundDialog(callID string, state imsInboundDialogState) {
	if a == nil || strings.TrimSpace(callID) == "" {
		return
	}
	callID = strings.TrimSpace(callID)
	a.mu.Lock()
	if a.dialogs == nil {
		a.dialogs = make(map[string]imsInboundDialogState)
	}
	if prev, ok := a.dialogs[callID]; ok {
		if prev.refreshTimer != nil && prev.refreshTimer != state.refreshTimer {
			prev.refreshTimer.Stop()
		}
		if prev.expiryTimer != nil && prev.expiryTimer != state.expiryTimer {
			prev.expiryTimer.Stop()
		}
	}
	a.dialogs[callID] = cloneInboundDialogStateSnapshot(state)
	a.mu.Unlock()
}

func (a *IMSInboundAgent) inboundDialog(callID string) (imsInboundDialogState, bool) {
	if a == nil || strings.TrimSpace(callID) == "" {
		return imsInboundDialogState{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	state, ok := a.dialogs[strings.TrimSpace(callID)]
	if !ok {
		return imsInboundDialogState{}, false
	}
	return cloneInboundDialogStateSnapshot(state), true
}

func (a *IMSInboundAgent) hasInboundDialog(callID string) bool {
	_, ok := a.inboundDialog(callID)
	return ok
}

func (a *IMSInboundAgent) inboundDialogCanceled(callID string) bool {
	state, ok := a.inboundDialog(callID)
	return ok && state.canceled
}

func (a *IMSInboundAgent) deleteInboundDialog(callID string) {
	if a == nil || strings.TrimSpace(callID) == "" {
		return
	}
	callID = strings.TrimSpace(callID)
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if ok {
		if state.refreshTimer != nil {
			state.refreshTimer.Stop()
		}
		if state.expiryTimer != nil {
			state.expiryTimer.Stop()
		}
		delete(a.dialogs, callID)
	}
	a.mu.Unlock()
	if ok && state.relay != nil {
		_ = state.relay.Close()
	}
}

func (a *IMSInboundAgent) closeInboundDialog(callID string) {
	a.deleteInboundDialog(callID)
}

func (a *IMSInboundAgent) TerminateAllDialogs(ctx context.Context) error {
	if a == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	a.mu.Lock()
	transport := a.ClientTransport
	imsTransport := a.IMSTransport
	snapshots := make(map[string]imsInboundDialogState, len(a.dialogs))
	for callID, state := range a.dialogs {
		stopInboundSessionRefresh(&state)
		snapshots[callID] = cloneInboundDialogStateSnapshot(state)
	}
	a.dialogs = nil
	a.mu.Unlock()

	var errs []error
	for callID, state := range snapshots {
		if transport != nil && !state.canceled && !state.terminating {
			termCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			if state.early {
				if !state.inviteInFlight || state.provisionalSeen {
					if cancelReq, buildErr := voiceclient.BuildCancelRequestWithBody(state.clientCfg, "", nil); buildErr == nil {
						copyDialogHeader(cancelReq.Headers, state.invite.Headers, "Via")
						_, _ = transport.RoundTripRequest(termCtx, cancelReq)
					}
				}
			} else {
				byeCfg := state.clientCfg
				byeCfg.CSeq = nextInboundClientCSeq(byeCfg.CSeq)
				if byeReq, buildErr := voiceclient.BuildByeRequestWithBody(byeCfg, "", nil); buildErr == nil {
					_, _ = transport.RoundTripRequest(termCtx, byeReq)
				}
				if imsTransport != nil && strings.TrimSpace(state.imsCfg.RemoteTargetURI) != "" {
					if imsBye, buildErr := voiceclient.BuildByeRequestWithBody(state.imsCfg, "", nil); buildErr == nil {
						_, _ = voiceclient.RoundTripRequestWithDigestAuth(termCtx, imsTransport, imsBye)
					}
				}
			}
			cancel()
		}
		if state.relay != nil {
			if closeErr := state.relay.Close(); closeErr != nil {
				errs = append(errs, closeErr)
			}
		}
		a.emitDialogEvent(ctx, callID, state.clientCfg.RemoteURI, DialogStateTerminated, state.clientCfg.LocalURI, state.clientCfg.RemoteURI, 200, "runtime stopped")
	}
	return errors.Join(errs...)
}

func (a *IMSInboundAgent) roundTripClientInvite(ctx context.Context, invite voiceclient.SIPRequestMessage, onProvisional func(voiceclient.SIPResponse) error) (voiceclient.SIPResponse, error) {
	transport := a.currentClientTransport()
	if a == nil || transport == nil {
		return voiceclient.SIPResponse{}, ErrIMSInboundAgentNotReady
	}
	if inviteTransport, ok := transport.(voiceclient.SIPInviteTransport); ok {
		return inviteTransport.RoundTripInvite(ctx, invite, func(_ context.Context, _ voiceclient.SIPRequestMessage, resp voiceclient.SIPResponse) error {
			if onProvisional == nil {
				return nil
			}
			return onProvisional(resp)
		})
	}
	return transport.RoundTripRequest(ctx, invite)
}
