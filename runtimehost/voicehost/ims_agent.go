package voicehost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kimoju/vowifi-go/runtimehost/voiceclient"
)

var ErrIMSVoiceAgentNotReady = errors.New("ims voice agent not ready")

type IMSOutboundAgent struct {
	Transport          voiceclient.SIPRequestTransport
	Profile            voiceclient.IMSProfile
	Registration       voiceclient.RegistrationBinding
	Domain             string
	UserAgent          string
	LocalTag           string
	SessionExpires     int
	SessionRefresher   string
	SessionRefreshLead time.Duration
	RemoteTargetURI    string
	MediaRelay         *RTPRelayConfig
	OnDialogTerminated func(ctx context.Context, callID string, reason string)

	mu      sync.Mutex
	dialogs map[string]imsDialogState
}

type IMSRegistrationUpdate struct {
	Transport          voiceclient.SIPRequestTransport
	Profile            voiceclient.IMSProfile
	Registration       voiceclient.RegistrationBinding
	Domain             string
	UserAgent          string
	SessionExpires     int
	SessionRefresher   string
	SessionRefreshLead time.Duration
	MediaRelay         *RTPRelayConfig
}

type IMSRegistrationUpdater interface {
	UpdateIMSRegistration(IMSRegistrationUpdate)
}

func (a *IMSOutboundAgent) UpdateIMSRegistration(update IMSRegistrationUpdate) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if update.Transport != nil {
		a.Transport = update.Transport
	}
	if strings.TrimSpace(update.Profile.IMPU) != "" || strings.TrimSpace(update.Profile.IMPI) != "" {
		a.Profile = update.Profile
	}
	if strings.TrimSpace(update.Registration.ContactURI) != "" {
		a.Registration = update.Registration
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

type imsDialogState struct {
	cfg                voiceclient.DialogRequestConfig
	invite             voiceclient.SIPRequestMessage
	relay              *RTPRelaySession
	srtpNegotiation    *outboundSDESRelayNegotiation
	localSDPBody       []byte
	early              bool
	terminating        bool
	inviteInFlight     bool
	provisionalSeen    bool
	cancelRequested    bool
	cancelSent         bool
	canceled           bool
	pendingCancel      DialogInfo
	pendingAckCfg      voiceclient.DialogRequestConfig
	hasPendingAck      bool
	awaitingInboundAck bool
	lastRemoteCSeq     int
	sessionDeadline    time.Time
	refreshTimer       *time.Timer
	expiryTimer        *time.Timer
	refreshSeq         uint64
}

func randomVoiceSIPTag() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return hex.EncodeToString(raw[:])
	}
	return strconv.FormatUint(uint64(time.Now().UnixNano()), 16)
}

func cloneDialogInfo(in DialogInfo) DialogInfo {
	out := in
	out.Body = append([]byte(nil), in.Body...)
	out.Headers = copyVoiceHeaderMap(in.Headers)
	return out
}

func cloneDialogRequestConfig(cfg voiceclient.DialogRequestConfig) voiceclient.DialogRequestConfig {
	out := cfg
	out.RouteSet = copyStringSlice(cfg.RouteSet)
	out.InviteHeaders = copyVoiceHeaderMap(cfg.InviteHeaders)
	return out
}

func cloneDialogStateSnapshot(state imsDialogState) imsDialogState {
	out := state
	out.cfg = cloneDialogRequestConfig(state.cfg)
	out.invite = cloneSIPRequestMessage(state.invite)
	out.localSDPBody = append([]byte(nil), state.localSDPBody...)
	out.pendingCancel = cloneDialogInfo(state.pendingCancel)
	out.pendingAckCfg = cloneDialogRequestConfig(state.pendingAckCfg)
	return out
}

func (a *IMSOutboundAgent) currentTransport() voiceclient.SIPRequestTransport {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	transport := a.Transport
	a.mu.Unlock()
	return transport
}

func (a *IMSOutboundAgent) writeRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) error {
	transport := a.currentTransport()
	if transport == nil {
		return ErrIMSVoiceAgentNotReady
	}
	return transport.WriteRequest(ctx, msg)
}

func effectiveMediaRelayForLocalIP(base *RTPRelayConfig, localIP string) *RTPRelayConfig {
	if base == nil {
		return nil
	}
	cfg := *base
	if strings.TrimSpace(cfg.IMSListenIP) == "" {
		if ip := net.ParseIP(strings.TrimSpace(localIP)); ip != nil && !ip.IsUnspecified() {
			cfg.IMSListenIP = ip.String()
			cfg.implicitIMSListenIP = true
			if strings.TrimSpace(cfg.IMSAdvertiseIP) == "" {
				cfg.IMSAdvertiseIP = ip.String()
			}
		}
	}
	if !cfg.RTCPReportSchedule.Enabled && cfg.RTCPReportSchedule.Interval == 0 {
		cfg.RTCPReportSchedule = RTPRelayRTCPReportScheduleConfig{
			Enabled:     true,
			Interval:    5 * time.Second,
			Kind:        RTCPReportKindSender,
			ClientToIMS: true,
			IMSToClient: true,
		}
	}
	return &cfg
}

func (a *IMSOutboundAgent) StartOutboundCall(ctx context.Context, req OutboundCallRequest) (OutboundCallResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentTransport() == nil {
		return OutboundCallResult{Accepted: false, Reason: "IMS voice transport unavailable"}, ErrIMSVoiceAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return OutboundCallResult{Accepted: false, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	a.mu.Lock()
	profile := a.Profile
	registration := a.Registration
	userAgent := a.UserAgent
	localTag := a.LocalTag
	sessionExpires := a.SessionExpires
	sessionRefresher := a.SessionRefresher
	remoteTargetURI := a.RemoteTargetURI
	mediaRelay := effectiveMediaRelayForLocalIP(a.MediaRelay, profile.LocalIP)
	a.mu.Unlock()

	remoteURI := a.remoteURI(req.Callee)
	if remoteURI == "" {
		return OutboundCallResult{Accepted: false, Reason: "callee empty"}, errors.New("callee is empty")
	}
	cfg := voiceclient.DialogRequestConfig{
		Profile:          profile,
		Registration:     registration,
		LocalURI:         firstVoiceNonEmpty(registration.PublicIdentity, profile.IMPU),
		ContactURI:       registration.ContactURI,
		RemoteURI:        remoteURI,
		RemoteTargetURI:  firstVoiceNonEmpty(req.RequestURI, remoteTargetURI, remoteURI),
		CallID:           callID,
		LocalTag:         firstVoiceNonEmpty(localTag, randomVoiceSIPTag()),
		CSeq:             1,
		RouteSet:         copyStringSlice(req.RouteSet),
		UserAgent:        firstVoiceNonEmpty(userAgent, profile.UserAgent, "vowifi-go"),
		SessionExpires:   sessionExpires,
		SessionRefresher: normalizeSessionRefresher(sessionRefresher),
		InviteHeaders:    copyVoiceHeaderMap(req.Headers),
	}
	inviteBody := append([]byte(nil), req.RawSDP...)
	localSDPBody := dialogLocalSDPBody(req.RawSDP, req.RemoteSDP)
	var relay *RTPRelaySession
	var srtpNegotiation *outboundSDESRelayNegotiation
	closeRelayOnError := true
	defer func() {
		if closeRelayOnError && relay != nil {
			_ = relay.Close()
		}
	}()
	if mediaRelay != nil {
		createdRelay, relayErr := NewRTPRelaySession(ctx, *mediaRelay, req.RemoteSDP)
		if relayErr != nil {
			return OutboundCallResult{Accepted: false, Reason: "RTP relay setup failed"}, relayErr
		}
		relay = createdRelay
		inviteBody = RewriteSDPMediaEndpoint(req.RawSDP, relay.IMSEndpoint())
		if mediaRelay.SRTP != nil {
			negotiation, err := newOutboundSDESRelayNegotiation(req.RawSDP, *mediaRelay.SRTP)
			if err != nil {
				return OutboundCallResult{Accepted: false, Reason: "RTP relay SRTP negotiation failed"}, err
			}
			srtpNegotiation = negotiation
			inviteBody = srtpNegotiation.RewriteIMSOffer(inviteBody)
		}
	}
	var invite voiceclient.SIPRequestMessage
	var resp voiceclient.SIPResponse
	var err error
	inviteCSeq := cfg.CSeq
	nextCSeq := inviteCSeq + 1
	retriedSessionInterval := false
	digestChallengeRetries := 0
	allowDigestChallengeRetry := true
	redirectRetries := 0
	var pendingInvite *voiceclient.SIPRequestMessage
	var provisionalSDP SDPInfo
	var provisionalAnswer []byte
	for {
		if a.isOutboundCancelRequested(callID) {
			a.deleteDialog(callID)
			return OutboundCallResult{Accepted: false, StatusCode: 487, Reason: "Request Terminated"}, nil
		}
		cfg.CSeq = inviteCSeq
		if pendingInvite != nil {
			invite = *pendingInvite
			pendingInvite = nil
		} else {
			invite, err = voiceclient.BuildInviteRequest(cfg, inviteBody)
			if err != nil {
				return OutboundCallResult{Accepted: false, Reason: "build IMS INVITE failed"}, err
			}
		}
		ensureHeaderOptionTag(invite.Headers, "Supported", "precondition")
		voiceclient.EnsureDialogRequestVia(&invite, cfg)
		a.storeInFlightEarlyDialog(callID, cfg, invite, relay, srtpNegotiation, localSDPBody, nextCSeq)
		provisionalSDP = SDPInfo{}
		provisionalAnswer = nil
		var sentInvite voiceclient.SIPRequestMessage
		resp, sentInvite, err = a.roundTripInvite(ctx, invite, func(provisional voiceclient.SIPResponse) error {
			if provisional.StatusCode < 100 || provisional.StatusCode >= 200 {
				return nil
			}
			var (
				sendDeferredCancel bool
				deferredCancelInfo DialogInfo
				deferredCancelCfg  voiceclient.DialogRequestConfig
				deferredCancelInv  voiceclient.SIPRequestMessage
			)
			a.mu.Lock()
			if latest, ok := a.dialogs[callID]; ok {
				latest.provisionalSeen = true
				if provisional.StatusCode > 100 {
					if tag := sipHeaderTag(firstVoiceHeader(provisional.Headers, "To")); tag != "" {
						latest.cfg.RemoteTag = tag
						cfg.RemoteTag = tag
					}
					if contact := sipHeaderURI(firstVoiceHeader(provisional.Headers, "Contact")); contact != "" {
						latest.cfg.RemoteTargetURI = contact
						cfg.RemoteTargetURI = contact
					}
					if routeSet := recordRouteSet(provisional.Headers); len(routeSet) > 0 {
						latest.cfg.RouteSet = routeSet
						cfg.RouteSet = copyStringSlice(routeSet)
					}
				}
				if latest.cancelRequested && !latest.cancelSent {
					latest.cancelSent = true
					sendDeferredCancel = true
					deferredCancelInfo = cloneDialogInfo(latest.pendingCancel)
					deferredCancelCfg = cloneDialogRequestConfig(latest.cfg)
					deferredCancelCfg.CSeq = inviteCSeq
					deferredCancelInv = cloneSIPRequestMessage(latest.invite)
				}
				a.dialogs[callID] = latest
			}
			a.mu.Unlock()
			if sendDeferredCancel {
				_, _ = a.sendOutboundCancelWire(ctx, callID, deferredCancelCfg, deferredCancelInv, deferredCancelInfo, true)
				return nil
			}
			if provisional.StatusCode <= 100 {
				return nil
			}
			var currentProvBody []byte
			if body, info, ok, err := a.provisionalAnswer(provisional, relay, srtpNegotiation); err != nil {
				return err
			} else if ok {
				currentProvBody = body
				provisionalAnswer = body
				provisionalSDP = info
			}
			if req.OnProvisional != nil {
				req.OnProvisional(OutboundProvisionalResponse{
					StatusCode:  provisional.StatusCode,
					Reason:      provisional.Reason,
					ContentType: firstVoiceHeader(provisional.Headers, "Content-Type"),
					Body:        append([]byte(nil), currentProvBody...),
					Headers:     firstValueSIPHeaders(provisional.Headers),
				})
			}
			rseq := firstVoiceHeader(provisional.Headers, "RSeq")
			if strings.TrimSpace(rseq) == "" || !headerHasToken(provisional.Headers, "Require", "100rel") {
				return nil
			}
			prackCSeq, earlyCfg := a.reserveEarlyDialogCSeq(callID, cfg, &nextCSeq)
			earlyCfg.CSeq = inviteCSeq
			prack, ok, err := buildReliableProvisionalPRACK(earlyCfg, provisional, prackCSeq)
			if err != nil || !ok {
				return err
			}
			prackResp, sentPrack, err := a.roundTripRequestWithResult(ctx, prack)
			if err != nil {
				return fmt.Errorf("IMS PRACK failed: %w", err)
			}
			a.syncSentDialogCSeq(callID, sentPrack, &nextCSeq)
			if prackResp.StatusCode < 200 || prackResp.StatusCode >= 300 {
				return fmt.Errorf("IMS PRACK rejected: %d %s", prackResp.StatusCode, strings.TrimSpace(prackResp.Reason))
			}
			if pre := ParseSDPPreconditions(provisional.Body); pre.Present && !pre.Satisfied() {
				baseOffer := localSDPBody
				if len(baseOffer) == 0 {
					baseOffer = inviteBody
				}
				confirmBody := BuildSDPPreconditionConfirmOffer(baseOffer, provisional.Body)
				localSDPBody = append([]byte(nil), confirmBody...)
				if relay != nil {
					confirmBody = RewriteSDPMediaEndpoint(confirmBody, relay.IMSEndpoint())
					if srtpNegotiation != nil {
						confirmBody, err = srtpNegotiation.RewriteIMSMidDialogOffer(relay, confirmBody)
						if err != nil {
							return fmt.Errorf("IMS precondition UPDATE SRTP offer failed: %w", err)
						}
					}
				}
				updCSeq, updCfg := a.reserveEarlyDialogCSeq(callID, cfg, &nextCSeq)
				updCfg.CSeq = updCSeq
				updCfg.InviteHeaders = nil
				updReq, err := voiceclient.BuildUpdateRequest(updCfg, confirmBody)
				if err != nil {
					return fmt.Errorf("build IMS precondition UPDATE failed: %w", err)
				}
				updResp, sentUpd, err := a.roundTripRequestWithResult(ctx, updReq)
				if err != nil {
					return fmt.Errorf("IMS precondition UPDATE failed: %w", err)
				}
				a.syncSentDialogCSeq(callID, sentUpd, &nextCSeq)
				if updResp.StatusCode < 200 || updResp.StatusCode >= 300 {
					return fmt.Errorf("IMS precondition UPDATE rejected: %d %s", updResp.StatusCode, strings.TrimSpace(updResp.Reason))
				}
				if body, info, ok, err := a.provisionalAnswer(updResp, relay, srtpNegotiation); err != nil {
					return err
				} else if ok {
					provisionalAnswer = body
					provisionalSDP = info
				}
			}
			return nil
		})
		if err != nil {
			a.deleteDialog(callID)
			return OutboundCallResult{Accepted: false, Reason: "IMS INVITE failed", RegistrationRecoveryNeeded: true}, err
		}
		invite = sentInvite
		if sentCSeq := voiceclient.ParseSIPCSeqNumber(sentInvite.Headers["CSeq"]); sentCSeq > 0 {
			inviteCSeq = sentCSeq
			cfg.CSeq = sentCSeq
			if next := outboundNextCSeq(sentCSeq); next > nextCSeq {
				nextCSeq = next
			}
		}
		if a.isOutboundCancelRequested(callID) {
			break
		}
		if isInviteDigestChallenge(resp) && invite.AuthSession != nil && allowDigestChallengeRetry && digestChallengeRetries < 2 {
			retryCfg, retryInvite, retryResult, ok, err := a.buildInviteDigestChallengeRetry(ctx, cfg, invite, resp, nextCSeq, inviteBody)
			if err != nil {
				a.deleteDialog(callID)
				return OutboundCallResult{Accepted: false, Reason: "IMS INVITE digest challenge failed", RegistrationRecoveryNeeded: true}, err
			}
			if ok {
				cfg = retryCfg
				digestChallengeRetries++
				allowDigestChallengeRetry = retryResult.Authorization.SyncFailure
				inviteCSeq = retryCfg.CSeq
				nextCSeq = outboundNextCSeq(inviteCSeq)
				pendingInvite = &retryInvite
				continue
			}
		}
		if resp.StatusCode == 422 && !retriedSessionInterval {
			if retryCfg, ok := retryDialogConfigForMinSE(cfg, invite.Headers, resp.Headers); ok {
				if err := a.ackRejectedInvite(ctx, cfg, invite, resp); err != nil {
					a.deleteDialog(callID)
					return OutboundCallResult{Accepted: false, Reason: "IMS INVITE session interval ACK failed"}, err
				}
				retryCfg.CSeq = nextCSeq
				cfg = retryCfg
				retriedSessionInterval = true
				inviteCSeq = retryCfg.CSeq
				nextCSeq = outboundNextCSeq(inviteCSeq)
				continue
			}
		}
		if redirectRetries < maxIMSInviteRedirects {
			if retryCfg, ok := retryDialogConfigForRedirect(cfg, resp, nextCSeq); ok {
				if err := a.ackRejectedInvite(ctx, cfg, invite, resp); err != nil {
					a.deleteDialog(callID)
					return OutboundCallResult{Accepted: false, Reason: "IMS INVITE redirect ACK failed"}, err
				}
				cfg = retryCfg
				redirectRetries++
				inviteCSeq = retryCfg.CSeq
				nextCSeq = outboundNextCSeq(inviteCSeq)
				continue
			}
		}
		break
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode >= 300 {
			if err := a.ackRejectedInvite(ctx, cfg, invite, resp); err != nil {
				a.deleteDialog(callID)
				return OutboundCallResult{Accepted: false, Reason: "IMS INVITE rejected ACK failed"}, err
			}
		}
		canceled := a.isOutboundCancelRequested(callID)
		a.deleteDialog(callID)
		if canceled {
			return OutboundCallResult{
				Accepted:   false,
				StatusCode: 487,
				Reason:     "Request Terminated",
			}, nil
		}
		return OutboundCallResult{
			Accepted:                   false,
			StatusCode:                 outboundStatusCode(resp.StatusCode, 486),
			Reason:                     firstVoiceNonEmpty(resp.Reason, fmt.Sprintf("IMS rejected call: %d", resp.StatusCode)),
			RegistrationRecoveryNeeded: imsRegistrationRecoveryNeededStatus(resp.StatusCode),
			RetryAfter:                 voiceclient.SIPResponseRetryAfter(resp),
		}, nil
	}
	if routeSet := recordRouteSet(resp.Headers); len(routeSet) > 0 {
		cfg.RouteSet = routeSet
	}
	cfg.RemoteTag = firstVoiceNonEmpty(sipHeaderTag(firstVoiceHeader(resp.Headers, "To")), cfg.RemoteTag)
	if contact := sipHeaderURI(firstVoiceHeader(resp.Headers, "Contact")); contact != "" {
		cfg.RemoteTargetURI = contact
	}
	defaultRefresher := firstVoiceNonEmpty(normalizeSessionRefresher(cfg.SessionRefresher), "uac")
	applyNegotiatedSessionIntervalWithDefault(&cfg, resp.Headers, defaultRefresher)
	cfg.InviteHeaders = nil
	ack, err := voiceclient.BuildAckRequest(cfg)
	if err != nil {
		a.deleteDialog(callID)
		return OutboundCallResult{Accepted: false, Reason: "build IMS ACK failed"}, err
	}
	if err := a.writeRequest(ctx, ack); err != nil {
		a.deleteDialog(callID)
		return OutboundCallResult{Accepted: false, Reason: "IMS ACK failed"}, err
	}
	a.mu.Lock()
	cancelGlare := false
	if latest, ok := a.dialogs[callID]; ok {
		if latest.cfg.CSeq > nextCSeq {
			nextCSeq = latest.cfg.CSeq
		}
		if len(latest.localSDPBody) > 0 {
			localSDPBody = append([]byte(nil), latest.localSDPBody...)
		}
		cancelGlare = latest.cancelRequested || latest.canceled
	}
	a.mu.Unlock()
	if cancelGlare {
		byeCfg := cfg
		byeCfg.CSeq = nextCSeq
		if byeReq, buildErr := voiceclient.BuildByeRequestWithBody(byeCfg, "", nil); buildErr == nil {
			termCtx, cancelTerm := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			_, _, _ = a.roundTripRequestWithResult(termCtx, byeReq)
			cancelTerm()
		}
		a.deleteDialog(callID)
		return OutboundCallResult{
			Accepted:   false,
			StatusCode: 487,
			Reason:     "Request Terminated",
		}, nil
	}
	answerBody := append([]byte(nil), resp.Body...)
	localSDP := provisionalSDP
	if len(answerBody) == 0 {
		answerBody = append([]byte(nil), provisionalAnswer...)
	}
	if len(resp.Body) > 0 {
		parsed, err := ParseSDP(resp.Body)
		if err != nil {
			a.deleteDialog(callID)
			return OutboundCallResult{Accepted: false, Reason: "invalid IMS SDP answer"}, err
		}
		localSDP = parsed
	}
	if relay != nil && len(resp.Body) > 0 {
		if err := relay.SetIMSRemote(localSDP); err != nil {
			a.deleteDialog(callID)
			return OutboundCallResult{Accepted: false, Reason: "RTP relay remote setup failed"}, err
		}
		if srtpNegotiation != nil {
			answerBody, localSDP, err = srtpNegotiation.RewriteClientAnswer(relay, resp.Body, localSDP)
			if err != nil {
				a.deleteDialog(callID)
				return OutboundCallResult{Accepted: false, Reason: "invalid RTP relay SRTP SDP answer"}, err
			}
		} else {
			answerBody = RewriteSDPMediaEndpoint(resp.Body, relay.ClientEndpoint())
			localSDP, err = ParseSDP(answerBody)
			if err != nil {
				a.deleteDialog(callID)
				return OutboundCallResult{Accepted: false, Reason: "invalid RTP relay SDP answer"}, err
			}
		}
	}
	if localSDP.MediaPort <= 0 || strings.TrimSpace(localSDP.ConnectionIP) == "" {
		parsed, err := ParseSDP(answerBody)
		if err != nil {
			a.deleteDialog(callID)
			return OutboundCallResult{Accepted: false, Reason: "invalid IMS SDP answer"}, err
		}
		localSDP = parsed
	}
	byeCfg := cfg
	byeCfg.CSeq = nextCSeq
	var sessionDeadline time.Time
	if byeCfg.SessionExpires > 0 {
		sessionDeadline = time.Now().Add(sessionExpirationTimeout(byeCfg.SessionExpires))
	}
	a.storeDialog(callID, imsDialogState{
		cfg:             byeCfg,
		relay:           relay,
		srtpNegotiation: srtpNegotiation,
		localSDPBody:    localSDPBody,
		sessionDeadline: sessionDeadline,
	})
	a.scheduleDialogSessionRefresh(callID)
	closeRelayOnError = false
	return OutboundCallResult{
		Accepted:   true,
		StatusCode: outboundStatusCode(resp.StatusCode, 200),
		Reason:     firstVoiceNonEmpty(resp.Reason, "OK"),
		LocalSDP:   localSDP,
		RawSDP:     answerBody,
		Headers:    firstValueSIPHeaders(resp.Headers),
	}, nil
}

func (a *IMSOutboundAgent) storeInFlightEarlyDialog(callID string, cfg voiceclient.DialogRequestConfig, invite voiceclient.SIPRequestMessage, relay *RTPRelaySession, srtpNegotiation *outboundSDESRelayNegotiation, localSDPBody []byte, nextCSeq int) {
	if a == nil || strings.TrimSpace(callID) == "" {
		return
	}
	callID = strings.TrimSpace(callID)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dialogs == nil {
		a.dialogs = make(map[string]imsDialogState)
	}
	prev, hadPrev := a.dialogs[callID]
	if hadPrev && prev.refreshTimer != nil {
		prev.refreshTimer.Stop()
	}
	storedCfg := cloneDialogRequestConfig(cfg)
	if nextCSeq > storedCfg.CSeq {
		storedCfg.CSeq = nextCSeq
	}
	state := imsDialogState{
		cfg:             storedCfg,
		invite:          cloneSIPRequestMessage(invite),
		relay:           relay,
		srtpNegotiation: srtpNegotiation,
		localSDPBody:    append([]byte(nil), localSDPBody...),
		early:           true,
		inviteInFlight:  true,
	}
	if hadPrev {
		state.cancelRequested = prev.cancelRequested
		state.canceled = prev.canceled
		state.pendingCancel = cloneDialogInfo(prev.pendingCancel)
	}
	a.dialogs[callID] = state
}

func (a *IMSOutboundAgent) isOutboundCancelRequested(callID string) bool {
	if a == nil || strings.TrimSpace(callID) == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	state, ok := a.dialogs[strings.TrimSpace(callID)]
	return ok && (state.cancelRequested || state.canceled)
}

func (a *IMSOutboundAgent) reserveEarlyDialogCSeq(callID string, fallback voiceclient.DialogRequestConfig, nextCSeq *int) (int, voiceclient.DialogRequestConfig) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cseq := 2
	if nextCSeq != nil && *nextCSeq > cseq {
		cseq = *nextCSeq
	}
	cfg := cloneDialogRequestConfig(fallback)
	if latest, ok := a.dialogs[callID]; ok {
		if latest.cfg.CSeq > cseq {
			cseq = latest.cfg.CSeq
		}
		cfg = cloneDialogRequestConfig(latest.cfg)
		latest.cfg.CSeq = outboundNextCSeq(cseq)
		a.dialogs[callID] = latest
	}
	if nextCSeq != nil {
		*nextCSeq = outboundNextCSeq(cseq)
	}
	return cseq, cfg
}

func (a *IMSOutboundAgent) syncSentDialogCSeq(callID string, sent voiceclient.SIPRequestMessage, nextCSeq *int) {
	sentCSeq := voiceclient.ParseSIPCSeqNumber(sent.Headers["CSeq"])
	if sentCSeq <= 0 {
		return
	}
	after := outboundNextCSeq(sentCSeq)
	if nextCSeq != nil && after > *nextCSeq {
		*nextCSeq = after
	}
	a.mu.Lock()
	if latest, ok := a.dialogs[callID]; ok && after > latest.cfg.CSeq {
		latest.cfg.CSeq = after
		a.dialogs[callID] = latest
	}
	a.mu.Unlock()
}

func (a *IMSOutboundAgent) allocateDialogCSeq(callID string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	latest, ok := a.dialogs[callID]
	if !ok {
		return 2
	}
	cseq := outboundInviteCSeq(latest.cfg.CSeq)
	latest.cfg.CSeq = outboundNextCSeq(cseq)
	a.dialogs[callID] = latest
	return cseq
}

func (a *IMSOutboundAgent) EndVoiceCall(ctx context.Context, info DialogInfo) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentTransport() == nil {
		return ErrIMSVoiceAgentNotReady
	}
	callID := strings.TrimSpace(info.CallID)
	if callID == "" {
		return nil
	}
	if _, ok := a.dialog(callID); !ok {
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

func (a *IMSOutboundAgent) EndVoiceCallWithResult(ctx context.Context, info DialogInfo) (DialogInfoResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentTransport() == nil {
		return DialogInfoResult{Accepted: false, Reason: "IMS voice transport unavailable"}, ErrIMSVoiceAgentNotReady
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
	cfg := cloneDialogRequestConfig(state.cfg)
	bye, err := voiceclient.BuildByeRequestWithBody(cfg, info.ContentType, info.Body)
	if err != nil {
		a.mu.Unlock()
		return DialogInfoResult{Accepted: false, StatusCode: 500, Reason: "build IMS BYE failed"}, err
	}
	applyDialogUpdateHeaders(bye.Headers, info.Headers)
	state.cfg.CSeq = outboundNextCSeq(cfg.CSeq)
	state.terminating = true
	stopDialogSessionRefresh(&state)
	a.dialogs[callID] = state
	relay := state.relay
	a.mu.Unlock()
	resp, sentBye, err := a.roundTripRequestWithResult(ctx, bye)
	a.syncSentDialogCSeq(callID, sentBye, nil)
	if err != nil {
		a.resumeDialogSessionRefreshAfterTerminating(callID)
		return DialogInfoResult{Accepted: false, Reason: "IMS BYE failed", RegistrationRecoveryNeeded: true}, err
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
			if relay != nil {
				_ = relay.Close()
			}
			a.mu.Lock()
			delete(a.dialogs, callID)
			a.mu.Unlock()
			return result, fmt.Errorf("IMS BYE rejected: %d %s", resp.StatusCode, strings.TrimSpace(resp.Reason))
		}
		a.resumeDialogSessionRefreshAfterTerminating(callID)
		return result, fmt.Errorf("IMS BYE rejected: %d %s", resp.StatusCode, strings.TrimSpace(resp.Reason))
	}
	if relay != nil {
		_ = relay.Close()
	}
	a.mu.Lock()
	delete(a.dialogs, callID)
	a.mu.Unlock()
	return result, nil
}

func (a *IMSOutboundAgent) SendDialogInfo(ctx context.Context, req DialogInfoRequest) (DialogInfoResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentTransport() == nil {
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
	cfg := cloneDialogRequestConfig(state.cfg)
	state.cfg.CSeq = outboundNextCSeq(cfg.CSeq)
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
		resp, sent, err = a.roundTripRequestWithResult(ctx, info)
		a.syncSentDialogCSeq(callID, sent, nil)
		if err != nil {
			return DialogInfoResult{Accepted: false, Reason: "IMS INFO failed", RegistrationRecoveryNeeded: true}, err
		}
		if redirectRetries < maxIMSInviteRedirects {
			if target := firstIMSRedirectContactURI(resp); target != "" {
				cfg.RemoteTargetURI = target
				cfg.CSeq = a.allocateDialogCSeq(callID)
				a.storeOutboundDialogTarget(callID, target)
				redirectRetries++
				continue
			}
		}
		break
	}
	accepted := resp.StatusCode >= 200 && resp.StatusCode < 300
	if accepted {
		a.updateOutboundDialogContact(callID, resp.Headers)
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

func (a *IMSOutboundAgent) SendDialogMessage(ctx context.Context, req DialogMessageRequest) (DialogMessageResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentTransport() == nil {
		return DialogMessageResult{Accepted: false, Reason: "IMS voice transport unavailable"}, ErrIMSVoiceAgentNotReady
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
	cfg := cloneDialogRequestConfig(state.cfg)
	state.cfg.CSeq = outboundNextCSeq(cfg.CSeq)
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
		resp, sent, err = a.roundTripRequestWithResult(ctx, msg)
		a.syncSentDialogCSeq(callID, sent, nil)
		if err != nil {
			return DialogMessageResult{Accepted: false, Reason: "IMS MESSAGE failed", RegistrationRecoveryNeeded: true}, err
		}
		if redirectRetries < maxIMSInviteRedirects {
			if target := firstIMSRedirectContactURI(resp); target != "" {
				cfg.RemoteTargetURI = target
				cfg.CSeq = a.allocateDialogCSeq(callID)
				a.storeOutboundDialogTarget(callID, target)
				redirectRetries++
				continue
			}
		}
		break
	}
	accepted := resp.StatusCode >= 200 && resp.StatusCode < 300
	if accepted {
		a.updateOutboundDialogContact(callID, resp.Headers)
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

func (a *IMSOutboundAgent) SendDialogPrack(ctx context.Context, req DialogPrackRequest) (DialogPrackResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentTransport() == nil {
		return DialogPrackResult{Accepted: false, Reason: "IMS voice transport unavailable"}, ErrIMSVoiceAgentNotReady
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
	localSDPBody := append([]byte(nil), req.Body...)
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
			rewritten, err := srtpNeg.RewriteIMSMidDialogOffer(relay, body)
			if err != nil {
				a.mu.Unlock()
				return DialogPrackResult{Accepted: false, StatusCode: 488, Reason: "invalid RTP relay SRTP PRACK SDP"}, err
			}
			body = rewritten
		}
	}
	cfg := cloneDialogRequestConfig(state.cfg)
	state.cfg.CSeq = outboundNextCSeq(cfg.CSeq)
	a.dialogs[callID] = state
	a.mu.Unlock()

	var resp voiceclient.SIPResponse
	redirectRetries := 0
	for {
		prack, err := voiceclient.BuildPrackRequestWithBody(cfg, rack, req.ContentType, body)
		if err != nil {
			return DialogPrackResult{Accepted: false, StatusCode: 500, Reason: "build IMS PRACK failed"}, err
		}
		applyDialogUpdateHeaders(prack.Headers, req.Headers)
		var sent voiceclient.SIPRequestMessage
		resp, sent, err = a.roundTripRequestWithResult(ctx, prack)
		a.syncSentDialogCSeq(callID, sent, nil)
		if err != nil {
			return DialogPrackResult{Accepted: false, Reason: "IMS PRACK failed", RegistrationRecoveryNeeded: true}, err
		}
		if redirectRetries < maxIMSInviteRedirects {
			if target := firstIMSRedirectContactURI(resp); target != "" {
				cfg.RemoteTargetURI = target
				cfg.CSeq = a.allocateDialogCSeq(callID)
				a.storeOutboundDialogTarget(callID, target)
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
			return DialogPrackResult{Accepted: false, StatusCode: 488, Reason: "invalid IMS PRACK SDP answer"}, err
		}
		if err := relay.SetIMSRemote(imsSDP); err != nil {
			return DialogPrackResult{Accepted: false, StatusCode: 503, Reason: "RTP relay IMS PRACK failed"}, err
		}
		if srtpNeg != nil {
			resultBody, _, err = srtpNeg.RewriteClientAnswer(relay, resp.Body, imsSDP)
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
				latest.cfg.RemoteTargetURI = contact
			}
			if len(localSDPBody) > 0 {
				latest.localSDPBody = append([]byte(nil), localSDPBody...)
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

func (a *IMSOutboundAgent) SendDialogOptions(ctx context.Context, req DialogOptionsRequest) (DialogOptionsResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentTransport() == nil {
		return DialogOptionsResult{Accepted: false, Reason: "IMS voice transport unavailable"}, ErrIMSVoiceAgentNotReady
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
	cfg := cloneDialogRequestConfig(state.cfg)
	state.cfg.CSeq = outboundNextCSeq(cfg.CSeq)
	a.dialogs[callID] = state
	a.mu.Unlock()

	var resp voiceclient.SIPResponse
	redirectRetries := 0
	for {
		options, err := voiceclient.BuildOptionsRequest(cfg)
		if err != nil {
			return DialogOptionsResult{Accepted: false, StatusCode: 500, Reason: "build IMS OPTIONS failed"}, err
		}
		applyDialogUpdateHeaders(options.Headers, req.Headers)
		var sent voiceclient.SIPRequestMessage
		resp, sent, err = a.roundTripRequestWithResult(ctx, options)
		a.syncSentDialogCSeq(callID, sent, nil)
		if err != nil {
			return DialogOptionsResult{Accepted: false, Reason: "IMS OPTIONS failed", RegistrationRecoveryNeeded: true}, err
		}
		if redirectRetries < maxIMSInviteRedirects {
			if target := firstIMSRedirectContactURI(resp); target != "" {
				cfg.RemoteTargetURI = target
				cfg.CSeq = a.allocateDialogCSeq(callID)
				a.storeOutboundDialogTarget(callID, target)
				redirectRetries++
				continue
			}
		}
		break
	}
	accepted := resp.StatusCode >= 200 && resp.StatusCode < 300
	if accepted {
		a.updateOutboundDialogContact(callID, resp.Headers)
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

func (a *IMSOutboundAgent) SendDialogRefer(ctx context.Context, req DialogReferRequest) (DialogReferResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentTransport() == nil {
		return DialogReferResult{Accepted: false, Reason: "IMS voice transport unavailable"}, ErrIMSVoiceAgentNotReady
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
	cfg := cloneDialogRequestConfig(state.cfg)
	state.cfg.CSeq = outboundNextCSeq(cfg.CSeq)
	a.dialogs[callID] = state
	a.mu.Unlock()

	var resp voiceclient.SIPResponse
	redirectRetries := 0
	for {
		refer, err := voiceclient.BuildReferRequestWithOptions(cfg, referTo, voiceclient.ReferRequestOptions{
			ReferredBy: req.ReferredBy,
			ReferSub:   effectiveReferSub,
		})
		if err != nil {
			return DialogReferResult{Accepted: false, StatusCode: 500, Reason: "build IMS REFER failed"}, err
		}
		applyDialogUpdateHeaders(refer.Headers, req.Headers)
		refer.Headers["Refer-Sub"] = effectiveReferSub
		var sent voiceclient.SIPRequestMessage
		resp, sent, err = a.roundTripRequestWithResult(ctx, refer)
		a.syncSentDialogCSeq(callID, sent, nil)
		if err != nil {
			return DialogReferResult{Accepted: false, Reason: "IMS REFER failed", RegistrationRecoveryNeeded: true}, err
		}
		if redirectRetries < maxIMSInviteRedirects {
			if target := firstIMSRedirectContactURI(resp); target != "" {
				cfg.RemoteTargetURI = target
				cfg.CSeq = a.allocateDialogCSeq(callID)
				a.storeOutboundDialogTarget(callID, target)
				redirectRetries++
				continue
			}
		}
		break
	}
	accepted := resp.StatusCode >= 200 && resp.StatusCode < 300
	if accepted {
		a.updateOutboundDialogContact(callID, resp.Headers)
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

func (a *IMSOutboundAgent) SendDialogNotify(ctx context.Context, req DialogNotifyRequest) (DialogNotifyResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentTransport() == nil {
		return DialogNotifyResult{Accepted: false, Reason: "IMS voice transport unavailable"}, ErrIMSVoiceAgentNotReady
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
	cfg := cloneDialogRequestConfig(state.cfg)
	state.cfg.CSeq = outboundNextCSeq(cfg.CSeq)
	a.dialogs[callID] = state
	a.mu.Unlock()

	var resp voiceclient.SIPResponse
	redirectRetries := 0
	for {
		notify, err := voiceclient.BuildNotifyRequest(cfg, event, subscriptionState, req.ContentType, req.Body)
		if err != nil {
			return DialogNotifyResult{Accepted: false, StatusCode: 500, Reason: "build IMS NOTIFY failed"}, err
		}
		applyDialogUpdateHeaders(notify.Headers, req.Headers)
		var sent voiceclient.SIPRequestMessage
		resp, sent, err = a.roundTripRequestWithResult(ctx, notify)
		a.syncSentDialogCSeq(callID, sent, nil)
		if err != nil {
			return DialogNotifyResult{Accepted: false, Reason: "IMS NOTIFY failed", RegistrationRecoveryNeeded: true}, err
		}
		if redirectRetries < maxIMSInviteRedirects {
			if target := firstIMSRedirectContactURI(resp); target != "" {
				cfg.RemoteTargetURI = target
				cfg.CSeq = a.allocateDialogCSeq(callID)
				a.storeOutboundDialogTarget(callID, target)
				redirectRetries++
				continue
			}
		}
		break
	}
	accepted := resp.StatusCode >= 200 && resp.StatusCode < 300
	if accepted {
		a.updateOutboundDialogContact(callID, resp.Headers)
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

func (a *IMSOutboundAgent) SendDialogSubscribe(ctx context.Context, req DialogSubscribeRequest) (DialogSubscribeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentTransport() == nil {
		return DialogSubscribeResult{Accepted: false, Reason: "IMS voice transport unavailable"}, ErrIMSVoiceAgentNotReady
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
	cfg := cloneDialogRequestConfig(state.cfg)
	state.cfg.CSeq = outboundNextCSeq(cfg.CSeq)
	a.dialogs[callID] = state
	a.mu.Unlock()

	var resp voiceclient.SIPResponse
	redirectRetries := 0
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
		resp, sent, err = a.roundTripRequestWithResult(ctx, subscribe)
		a.syncSentDialogCSeq(callID, sent, nil)
		if err != nil {
			return DialogSubscribeResult{Accepted: false, Reason: "IMS SUBSCRIBE failed", RegistrationRecoveryNeeded: true}, err
		}
		if resp.StatusCode == 423 && !retriedMinExpires {
			if retryCfg, retryExpires, ok := retryDialogConfigForMinExpires(cfg, subscribe.Headers, resp.Headers); ok {
				retryCfg.CSeq = a.allocateDialogCSeq(callID)
				cfg = retryCfg
				subscribeExpires = retryExpires
				a.storeOutboundDialogTarget(callID, cfg.RemoteTargetURI)
				retriedMinExpires = true
				continue
			}
		}
		if redirectRetries < maxIMSInviteRedirects {
			if target := firstIMSRedirectContactURI(resp); target != "" {
				cfg.RemoteTargetURI = target
				cfg.CSeq = a.allocateDialogCSeq(callID)
				a.storeOutboundDialogTarget(callID, target)
				redirectRetries++
				continue
			}
		}
		break
	}
	accepted := resp.StatusCode >= 200 && resp.StatusCode < 300
	if accepted {
		a.updateOutboundDialogContact(callID, resp.Headers)
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

func (a *IMSOutboundAgent) SendDialogUpdate(ctx context.Context, req DialogUpdateRequest) (DialogUpdateResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentTransport() == nil {
		return DialogUpdateResult{Accepted: false, Reason: "IMS voice transport unavailable"}, ErrIMSVoiceAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return DialogUpdateResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	body := append([]byte(nil), req.Body...)
	localSDPBody := append([]byte(nil), req.Body...)
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return DialogUpdateResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	if state.terminating {
		a.mu.Unlock()
		return DialogUpdateResult{Accepted: false, StatusCode: 481, Reason: "dialog terminating"}, nil
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
			rewritten, err := srtpNeg.RewriteIMSMidDialogOffer(relay, body)
			if err != nil {
				a.mu.Unlock()
				return DialogUpdateResult{Accepted: false, StatusCode: 488, Reason: "invalid RTP relay SRTP UPDATE SDP"}, err
			}
			body = rewritten
		}
	}
	cfg := cloneDialogRequestConfig(state.cfg)
	state.cfg.CSeq = outboundNextCSeq(cfg.CSeq)
	a.dialogs[callID] = state
	a.mu.Unlock()

	buildUpdate := func(sendCfg voiceclient.DialogRequestConfig, forceSessionHeaders bool) (voiceclient.SIPRequestMessage, error) {
		update, err := voiceclient.BuildUpdateRequest(sendCfg, body)
		if err != nil {
			return voiceclient.SIPRequestMessage{}, err
		}
		if len(body) > 0 && strings.TrimSpace(req.ContentType) != "" {
			update.Headers["Content-Type"] = strings.TrimSpace(req.ContentType)
		}
		applyDialogUpdateHeaders(update.Headers, req.Headers)
		if forceSessionHeaders {
			applySessionIntervalHeaders(update.Headers, sendCfg)
			if sendCfg.MinSE > 0 {
				update.Headers["Min-SE"] = strconv.Itoa(sendCfg.MinSE)
			}
		}
		return update, nil
	}
	storeSessionFields := func(sendCfg voiceclient.DialogRequestConfig) {
		a.mu.Lock()
		if latest, ok := a.dialogs[callID]; ok {
			latest.cfg.RemoteTargetURI = sendCfg.RemoteTargetURI
			latest.cfg.SessionExpires = sendCfg.SessionExpires
			latest.cfg.SessionRefresher = sendCfg.SessionRefresher
			latest.cfg.MinSE = sendCfg.MinSE
			a.dialogs[callID] = latest
		}
		a.mu.Unlock()
	}

	var update voiceclient.SIPRequestMessage
	var resp voiceclient.SIPResponse
	var err error
	retriedSessionInterval := false
	forceSessionHeaders := false
	redirectRetries := 0
	glareRetries := 0
	for {
		update, err = buildUpdate(cfg, forceSessionHeaders)
		if err != nil {
			return DialogUpdateResult{Accepted: false, StatusCode: 500, Reason: "build IMS UPDATE failed"}, err
		}
		storeSessionFields(cfg)
		var sent voiceclient.SIPRequestMessage
		resp, sent, err = a.roundTripRequestWithResult(ctx, update)
		a.syncSentDialogCSeq(callID, sent, nil)
		if err != nil {
			return DialogUpdateResult{Accepted: false, Reason: "IMS UPDATE failed", RegistrationRecoveryNeeded: true}, err
		}
		if resp.StatusCode == 422 && !retriedSessionInterval {
			if retryCfg, ok := retryDialogConfigForMinSE(cfg, update.Headers, resp.Headers); ok {
				retryCfg.CSeq = a.allocateDialogCSeq(callID)
				cfg = retryCfg
				retriedSessionInterval = true
				forceSessionHeaders = true
				continue
			}
		}
		if glareRetries < maxIMSDialogGlareRetries {
			if retryCfg, delay, ok := retryDialogConfigForGlare(cfg, resp, 0); ok {
				if err := waitForIMSDialogRetry(ctx, delay); err != nil {
					return DialogUpdateResult{
						Accepted:                   false,
						StatusCode:                 outboundStatusCode(resp.StatusCode, 500),
						Reason:                     firstVoiceNonEmpty(resp.Reason, "IMS UPDATE retry canceled"),
						RegistrationRecoveryNeeded: imsRegistrationRecoveryNeededStatus(resp.StatusCode),
						RetryAfter:                 voiceclient.SIPResponseRetryAfter(resp),
						ContentType:                firstVoiceHeader(resp.Headers, "Content-Type"),
						Body:                       append([]byte(nil), resp.Body...),
						Headers:                    firstValueSIPHeaders(resp.Headers),
					}, err
				}
				retryCfg.CSeq = a.allocateDialogCSeq(callID)
				cfg = retryCfg
				glareRetries++
				continue
			}
		}
		if redirectRetries < maxIMSInviteRedirects {
			if target := firstIMSRedirectContactURI(resp); target != "" {
				cfg.RemoteTargetURI = target
				cfg.CSeq = a.allocateDialogCSeq(callID)
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
			resultBody, _, err = srtpNeg.RewriteClientAnswer(relay, resp.Body, imsSDP)
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
				latest.cfg.RemoteTargetURI = contact
			}
			if len(localSDPBody) > 0 {
				latest.localSDPBody = append([]byte(nil), localSDPBody...)
			}
			defaultRef := firstVoiceNonEmpty(normalizeSessionRefresher(latest.cfg.SessionRefresher), "uac")
			applyNegotiatedSessionIntervalWithDefault(&latest.cfg, resp.Headers, defaultRef)
			if latest.cfg.SessionExpires > 0 {
				latest.sessionDeadline = time.Now().Add(sessionExpirationTimeout(latest.cfg.SessionExpires))
			} else {
				latest.sessionDeadline = time.Time{}
			}
			a.dialogs[callID] = latest
		}
		a.mu.Unlock()
		a.scheduleDialogSessionRefresh(callID)
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

func (a *IMSOutboundAgent) SendDialogHold(ctx context.Context, req DialogHoldRequest) (DialogUpdateResult, error) {
	direction := strings.TrimSpace(req.Direction)
	if direction == "" {
		direction = "sendonly"
	}
	return a.sendDialogDirectionUpdate(ctx, req.CallID, direction, firstVoiceNonEmpty(req.ContentType, "application/sdp"), req.Headers)
}

func (a *IMSOutboundAgent) SendDialogResume(ctx context.Context, req DialogResumeRequest) (DialogUpdateResult, error) {
	return a.sendDialogDirectionUpdate(ctx, req.CallID, "sendrecv", firstVoiceNonEmpty(req.ContentType, "application/sdp"), req.Headers)
}

func (a *IMSOutboundAgent) SendDialogReinvite(ctx context.Context, req DialogReinviteRequest) (DialogReinviteResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentTransport() == nil {
		return DialogReinviteResult{Accepted: false, Reason: "IMS voice transport unavailable"}, ErrIMSVoiceAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return DialogReinviteResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	body := append([]byte(nil), req.Body...)
	localSDPBody := append([]byte(nil), req.Body...)
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return DialogReinviteResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	relay := state.relay
	srtpNeg := state.srtpNegotiation
	cfg := cloneDialogRequestConfig(state.cfg)
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
			rewritten, err := srtpNeg.RewriteIMSMidDialogOffer(relay, body)
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
	state.cfg.CSeq = nextCSeq
	a.dialogs[callID] = state
	a.mu.Unlock()
	activeCfg := cfg
	activeInvite := invite
	sendReinvite := func(sendCfg voiceclient.DialogRequestConfig, sendInvite voiceclient.SIPRequestMessage, label string) (voiceclient.SIPResponse, voiceclient.SIPRequestMessage, error) {
		voiceclient.EnsureDialogRequestVia(&sendInvite, sendCfg)
		return a.roundTripInvite(ctx, sendInvite, func(provisional voiceclient.SIPResponse) error {
			rseq := firstVoiceHeader(provisional.Headers, "RSeq")
			if strings.TrimSpace(rseq) == "" || !headerHasToken(provisional.Headers, "Require", "100rel") || provisional.StatusCode <= 100 || provisional.StatusCode >= 200 {
				return nil
			}
			prackCSeq := a.allocateDialogCSeq(callID)
			if outboundNextCSeq(prackCSeq) > nextCSeq {
				nextCSeq = outboundNextCSeq(prackCSeq)
			}
			prack, ok, err := buildReliableProvisionalPRACK(sendCfg, provisional, prackCSeq)
			if err != nil || !ok {
				return err
			}
			prackResp, sentPrack, err := a.roundTripRequestWithResult(ctx, prack)
			if err != nil {
				return fmt.Errorf("%s PRACK failed: %w", label, err)
			}
			a.syncSentDialogCSeq(callID, sentPrack, &nextCSeq)
			if prackResp.StatusCode < 200 || prackResp.StatusCode >= 300 {
				return fmt.Errorf("%s PRACK rejected: %d %s", label, prackResp.StatusCode, strings.TrimSpace(prackResp.Reason))
			}
			return nil
		})
	}
	resp, sentInvite, err := sendReinvite(cfg, invite, "IMS re-INVITE")
	if err != nil {
		return DialogReinviteResult{Accepted: false, Reason: "IMS re-INVITE failed", RegistrationRecoveryNeeded: true}, err
	}
	syncSentInvite := func(sent voiceclient.SIPRequestMessage) {
		activeInvite = sent
		invite = sent
		if sentCSeq := voiceclient.ParseSIPCSeqNumber(sent.Headers["CSeq"]); sentCSeq > 0 {
			cfg.CSeq = sentCSeq
			activeCfg.CSeq = sentCSeq
			if after := outboundNextCSeq(sentCSeq); after > nextCSeq {
				nextCSeq = after
			}
			a.syncSentDialogCSeq(callID, sent, &nextCSeq)
		}
	}
	syncSentInvite(sentInvite)
	digestChallengeRetries := 0
	allowDigestChallengeRetry := true
	retriedSessionInterval := false
	redirectRetries := 0
	glareRetries := 0
	for {
		if isInviteDigestChallenge(resp) && invite.AuthSession != nil && allowDigestChallengeRetry && digestChallengeRetries < 2 {
			cseqForRetry := a.allocateDialogCSeq(callID)
			retryCfg, retryInvite, retryResult, ok, err := a.buildInviteDigestChallengeRetry(ctx, cfg, invite, resp, cseqForRetry, body)
			if err != nil {
				return DialogReinviteResult{Accepted: false, StatusCode: 500, Reason: "IMS re-INVITE digest challenge failed"}, err
			}
			if !ok {
				break
			}
			if len(body) > 0 && strings.TrimSpace(req.ContentType) != "" {
				retryInvite.Headers["Content-Type"] = strings.TrimSpace(req.ContentType)
			}
			applyDialogUpdateHeaders(retryInvite.Headers, req.Headers)
			voiceclient.EnsureDialogRequestVia(&retryInvite, retryCfg)
			cfg = retryCfg
			invite = retryInvite
			activeCfg = retryCfg
			activeInvite = retryInvite
			nextCSeq = outboundNextCSeq(retryCfg.CSeq)
			digestChallengeRetries++
			allowDigestChallengeRetry = retryResult.Authorization.SyncFailure
			resp, sentInvite, err = sendReinvite(retryCfg, retryInvite, "IMS re-INVITE digest retry")
			if err != nil {
				return DialogReinviteResult{Accepted: false, Reason: "IMS re-INVITE digest retry failed", RegistrationRecoveryNeeded: true}, err
			}
			syncSentInvite(sentInvite)
			continue
		}
		if resp.StatusCode == 422 && !retriedSessionInterval {
			retryCfg, ok := retryDialogConfigForMinSE(cfg, invite.Headers, resp.Headers)
			if !ok {
				break
			}
			if err := a.ackRejectedInvite(ctx, cfg, invite, resp); err != nil {
				return DialogReinviteResult{Accepted: false, StatusCode: 500, Reason: "IMS re-INVITE session interval ACK failed"}, err
			}
			retryCfg.CSeq = a.allocateDialogCSeq(callID)
			retryInvite, err := voiceclient.BuildInviteRequest(retryCfg, body)
			if err != nil {
				return DialogReinviteResult{Accepted: false, StatusCode: 500, Reason: "build IMS re-INVITE retry failed"}, err
			}
			if len(body) > 0 && strings.TrimSpace(req.ContentType) != "" {
				retryInvite.Headers["Content-Type"] = strings.TrimSpace(req.ContentType)
			}
			applyDialogUpdateHeaders(retryInvite.Headers, req.Headers)
			applySessionIntervalHeaders(retryInvite.Headers, retryCfg)
			voiceclient.EnsureDialogRequestVia(&retryInvite, retryCfg)
			cfg = retryCfg
			invite = retryInvite
			activeCfg = retryCfg
			activeInvite = retryInvite
			nextCSeq = outboundNextCSeq(retryCfg.CSeq)
			retriedSessionInterval = true
			a.mu.Lock()
			if latest, ok := a.dialogs[callID]; ok {
				latest.cfg.SessionExpires = retryCfg.SessionExpires
				latest.cfg.SessionRefresher = retryCfg.SessionRefresher
				latest.cfg.MinSE = retryCfg.MinSE
				a.dialogs[callID] = latest
			}
			a.mu.Unlock()
			resp, sentInvite, err = sendReinvite(retryCfg, retryInvite, "IMS re-INVITE retry")
			if err != nil {
				return DialogReinviteResult{Accepted: false, Reason: "IMS re-INVITE retry failed", RegistrationRecoveryNeeded: true}, err
			}
			syncSentInvite(sentInvite)
			continue
		}
		if glareRetries < maxIMSDialogGlareRetries {
			retryCfg, delay, ok := retryDialogConfigForGlare(cfg, resp, 0)
			if ok {
				if err := a.ackRejectedInvite(ctx, cfg, invite, resp); err != nil {
					return DialogReinviteResult{Accepted: false, StatusCode: 500, Reason: "IMS re-INVITE glare ACK failed"}, err
				}
				if err := waitForIMSDialogRetry(ctx, delay); err != nil {
					return DialogReinviteResult{
						Accepted:                   false,
						StatusCode:                 outboundStatusCode(resp.StatusCode, 488),
						Reason:                     firstVoiceNonEmpty(resp.Reason, "IMS re-INVITE retry canceled"),
						RegistrationRecoveryNeeded: imsRegistrationRecoveryNeededStatus(resp.StatusCode),
						RetryAfter:                 voiceclient.SIPResponseRetryAfter(resp),
						ContentType:                firstVoiceHeader(resp.Headers, "Content-Type"),
						Body:                       append([]byte(nil), resp.Body...),
						Headers:                    firstValueSIPHeaders(resp.Headers),
					}, err
				}
				retryCfg.CSeq = a.allocateDialogCSeq(callID)
				retryInvite, err := voiceclient.BuildInviteRequest(retryCfg, body)
				if err != nil {
					return DialogReinviteResult{Accepted: false, StatusCode: 500, Reason: "build IMS re-INVITE glare retry failed"}, err
				}
				if len(body) > 0 && strings.TrimSpace(req.ContentType) != "" {
					retryInvite.Headers["Content-Type"] = strings.TrimSpace(req.ContentType)
				}
				applyDialogUpdateHeaders(retryInvite.Headers, req.Headers)
				voiceclient.EnsureDialogRequestVia(&retryInvite, retryCfg)
				cfg = retryCfg
				invite = retryInvite
				activeCfg = retryCfg
				activeInvite = retryInvite
				nextCSeq = outboundNextCSeq(retryCfg.CSeq)
				glareRetries++
				resp, sentInvite, err = sendReinvite(retryCfg, retryInvite, "IMS re-INVITE glare retry")
				if err != nil {
					return DialogReinviteResult{Accepted: false, Reason: "IMS re-INVITE glare retry failed", RegistrationRecoveryNeeded: true}, err
				}
				syncSentInvite(sentInvite)
				continue
			}
		}
		if redirectRetries < maxIMSInviteRedirects {
			retryCfg, ok := retryDialogConfigForRedirect(cfg, resp, 0)
			if !ok {
				break
			}
			if err := a.ackRejectedInvite(ctx, cfg, invite, resp); err != nil {
				return DialogReinviteResult{Accepted: false, StatusCode: 500, Reason: "IMS re-INVITE redirect ACK failed"}, err
			}
			retryCfg.CSeq = a.allocateDialogCSeq(callID)
			retryInvite, err := voiceclient.BuildInviteRequest(retryCfg, body)
			if err != nil {
				return DialogReinviteResult{Accepted: false, StatusCode: 500, Reason: "build IMS re-INVITE redirect failed"}, err
			}
			if len(body) > 0 && strings.TrimSpace(req.ContentType) != "" {
				retryInvite.Headers["Content-Type"] = strings.TrimSpace(req.ContentType)
			}
			applyDialogUpdateHeaders(retryInvite.Headers, req.Headers)
			voiceclient.EnsureDialogRequestVia(&retryInvite, retryCfg)
			cfg = retryCfg
			invite = retryInvite
			activeCfg = retryCfg
			activeInvite = retryInvite
			nextCSeq = outboundNextCSeq(retryCfg.CSeq)
			redirectRetries++
			a.storeOutboundDialogTarget(callID, retryCfg.RemoteTargetURI)
			resp, sentInvite, err = sendReinvite(retryCfg, retryInvite, "IMS re-INVITE redirect")
			if err != nil {
				return DialogReinviteResult{Accepted: false, Reason: "IMS re-INVITE redirect failed", RegistrationRecoveryNeeded: true}, err
			}
			syncSentInvite(sentInvite)
			continue
		}
		break
	}
	accepted := resp.StatusCode >= 200 && resp.StatusCode < 300
	if !accepted {
		if resp.StatusCode >= 300 {
			if err := a.ackRejectedInvite(ctx, activeCfg, activeInvite, resp); err != nil {
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
			if latest, ok := a.dialogs[callID]; ok && len(latest.localSDPBody) > 0 {
				ackBody = append([]byte(nil), latest.localSDPBody...)
			}
			a.mu.Unlock()
			if len(ackBody) > 0 && relay != nil {
				ackBody = RewriteSDPMediaEndpoint(ackBody, relay.IMSEndpoint())
				if srtpNeg != nil {
					if rewritten, rwErr := srtpNeg.RewriteIMSMidDialogAnswer(relay, resp.Body, ackBody); rwErr == nil {
						ackBody = rewritten
					}
				}
			}
		}
		ack, err := buildDialogAckWithOptionalSDP(ackCfg, ackBody)
		if err != nil {
			return DialogReinviteResult{Accepted: false, StatusCode: 500, Reason: "build IMS re-INVITE ACK failed"}, err
		}
		if err := a.writeRequest(ctx, ack); err != nil {
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
			resultBody, _, err = srtpNeg.RewriteClientAnswer(relay, resp.Body, imsSDP)
			if err != nil {
				return DialogReinviteResult{Accepted: false, StatusCode: 488, Reason: "invalid RTP relay SRTP re-INVITE SDP answer"}, err
			}
		} else {
			resultBody = RewriteSDPMediaEndpoint(resultBody, relay.ClientEndpoint())
		}
	}
	a.mu.Lock()
	if latest, ok := a.dialogs[callID]; ok {
		if ackCfg.RemoteTargetURI != cfg.RemoteTargetURI || ackCfg.RemoteTag != cfg.RemoteTag {
			latest.cfg.RemoteTargetURI = ackCfg.RemoteTargetURI
			latest.cfg.RemoteTag = ackCfg.RemoteTag
		}
		if nextCSeq > latest.cfg.CSeq {
			latest.cfg.CSeq = nextCSeq
		}
		if len(localSDPBody) > 0 {
			latest.localSDPBody = append([]byte(nil), localSDPBody...)
		}
		if deferAck {
			latest.pendingAckCfg = cloneDialogRequestConfig(ackCfg)
			latest.hasPendingAck = true
		} else {
			latest.hasPendingAck = false
		}
		defaultRef := firstVoiceNonEmpty(normalizeSessionRefresher(latest.cfg.SessionRefresher), "uac")
		applyNegotiatedSessionIntervalWithDefault(&latest.cfg, resp.Headers, defaultRef)
		if latest.cfg.SessionExpires > 0 {
			latest.sessionDeadline = time.Now().Add(sessionExpirationTimeout(latest.cfg.SessionExpires))
		} else {
			latest.sessionDeadline = time.Time{}
		}
		a.dialogs[callID] = latest
	}
	a.mu.Unlock()
	a.scheduleDialogSessionRefresh(callID)
	return DialogReinviteResult{
		Accepted:    true,
		StatusCode:  outboundStatusCode(resp.StatusCode, 200),
		Reason:      firstVoiceNonEmpty(resp.Reason, "OK"),
		ContentType: firstVoiceHeader(resp.Headers, "Content-Type"),
		Body:        resultBody,
		Headers:     firstValueSIPHeaders(resp.Headers),
	}, nil
}

func (a *IMSOutboundAgent) AckDialog(ctx context.Context, req DialogAckRequest) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentTransport() == nil {
		return ErrIMSVoiceAgentNotReady
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return nil
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok || !state.hasPendingAck {
		a.mu.Unlock()
		return nil
	}
	ackCfg := cloneDialogRequestConfig(state.pendingAckCfg)
	relay := state.relay
	srtpNeg := state.srtpNegotiation
	state.hasPendingAck = false
	if len(req.Body) > 0 {
		state.localSDPBody = append([]byte(nil), req.Body...)
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
			ackBody, err = srtpNeg.RewriteIMSMidDialogOffer(relay, ackBody)
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
	return a.writeRequest(ctx, ack)
}

func buildDialogAckWithOptionalSDP(cfg voiceclient.DialogRequestConfig, sdpBody []byte) (voiceclient.SIPRequestMessage, error) {
	ack, err := voiceclient.BuildAckRequest(cfg)
	if err != nil {
		return voiceclient.SIPRequestMessage{}, err
	}
	if len(sdpBody) > 0 {
		ack.Body = append([]byte(nil), sdpBody...)
		ack.Headers["Content-Type"] = "application/sdp"
		ack.Headers["Content-Length"] = strconv.Itoa(len(ack.Body))
	}
	return ack, nil
}

func (a *IMSOutboundAgent) sendDialogDirectionUpdate(ctx context.Context, callID, direction, contentType string, headers map[string]string) (DialogUpdateResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentTransport() == nil {
		return DialogUpdateResult{Accepted: false, Reason: "IMS voice transport unavailable"}, ErrIMSVoiceAgentNotReady
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
	body := append([]byte(nil), state.localSDPBody...)
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

func (a *IMSOutboundAgent) ackRejectedInvite(ctx context.Context, cfg voiceclient.DialogRequestConfig, invite voiceclient.SIPRequestMessage, resp voiceclient.SIPResponse) error {
	if strings.TrimSpace(invite.URI) != "" && len(invite.Headers) > 0 {
		if ack, err := voiceclient.BuildNon2xxInviteAck(invite, resp); err == nil {
			return a.writeRequest(ctx, ack)
		}
	}
	ackCfg := cfg
	ackCfg.RemoteTag = firstVoiceNonEmpty(sipHeaderTag(firstVoiceHeader(resp.Headers, "To")), cfg.RemoteTag)
	ack, err := voiceclient.BuildAckRequest(ackCfg)
	if err != nil {
		return err
	}
	copyDialogHeader(ack.Headers, invite.Headers, "Via")
	return a.writeRequest(ctx, ack)
}

func (a *IMSOutboundAgent) buildInviteDigestChallengeRetry(ctx context.Context, cfg voiceclient.DialogRequestConfig, invite voiceclient.SIPRequestMessage, resp voiceclient.SIPResponse, cseq int, body []byte) (voiceclient.DialogRequestConfig, voiceclient.SIPRequestMessage, voiceclient.DigestChallengeRetryResult, bool, error) {
	if invite.AuthSession == nil || !isInviteDigestChallenge(resp) {
		return voiceclient.DialogRequestConfig{}, voiceclient.SIPRequestMessage{}, voiceclient.DigestChallengeRetryResult{}, false, nil
	}
	if err := a.ackRejectedInvite(ctx, cfg, invite, resp); err != nil {
		return voiceclient.DialogRequestConfig{}, voiceclient.SIPRequestMessage{}, voiceclient.DigestChallengeRetryResult{}, false, err
	}
	authz, ok, err := invite.AuthSession.AuthorizeChallengeWithResult(resp, "INVITE", invite.URI, invite.Body)
	if err != nil || !ok {
		return voiceclient.DialogRequestConfig{}, voiceclient.SIPRequestMessage{}, voiceclient.DigestChallengeRetryResult{Authorization: authz}, false, err
	}
	retryCfg := cfg
	retryCfg.CSeq = cseq
	wireCfg := retryCfg
	wireCfg.AuthSession = nil
	wireCfg.AuthHeaderName = authz.HeaderName
	wireCfg.AuthHeader = authz.Header
	wireCfg.Registration.AuthSession = nil
	retryInvite, err := voiceclient.BuildInviteRequest(wireCfg, body)
	if err != nil {
		return voiceclient.DialogRequestConfig{}, voiceclient.SIPRequestMessage{}, voiceclient.DigestChallengeRetryResult{Authorization: authz}, false, err
	}
	ensureHeaderOptionTag(retryInvite.Headers, "Supported", "precondition")
	voiceclient.EnsureDialogRequestVia(&retryInvite, retryCfg)
	retryInvite.AuthSession = invite.AuthSession
	return retryCfg, retryInvite, voiceclient.DigestChallengeRetryResult{Authorization: authz}, true, nil
}

const maxIMSInviteRedirects = 4
const maxIMSDialogGlareRetries = 1
const defaultIMSDialogGlareRetryDelay = 500 * time.Millisecond

func retryDialogConfigForRedirect(cfg voiceclient.DialogRequestConfig, resp voiceclient.SIPResponse, cseq int) (voiceclient.DialogRequestConfig, bool) {
	target := firstIMSRedirectContactURI(resp)
	if target == "" {
		return voiceclient.DialogRequestConfig{}, false
	}
	retryCfg := cfg
	retryCfg.RemoteTargetURI = target
	retryCfg.CSeq = cseq
	return retryCfg, true
}

func retryDialogConfigForGlare(cfg voiceclient.DialogRequestConfig, resp voiceclient.SIPResponse, cseq int) (voiceclient.DialogRequestConfig, time.Duration, bool) {
	if !isDialogGlareRetryResponse(resp) {
		return voiceclient.DialogRequestConfig{}, 0, false
	}
	retryCfg := cfg
	retryCfg.CSeq = cseq
	return retryCfg, imsDialogGlareRetryDelay(resp), true
}

func isDialogGlareRetryResponse(resp voiceclient.SIPResponse) bool {
	switch resp.StatusCode {
	case 491:
		return true
	case 500:
		return hasVoiceHeader(resp.Headers, "Retry-After")
	default:
		return false
	}
}

func imsDialogGlareRetryDelay(resp voiceclient.SIPResponse) time.Duration {
	delay := voiceclient.SIPResponseRetryAfter(resp)
	if delay > 0 {
		return delay
	}
	if resp.StatusCode == 491 && !hasVoiceHeader(resp.Headers, "Retry-After") {
		return defaultIMSDialogGlareRetryDelay
	}
	return 0
}

func waitForIMSDialogRetry(ctx context.Context, delay time.Duration) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func hasVoiceHeader(headers map[string][]string, name string) bool {
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				return true
			}
		}
	}
	return false
}

func firstIMSRedirectContactURI(resp voiceclient.SIPResponse) string {
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return ""
	}
	for _, uri := range imsRedirectContactURIs(resp.Headers) {
		return uri
	}
	return ""
}

func imsRedirectContactURIs(headers map[string][]string) []string {
	var out []string
	for key, values := range headers {
		if !strings.EqualFold(key, "Contact") {
			continue
		}
		for _, value := range values {
			for _, contact := range splitVoiceHeaderValues(value) {
				uri := sipHeaderURI(contact)
				if !isSIPRedirectTargetURI(uri) {
					continue
				}
				duplicate := false
				for _, existing := range out {
					if existing == uri {
						duplicate = true
						break
					}
				}
				if !duplicate {
					out = append(out, uri)
				}
			}
		}
	}
	return out
}

func isSIPRedirectTargetURI(uri string) bool {
	uri = strings.TrimSpace(uri)
	if uri == "" || uri == "*" {
		return false
	}
	lower := strings.ToLower(uri)
	return strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:")
}

func isInviteDigestChallenge(resp voiceclient.SIPResponse) bool {
	return resp.StatusCode == 401 || resp.StatusCode == 407
}

func dialogLocalSDPBody(raw []byte, info SDPInfo) []byte {
	if len(raw) > 0 {
		return append([]byte(nil), raw...)
	}
	if strings.TrimSpace(info.ConnectionIP) == "" && info.MediaPort <= 0 && len(info.Payloads) == 0 {
		return nil
	}
	return BuildSDPAnswer(info)
}

func (a *IMSOutboundAgent) CancelVoiceCall(ctx context.Context, info DialogInfo) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentTransport() == nil {
		return ErrIMSVoiceAgentNotReady
	}
	callID := strings.TrimSpace(info.CallID)
	if callID == "" {
		return nil
	}
	state, ok := a.dialog(callID)
	if !ok || !state.early {
		return nil
	}
	result, err := a.CancelVoiceCallWithResult(ctx, info)
	if err != nil {
		return err
	}
	if result.StatusCode > 0 && (result.StatusCode < 200 || result.StatusCode >= 300) {
		return fmt.Errorf("IMS CANCEL rejected: %d %s", result.StatusCode, strings.TrimSpace(result.Reason))
	}
	return nil
}

func (a *IMSOutboundAgent) CancelVoiceCallWithResult(ctx context.Context, info DialogInfo) (DialogInfoResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.currentTransport() == nil {
		return DialogInfoResult{Accepted: false, Reason: "IMS voice transport unavailable"}, ErrIMSVoiceAgentNotReady
	}
	callID := strings.TrimSpace(info.CallID)
	if callID == "" {
		return DialogInfoResult{Accepted: false, StatusCode: 400, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok || !state.early {
		a.mu.Unlock()
		return DialogInfoResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}
	if state.canceled {
		a.mu.Unlock()
		return DialogInfoResult{Accepted: true, StatusCode: 200, Reason: "OK"}, nil
	}
	if state.inviteInFlight && !state.provisionalSeen {
		state.cancelRequested = true
		state.pendingCancel = cloneDialogInfo(info)
		a.dialogs[callID] = state
		a.mu.Unlock()
		return DialogInfoResult{Accepted: true, StatusCode: 200, Reason: "OK"}, nil
	}
	inFlight := state.inviteInFlight
	cancelCfg := cloneDialogRequestConfig(state.cfg)
	cancelInv := cloneSIPRequestMessage(state.invite)
	if sentCSeq := voiceclient.ParseSIPCSeqNumber(cancelInv.Headers["CSeq"]); sentCSeq > 0 {
		cancelCfg.CSeq = sentCSeq
	}
	state.cancelRequested = true
	state.cancelSent = true
	a.dialogs[callID] = state
	a.mu.Unlock()
	return a.sendOutboundCancelWire(ctx, callID, cancelCfg, cancelInv, info, inFlight)
}

func (a *IMSOutboundAgent) sendOutboundCancelWire(ctx context.Context, callID string, cancelCfg voiceclient.DialogRequestConfig, cancelInv voiceclient.SIPRequestMessage, info DialogInfo, inFlight bool) (DialogInfoResult, error) {
	cancel, err := voiceclient.BuildCancelRequestWithBody(cancelCfg, info.ContentType, info.Body)
	if err != nil {
		return DialogInfoResult{Accepted: false, StatusCode: 500, Reason: "build IMS CANCEL failed"}, err
	}
	applyDialogUpdateHeaders(cancel.Headers, info.Headers)
	copyDialogHeader(cancel.Headers, cancelInv.Headers, "Via")
	resp, sentCancel, err := a.roundTripRequestWithResult(ctx, cancel)
	_ = sentCancel
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
		return DialogInfoResult{Accepted: false, Reason: "IMS CANCEL failed", RegistrationRecoveryNeeded: true}, err
	}
	defaultReason := "OK"
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defaultReason = "IMS CANCEL rejected"
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
		if resp.StatusCode == 481 && !inFlight {
			a.deleteDialog(callID)
		} else if !inFlight {
			a.mu.Lock()
			if st, ok := a.dialogs[callID]; ok {
				st.cancelRequested = false
				st.cancelSent = false
				a.dialogs[callID] = st
			}
			a.mu.Unlock()
		}
		return result, fmt.Errorf("IMS CANCEL rejected: %d %s", resp.StatusCode, strings.TrimSpace(resp.Reason))
	}
	if !inFlight {
		a.deleteDialog(callID)
		return result, nil
	}
	a.mu.Lock()
	if st, ok := a.dialogs[callID]; ok {
		st.canceled = true
		st.cancelRequested = true
		a.dialogs[callID] = st
	}
	a.mu.Unlock()
	return result, nil
}

func (a *IMSOutboundAgent) provisionalAnswer(resp voiceclient.SIPResponse, relay *RTPRelaySession, srtpNegotiation *outboundSDESRelayNegotiation) ([]byte, SDPInfo, bool, error) {
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
		if srtpNegotiation != nil {
			answerBody, localSDP, err = srtpNegotiation.RewriteClientAnswer(relay, resp.Body, remoteSDP)
			if err != nil {
				return nil, SDPInfo{}, false, fmt.Errorf("invalid RTP relay provisional SRTP SDP answer: %w", err)
			}
		} else {
			answerBody = RewriteSDPMediaEndpoint(resp.Body, relay.ClientEndpoint())
			localSDP, err = ParseSDP(answerBody)
			if err != nil {
				return nil, SDPInfo{}, false, fmt.Errorf("invalid RTP relay provisional SDP answer: %w", err)
			}
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
	callID = strings.TrimSpace(callID)
	if previous, ok := a.dialogs[callID]; ok {
		if previous.refreshTimer != nil && previous.refreshTimer != state.refreshTimer {
			previous.refreshTimer.Stop()
		}
		if previous.expiryTimer != nil && previous.expiryTimer != state.expiryTimer {
			previous.expiryTimer.Stop()
		}
	}
	a.dialogs[callID] = cloneDialogStateSnapshot(state)
	a.mu.Unlock()
}

func (a *IMSOutboundAgent) storeOutboundDialogTarget(callID string, target string) {
	if a == nil || strings.TrimSpace(callID) == "" || strings.TrimSpace(target) == "" {
		return
	}
	a.mu.Lock()
	if latest, ok := a.dialogs[strings.TrimSpace(callID)]; ok {
		latest.cfg.RemoteTargetURI = strings.TrimSpace(target)
		a.dialogs[strings.TrimSpace(callID)] = latest
	}
	a.mu.Unlock()
}

func (a *IMSOutboundAgent) updateOutboundDialogContact(callID string, headers map[string][]string) {
	if a == nil || strings.TrimSpace(callID) == "" {
		return
	}
	contact := sipHeaderURI(firstVoiceHeader(headers, "Contact"))
	if contact == "" {
		return
	}
	a.mu.Lock()
	if latest, ok := a.dialogs[strings.TrimSpace(callID)]; ok {
		latest.cfg.RemoteTargetURI = contact
		a.dialogs[strings.TrimSpace(callID)] = latest
	}
	a.mu.Unlock()
}

func (a *IMSOutboundAgent) dialog(callID string) (imsDialogState, bool) {
	if a == nil || strings.TrimSpace(callID) == "" {
		return imsDialogState{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	state, ok := a.dialogs[strings.TrimSpace(callID)]
	if !ok {
		return imsDialogState{}, false
	}
	return cloneDialogStateSnapshot(state), true
}

func (a *IMSOutboundAgent) OutboundDialogLocalTag(callID string) string {
	if a == nil || strings.TrimSpace(callID) == "" {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if state, ok := a.dialogs[strings.TrimSpace(callID)]; ok {
		return strings.TrimSpace(state.cfg.LocalTag)
	}
	return ""
}

func (a *IMSOutboundAgent) deleteDialog(callID string) {
	if a == nil || strings.TrimSpace(callID) == "" {
		return
	}
	a.mu.Lock()
	state, ok := a.dialogs[strings.TrimSpace(callID)]
	if ok {
		if state.refreshTimer != nil {
			state.refreshTimer.Stop()
		}
		if state.expiryTimer != nil {
			state.expiryTimer.Stop()
		}
		delete(a.dialogs, strings.TrimSpace(callID))
	}
	a.mu.Unlock()
	if ok && state.relay != nil {
		_ = state.relay.Close()
	}
}

func (a *IMSOutboundAgent) StopSessionTimers() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for callID, state := range a.dialogs {
		stopDialogSessionRefresh(&state)
		a.dialogs[callID] = state
	}
}

func (a *IMSOutboundAgent) TerminateAllDialogs(ctx context.Context) error {
	if a == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	a.mu.Lock()
	transport := a.Transport
	onTerminated := a.OnDialogTerminated
	snapshots := make(map[string]imsDialogState, len(a.dialogs))
	for callID, state := range a.dialogs {
		stopDialogSessionRefresh(&state)
		snapshots[callID] = cloneDialogStateSnapshot(state)
	}
	a.dialogs = nil
	a.mu.Unlock()

	var errs []error
	for callID, state := range snapshots {
		if transport != nil && !state.terminating && !state.canceled {
			termCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			if state.early {
				if !state.inviteInFlight || state.provisionalSeen {
					cancelCfg := state.cfg
					if sentCSeq := voiceclient.ParseSIPCSeqNumber(state.invite.Headers["CSeq"]); sentCSeq > 0 {
						cancelCfg.CSeq = sentCSeq
					}
					if cancelReq, buildErr := voiceclient.BuildCancelRequestWithBody(cancelCfg, "", nil); buildErr == nil {
						copyDialogHeader(cancelReq.Headers, state.invite.Headers, "Via")
						_, _ = voiceclient.RoundTripRequestWithDigestAuth(termCtx, transport, cancelReq)
					}
				}
			} else {
				if byeReq, buildErr := voiceclient.BuildByeRequestWithBody(state.cfg, "", nil); buildErr == nil {
					_, _ = voiceclient.RoundTripRequestWithDigestAuth(termCtx, transport, byeReq)
				}
			}
			cancel()
		}
		if state.relay != nil {
			if closeErr := state.relay.Close(); closeErr != nil {
				errs = append(errs, closeErr)
			}
		}
		if onTerminated != nil {
			onTerminated(ctx, callID, "runtime stopped")
		}
	}
	return errors.Join(errs...)
}

type IMSOutboundDialogHandler interface {
	HasOutboundDialog(callID string) bool
	HandleOutboundBye(ctx context.Context, req IMSByeRequest) (IMSByeResult, bool, error)
	HandleOutboundUpdate(ctx context.Context, req InboundDialogRequest) (InboundCallResult, bool, error)
	HandleOutboundReinvite(ctx context.Context, req InboundCallRequest) (InboundCallResult, bool, error)
	AckOutboundReinvite(ctx context.Context, callID string) bool
	HandleOutboundNotify(ctx context.Context, req InboundDialogRequest) (IMSInfoResult, bool, error)
	HandleOutboundInfo(ctx context.Context, req IMSInfoRequest) (IMSInfoResult, bool, error)
}

func (a *IMSOutboundAgent) HasOutboundDialog(callID string) bool {
	if a == nil || strings.TrimSpace(callID) == "" {
		return false
	}
	_, ok := a.dialog(callID)
	return ok
}

func outboundDialogTagsMatch(cfg voiceclient.DialogRequestConfig, headers map[string][]string) bool {
	localTag := strings.TrimSpace(cfg.LocalTag)
	remoteTag := strings.TrimSpace(cfg.RemoteTag)
	toTag := sipHeaderTag(firstVoiceHeader(headers, "To"))
	fromTag := sipHeaderTag(firstVoiceHeader(headers, "From"))
	if localTag != "" && toTag != localTag {
		return false
	}
	if remoteTag != "" && fromTag != remoteTag {
		return false
	}
	return true
}

func (a *IMSOutboundAgent) validateInboundRemoteCSeqLocked(callID string, state *imsDialogState, cseq int) bool {
	if cseq <= 0 {
		return true
	}
	if state.lastRemoteCSeq > 0 && cseq <= state.lastRemoteCSeq {
		return false
	}
	state.lastRemoteCSeq = cseq
	a.dialogs[callID] = *state
	return true
}

func (a *IMSOutboundAgent) HandleOutboundBye(ctx context.Context, req IMSByeRequest) (IMSByeResult, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil {
		return IMSByeResult{}, false, nil
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return IMSByeResult{}, false, nil
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return IMSByeResult{}, false, nil
	}
	if !outboundDialogTagsMatch(state.cfg, req.Headers) {
		a.mu.Unlock()
		return IMSByeResult{Handled: true, StatusCode: 481, Reason: "Call/Transaction Does Not Exist"}, true, nil
	}
	if !a.validateInboundRemoteCSeqLocked(callID, &state, req.CSeq) {
		a.mu.Unlock()
		return IMSByeResult{Handled: true, StatusCode: 500, Reason: "CSeq Out of Order"}, true, nil
	}
	stopDialogSessionRefresh(&state)
	delete(a.dialogs, callID)
	onTerminated := a.OnDialogTerminated
	a.mu.Unlock()

	if state.relay != nil {
		_ = state.relay.Close()
	}
	if onTerminated != nil {
		onTerminated(ctx, callID, "remote BYE")
	}
	return IMSByeResult{Handled: true, StatusCode: 200, Reason: "OK"}, true, nil
}

func (a *IMSOutboundAgent) HandleOutboundUpdate(ctx context.Context, req InboundDialogRequest) (InboundCallResult, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil {
		return InboundCallResult{}, false, nil
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return InboundCallResult{}, false, nil
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return InboundCallResult{}, false, nil
	}
	if !outboundDialogTagsMatch(state.cfg, req.Headers) {
		a.mu.Unlock()
		return InboundCallResult{Accepted: false, StatusCode: 481, Reason: "Call/Transaction Does Not Exist"}, true, nil
	}
	if !a.validateInboundRemoteCSeqLocked(callID, &state, req.CSeq) {
		a.mu.Unlock()
		return InboundCallResult{Accepted: false, StatusCode: 500, Reason: "CSeq Out of Order"}, true, nil
	}
	a.mu.Unlock()

	return a.handleInboundOutboundMediaUpdate(callID, inboundDialogBody(req), req.Headers, false)
}

func (a *IMSOutboundAgent) HandleOutboundReinvite(ctx context.Context, req InboundCallRequest) (InboundCallResult, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil {
		return InboundCallResult{}, false, nil
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return InboundCallResult{}, false, nil
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return InboundCallResult{}, false, nil
	}
	if !outboundDialogTagsMatch(state.cfg, req.Headers) {
		a.mu.Unlock()
		return InboundCallResult{Accepted: false, StatusCode: 481, Reason: "Call/Transaction Does Not Exist"}, true, nil
	}
	if !a.validateInboundRemoteCSeqLocked(callID, &state, req.CSeq) {
		a.mu.Unlock()
		return InboundCallResult{Accepted: false, StatusCode: 500, Reason: "CSeq Out of Order"}, true, nil
	}
	a.mu.Unlock()

	body := append([]byte(nil), req.RawSDP...)
	if len(body) == 0 && inboundSDPInfoPresent(req.RemoteSDP) {
		body = BuildSDPAnswer(req.RemoteSDP)
	}
	return a.handleInboundOutboundMediaUpdate(callID, body, req.Headers, true)
}

func (a *IMSOutboundAgent) AckOutboundReinvite(ctx context.Context, callID string) bool {
	return a.AckOutboundReinviteWithBody(ctx, callID, nil)
}

func (a *IMSOutboundAgent) AckOutboundReinviteWithBody(_ context.Context, callID string, body []byte) bool {
	if a == nil || strings.TrimSpace(callID) == "" {
		return false
	}
	callID = strings.TrimSpace(callID)
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return false
	}
	awaiting := state.awaitingInboundAck
	relay := state.relay
	srtpNeg := state.srtpNegotiation
	state.awaitingInboundAck = false
	a.dialogs[callID] = state
	a.mu.Unlock()
	if awaiting && len(body) > 0 && relay != nil {
		if remoteSDP, err := ParseSDP(body); err == nil {
			_ = relay.SetIMSRemote(remoteSDP)
			if srtpNeg != nil {
				_, _, _ = srtpNeg.RewriteClientAnswer(relay, body, remoteSDP)
			}
		}
	}
	return true
}

func (a *IMSOutboundAgent) handleInboundOutboundMediaUpdate(callID string, rawOffer []byte, headers map[string][]string, isReinvite bool) (InboundCallResult, bool, error) {
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return InboundCallResult{}, false, nil
	}
	cfg := cloneDialogRequestConfig(state.cfg)
	relay := state.relay
	srtpNeg := state.srtpNegotiation
	localSDPBody := append([]byte(nil), state.localSDPBody...)
	a.mu.Unlock()

	if contact := sipHeaderURI(firstVoiceHeader(headers, "Contact")); contact != "" {
		cfg.RemoteTargetURI = contact
	}
	respHeaders := make(map[string]string)
	if interval := sessionExpiresResponseHeader(headers); interval.Expires > 0 {
		if cfg.MinSE > 0 && interval.Expires < cfg.MinSE {
			respHeaders["Min-SE"] = strconv.Itoa(cfg.MinSE)
			return InboundCallResult{Accepted: false, StatusCode: 422, Reason: "Session Interval Too Small", Headers: respHeaders}, true, nil
		}
		cfg.SessionExpires = interval.Expires
		refresher := normalizeSessionRefresher(interval.Refresher)
		if refresher == "" {
			refresher = "uac"
		}
		switch refresher {
		case "uac":
			cfg.SessionRefresher = "uas"
			respHeaders["Session-Expires"] = strconv.Itoa(interval.Expires) + ";refresher=uac"
		case "uas":
			cfg.SessionRefresher = "uac"
			respHeaders["Session-Expires"] = strconv.Itoa(interval.Expires) + ";refresher=uas"
		}
	}

	var answerSDP []byte
	var parsedAnswer SDPInfo
	awaitingAck := false
	if len(rawOffer) > 0 {
		remoteSDP, err := ParseSDP(rawOffer)
		if err != nil {
			return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "Invalid SDP"}, true, err
		}
		if relay != nil {
			if err := relay.SetIMSRemote(remoteSDP); err != nil {
				return InboundCallResult{Accepted: false, StatusCode: 503, Reason: "RTP relay update failed"}, true, err
			}
		}
		baseSDP := localSDPBody
		if len(baseSDP) == 0 {
			baseSDP = BuildSDPAnswer(SDPInfo{
				ConnectionIP: firstVoiceNonEmpty(cfg.Profile.LocalIP, "127.0.0.1"),
				MediaPort:    4000,
				Payloads:     remoteSDP.Payloads,
				Direction:    outboundAnswerDirection(remoteSDP.Direction),
			})
		} else if rewrittenDir, dirErr := RewriteSDPMediaDirection(baseSDP, outboundAnswerDirection(remoteSDP.Direction)); dirErr == nil {
			baseSDP = rewrittenDir
		}
		baseSDP = RewriteSDPPreconditionsForAnswer(rawOffer, baseSDP)
		if relay != nil {
			baseSDP = RewriteSDPMediaEndpoint(baseSDP, relay.IMSEndpoint())
			if srtpNeg != nil {
				rewritten, rwErr := srtpNeg.RewriteIMSMidDialogAnswer(relay, rawOffer, baseSDP)
				if rwErr != nil {
					return InboundCallResult{Accepted: false, StatusCode: 488, Reason: "Invalid SRTP SDP"}, true, rwErr
				}
				baseSDP = rewritten
			}
		}
		parsed, parseErr := ParseSDP(baseSDP)
		if parseErr != nil {
			return InboundCallResult{Accepted: false, StatusCode: 500, Reason: "Invalid local SDP answer"}, true, parseErr
		}
		answerSDP = baseSDP
		parsedAnswer = parsed
	} else if isReinvite {
		// RFC 3261 §13.2.1 late-offer re-INVITE: supply local SDP offer in 200 OK and await answer in ACK.
		baseSDP := localSDPBody
		if len(baseSDP) > 0 {
			if relay != nil {
				baseSDP = RewriteSDPMediaEndpoint(baseSDP, relay.IMSEndpoint())
				if srtpNeg != nil {
					if rewritten, rwErr := srtpNeg.RewriteIMSMidDialogOffer(relay, baseSDP); rwErr == nil {
						baseSDP = rewritten
					}
				}
			}
			if parsed, parseErr := ParseSDP(baseSDP); parseErr == nil {
				answerSDP = baseSDP
				parsedAnswer = parsed
				awaitingAck = true
			}
		}
	}

	a.mu.Lock()
	if latest, exists := a.dialogs[callID]; exists {
		latest.cfg.RemoteTargetURI = cfg.RemoteTargetURI
		latest.cfg.SessionExpires = cfg.SessionExpires
		latest.cfg.SessionRefresher = cfg.SessionRefresher
		latest.awaitingInboundAck = awaitingAck
		if latest.cfg.SessionExpires > 0 {
			latest.sessionDeadline = time.Now().Add(sessionExpirationTimeout(latest.cfg.SessionExpires))
		}
		a.dialogs[callID] = latest
	}
	a.mu.Unlock()
	a.scheduleDialogSessionRefresh(callID)

	return InboundCallResult{
		Accepted:   true,
		StatusCode: 200,
		Reason:     "OK",
		LocalSDP:   parsedAnswer,
		RawSDP:     answerSDP,
		Headers:    respHeaders,
	}, true, nil
}

func outboundAnswerDirection(offerDirection string) string {
	switch normalizeSDPDirection(offerDirection) {
	case "sendonly":
		return "recvonly"
	case "recvonly":
		return "sendonly"
	case "inactive":
		return "inactive"
	default:
		return "sendrecv"
	}
}

func (a *IMSOutboundAgent) HandleOutboundNotify(ctx context.Context, req InboundDialogRequest) (IMSInfoResult, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil {
		return IMSInfoResult{}, false, nil
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return IMSInfoResult{}, false, nil
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return IMSInfoResult{}, false, nil
	}
	if !outboundDialogTagsMatch(state.cfg, req.Headers) {
		a.mu.Unlock()
		return IMSInfoResult{Handled: true, StatusCode: 481, Reason: "Call/Transaction Does Not Exist"}, true, nil
	}
	if !a.validateInboundRemoteCSeqLocked(callID, &state, req.CSeq) {
		a.mu.Unlock()
		return IMSInfoResult{Handled: true, StatusCode: 500, Reason: "CSeq Out of Order"}, true, nil
	}
	a.mu.Unlock()

	event := firstVoiceNonEmpty(req.Event, firstVoiceHeader(req.Headers, "Event"))
	if strings.TrimSpace(event) == "" {
		return IMSInfoResult{Handled: true, StatusCode: 400, Reason: "Event empty"}, true, errors.New("Event is empty")
	}
	subState := firstVoiceNonEmpty(req.SubscriptionState, firstVoiceHeader(req.Headers, "Subscription-State"))
	if strings.TrimSpace(subState) == "" {
		return IMSInfoResult{Handled: true, StatusCode: 400, Reason: "Subscription-State empty"}, true, errors.New("Subscription-State is empty")
	}
	a.updateOutboundDialogContact(callID, req.Headers)
	return IMSInfoResult{Handled: true, StatusCode: 200, Reason: "OK"}, true, nil
}

func (a *IMSOutboundAgent) HandleOutboundInfo(ctx context.Context, req IMSInfoRequest) (IMSInfoResult, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil {
		return IMSInfoResult{}, false, nil
	}
	callID := strings.TrimSpace(req.CallID)
	if callID == "" {
		return IMSInfoResult{}, false, nil
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok {
		a.mu.Unlock()
		return IMSInfoResult{}, false, nil
	}
	if !outboundDialogTagsMatch(state.cfg, req.Headers) {
		a.mu.Unlock()
		return IMSInfoResult{Handled: true, StatusCode: 481, Reason: "Call/Transaction Does Not Exist"}, true, nil
	}
	if !a.validateInboundRemoteCSeqLocked(callID, &state, req.CSeq) {
		a.mu.Unlock()
		return IMSInfoResult{Handled: true, StatusCode: 500, Reason: "CSeq Out of Order"}, true, nil
	}
	a.mu.Unlock()

	if isDTMFRelayContentType(req.ContentType) || strings.EqualFold(strings.TrimSpace(req.InfoPackage), DTMFInfoPackage) {
		if _, _, err := ParseDTMFRelayBody(req.Body); err != nil {
			return IMSInfoResult{Handled: true, StatusCode: 400, Reason: "Invalid DTMF relay"}, true, err
		}
	}
	a.updateOutboundDialogContact(callID, req.Headers)
	return IMSInfoResult{Handled: true, StatusCode: 200, Reason: "OK"}, true, nil
}

func (a *IMSOutboundAgent) scheduleDialogSessionRefresh(callID string) {
	a.scheduleDialogSessionRefreshAfter(callID, 0)
}

func (a *IMSOutboundAgent) scheduleDialogSessionRefreshAfter(callID string, customDelay time.Duration) {
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
	stopDialogSessionRefresh(&state)
	seq := state.refreshSeq
	refresher := normalizeSessionRefresher(state.cfg.SessionRefresher)
	delay := customDelay
	if delay <= 0 {
		switch refresher {
		case "uac":
			delay = sessionRefreshDelay(state.cfg.SessionExpires, "uac", a.SessionRefreshLead)
		case "uas":
			delay = sessionExpirationTimeout(state.cfg.SessionExpires)
		}
	}
	if delay <= 0 || state.early || state.terminating || state.cfg.SessionExpires <= 0 {
		a.dialogs[callID] = state
		a.mu.Unlock()
		return
	}
	if refresher == "uas" && customDelay <= 0 {
		state.expiryTimer = time.AfterFunc(delay, func() {
			a.runDialogSessionRefresh(callID, seq)
		})
	} else {
		state.refreshTimer = time.AfterFunc(delay, func() {
			a.runDialogSessionRefresh(callID, seq)
		})
	}
	a.dialogs[callID] = state
	a.mu.Unlock()
}

func (a *IMSOutboundAgent) runDialogSessionRefresh(callID string, seq uint64) {
	if a == nil || strings.TrimSpace(callID) == "" {
		return
	}
	callID = strings.TrimSpace(callID)
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	if !ok || state.refreshSeq != seq || state.early || state.terminating || state.cfg.SessionExpires <= 0 {
		a.mu.Unlock()
		return
	}
	refresher := normalizeSessionRefresher(state.cfg.SessionRefresher)
	localSDPBody := append([]byte(nil), state.localSDPBody...)
	deadline := state.sessionDeadline
	expires := state.cfg.SessionExpires
	a.mu.Unlock()

	if refresher == "uas" {
		a.terminateExpiredSession(callID, "session expired")
		return
	}
	if refresher != "uac" {
		return
	}
	updRes, updErr := a.SendDialogUpdate(context.Background(), DialogUpdateRequest{CallID: callID})
	if updErr == nil && updRes.Accepted {
		return
	}
	if updRes.StatusCode == 405 || updRes.StatusCode == 501 {
		reReq := DialogReinviteRequest{CallID: callID}
		if len(localSDPBody) > 0 {
			reReq.ContentType = "application/sdp"
			reReq.Body = localSDPBody
		}
		reRes, reErr := a.SendDialogReinvite(context.Background(), reReq)
		if reErr == nil && reRes.Accepted {
			return
		}
		if reRes.StatusCode == 481 {
			a.terminateExpiredSession(callID, "session refresh 481")
			return
		}
	}
	if updRes.StatusCode == 481 {
		a.terminateExpiredSession(callID, "session refresh 481")
		return
	}
	now := time.Now()
	if deadline.IsZero() && expires > 0 {
		deadline = now.Add(sessionExpirationTimeout(expires) / 2)
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		a.terminateExpiredSession(callID, "session expired")
		return
	}
	retryDelay := remaining / 2
	if retryDelay > 10*time.Second {
		retryDelay = 10 * time.Second
	}
	if retryDelay < 50*time.Millisecond {
		retryDelay = 50 * time.Millisecond
	}
	a.scheduleDialogSessionRefreshAfter(callID, retryDelay)
}

func (a *IMSOutboundAgent) terminateExpiredSession(callID string, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = a.EndVoiceCallWithResult(ctx, DialogInfo{CallID: callID})
	// Ensure local cleanup even if BYE transport call failed.
	a.deleteDialog(callID)
	a.mu.Lock()
	onTerminated := a.OnDialogTerminated
	a.mu.Unlock()
	if onTerminated != nil {
		onTerminated(context.Background(), callID, reason)
	}
}

func stopDialogSessionRefresh(state *imsDialogState) {
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

func (a *IMSOutboundAgent) resumeDialogSessionRefreshAfterTerminating(callID string) {
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
	a.scheduleDialogSessionRefresh(callID)
}

func sessionRefreshDelay(expires int, refresher string, lead time.Duration) time.Duration {
	if expires <= 0 || normalizeSessionRefresher(refresher) != "uac" {
		return 0
	}
	interval := time.Duration(expires) * time.Second
	if interval <= 0 {
		return 0
	}
	if lead > 0 && lead < interval {
		delay := interval - lead
		if delay > 0 {
			return delay
		}
	}
	delay := interval / 2
	if delay <= 0 {
		delay = interval
	}
	return delay
}

func sessionExpirationTimeout(expires int) time.Duration {
	if expires <= 0 {
		return 0
	}
	interval := time.Duration(expires) * time.Second
	if expires <= 3 {
		return interval
	}
	grace := interval / 3
	if grace > 32*time.Second {
		grace = 32 * time.Second
	}
	if interval > grace {
		return interval - grace
	}
	return interval
}

func (a *IMSOutboundAgent) roundTripInvite(ctx context.Context, invite voiceclient.SIPRequestMessage, onProvisional func(voiceclient.SIPResponse) error) (voiceclient.SIPResponse, voiceclient.SIPRequestMessage, error) {
	transport := a.currentTransport()
	if a == nil || transport == nil {
		return voiceclient.SIPResponse{}, invite, ErrIMSVoiceAgentNotReady
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
	return a.roundTripRequestWithResult(ctx, invite)
}

func (a *IMSOutboundAgent) roundTripRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error) {
	resp, _, err := a.roundTripRequestWithResult(ctx, msg)
	return resp, err
}

func (a *IMSOutboundAgent) roundTripRequestWithResult(ctx context.Context, msg voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, voiceclient.SIPRequestMessage, error) {
	transport := a.currentTransport()
	if a == nil || transport == nil {
		return voiceclient.SIPResponse{}, msg, ErrIMSVoiceAgentNotReady
	}
	return voiceclient.RoundTripRequestWithDigestAuthResult(ctx, transport, msg)
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
	if routeSet := recordRouteSet(resp.Headers); len(routeSet) > 0 {
		prackCfg.RouteSet = routeSet
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

func imsRegistrationRecoveryNeededStatus(code int) bool {
	switch code {
	case 408, 430, 480, 481, 500, 502, 503, 504, 580:
		return true
	default:
		return code >= 500 && code < 600
	}
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

func retryDialogConfigForMinSE(cfg voiceclient.DialogRequestConfig, sentHeaders map[string]string, responseHeaders map[string][]string) (voiceclient.DialogRequestConfig, bool) {
	minSE := minSEHeader(responseHeaders)
	if minSE <= 0 {
		return voiceclient.DialogRequestConfig{}, false
	}
	sentInterval := sessionExpiresRequestHeader(sentHeaders)
	if sentInterval.Expires <= 0 {
		sentInterval.Expires = cfg.SessionExpires
		sentInterval.Refresher = normalizeSessionRefresher(cfg.SessionRefresher)
	}
	if sentInterval.Refresher == "" {
		sentInterval.Refresher = normalizeSessionRefresher(cfg.SessionRefresher)
	}
	if sentInterval.Expires < minSE {
		sentInterval.Expires = minSE
	}
	retry := cfg
	retry.CSeq = outboundNextCSeq(cfg.CSeq)
	retry.SessionExpires = sentInterval.Expires
	retry.SessionRefresher = sentInterval.Refresher
	retry.MinSE = minSE
	return retry, true
}

func retryDialogConfigForMinExpires(cfg voiceclient.DialogRequestConfig, sentHeaders map[string]string, responseHeaders map[string][]string) (voiceclient.DialogRequestConfig, string, bool) {
	minExpires := minExpiresHeader(responseHeaders)
	if minExpires <= 0 {
		return voiceclient.DialogRequestConfig{}, "", false
	}
	expires := subscribeExpiresHeader(sentHeaders)
	if expires >= minExpires {
		return voiceclient.DialogRequestConfig{}, "", false
	}
	retry := cfg
	retry.CSeq = outboundNextCSeq(cfg.CSeq)
	if contact := sipHeaderURI(firstVoiceHeader(responseHeaders, "Contact")); contact != "" {
		retry.RemoteTargetURI = contact
	}
	return retry, strconv.Itoa(minExpires), true
}

func minExpiresHeader(headers map[string][]string) int {
	for key, values := range headers {
		if !strings.EqualFold(key, "Min-Expires") {
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

func subscribeExpiresHeader(headers map[string]string) int {
	for key, value := range headers {
		if !strings.EqualFold(key, "Expires") {
			continue
		}
		value = strings.TrimSpace(value)
		if semi := strings.IndexByte(value, ';'); semi >= 0 {
			value = value[:semi]
		}
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err == nil && n > 0 {
			return n
		}
	}
	return 0
}

type sessionIntervalHeader struct {
	Expires   int
	Refresher string
}

func sessionExpiresRequestHeader(headers map[string]string) sessionIntervalHeader {
	for key, value := range headers {
		if !strings.EqualFold(key, "Session-Expires") {
			continue
		}
		if interval := parseSessionExpiresHeaderValue(value); interval.Expires > 0 {
			return interval
		}
	}
	return sessionIntervalHeader{}
}

func sessionExpiresResponseHeader(headers map[string][]string) sessionIntervalHeader {
	for key, values := range headers {
		if !strings.EqualFold(key, "Session-Expires") {
			continue
		}
		for _, value := range values {
			if interval := parseSessionExpiresHeaderValue(value); interval.Expires > 0 {
				return interval
			}
		}
	}
	return sessionIntervalHeader{}
}

func parseSessionExpiresHeaderValue(value string) sessionIntervalHeader {
	for _, entry := range splitVoiceHeaderValues(value) {
		parts := splitVoiceHeaderParams(entry)
		if len(parts) == 0 {
			continue
		}
		expires, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || expires <= 0 {
			continue
		}
		interval := sessionIntervalHeader{Expires: expires}
		for _, param := range parts[1:] {
			key, raw, ok := strings.Cut(strings.TrimSpace(param), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "refresher") {
				continue
			}
			interval.Refresher = normalizeSessionRefresher(strings.Trim(strings.TrimSpace(raw), `"`))
		}
		return interval
	}
	return sessionIntervalHeader{}
}

func applyNegotiatedSessionInterval(cfg *voiceclient.DialogRequestConfig, headers map[string][]string) bool {
	return applyNegotiatedSessionIntervalWithDefault(cfg, headers, "uac")
}

func applyNegotiatedSessionIntervalWithDefault(cfg *voiceclient.DialogRequestConfig, headers map[string][]string, defaultRefresher string) bool {
	if cfg == nil {
		return false
	}
	interval := sessionExpiresResponseHeader(headers)
	if interval.Expires <= 0 {
		cfg.SessionExpires = 0
		cfg.SessionRefresher = ""
		return false
	}
	cfg.SessionExpires = interval.Expires
	refresher := normalizeSessionRefresher(interval.Refresher)
	if refresher == "" {
		refresher = firstVoiceNonEmpty(normalizeSessionRefresher(cfg.SessionRefresher), normalizeSessionRefresher(defaultRefresher), "uac")
	}
	cfg.SessionRefresher = refresher
	return true
}

func applySessionIntervalHeaders(headers map[string]string, cfg voiceclient.DialogRequestConfig) {
	if headers == nil {
		return
	}
	if cfg.SessionExpires > 0 {
		value := strconv.Itoa(cfg.SessionExpires)
		if refresher := normalizeSessionRefresher(cfg.SessionRefresher); refresher != "" {
			value += ";refresher=" + refresher
		}
		headers["Session-Expires"] = value
	}
	if cfg.MinSE > 0 {
		headers["Min-SE"] = strconv.Itoa(cfg.MinSE)
	}
}

func normalizeSessionRefresher(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "uac", "uas":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
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

func ensureHeaderOptionTag(headers map[string]string, name string, tag string) {
	if headers == nil || strings.TrimSpace(name) == "" || strings.TrimSpace(tag) == "" {
		return
	}
	tag = strings.TrimSpace(tag)
	existingKey := name
	existingVal := ""
	for k, v := range headers {
		if strings.EqualFold(strings.TrimSpace(k), name) {
			existingKey = k
			existingVal = strings.TrimSpace(v)
			break
		}
	}
	if existingVal == "" {
		headers[existingKey] = tag
		return
	}
	for _, part := range strings.Split(existingVal, ",") {
		if strings.EqualFold(strings.TrimSpace(part), tag) {
			return
		}
	}
	headers[existingKey] = existingVal + ", " + tag
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
	case "to", "from", "call-id", "cseq", "max-forwards", "route", "record-route", "via", "contact", "content-length", "content-type", "rack", "refer-to", "referred-by", "event", "subscription-state":
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

func copyVoiceHeaderMap(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for key, value := range headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			out[key] = value
		}
	}
	return out
}

func copyStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func uasRecordRouteSet(headers map[string][]string) []string {
	var routes []string
	for key, values := range headers {
		if !strings.EqualFold(key, "Record-Route") {
			continue
		}
		for _, value := range values {
			for _, route := range splitVoiceHeaderValues(value) {
				if strings.TrimSpace(route) != "" {
					routes = append(routes, strings.TrimSpace(route))
				}
			}
		}
	}
	return routes
}

func recordRouteSet(headers map[string][]string) []string {
	routes := uasRecordRouteSet(headers)
	for i, j := 0, len(routes)-1; i < j; i, j = i+1, j-1 {
		routes[i], routes[j] = routes[j], routes[i]
	}
	return routes
}

func splitVoiceHeaderValues(value string) []string {
	return splitVoiceHeaderItems(value, ',')
}

func splitVoiceHeaderParams(value string) []string {
	return splitVoiceHeaderItems(value, ';')
}

func splitVoiceHeaderItems(value string, separator rune) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	escaped := false
	angleDepth := 0
	for _, r := range value {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && inQuote:
			cur.WriteRune(r)
			escaped = true
		case r == '"':
			cur.WriteRune(r)
			inQuote = !inQuote
		case r == '<' && !inQuote:
			angleDepth++
			cur.WriteRune(r)
		case r == '>' && !inQuote:
			if angleDepth > 0 {
				angleDepth--
			}
			cur.WriteRune(r)
		case r == separator && !inQuote && angleDepth == 0:
			if part := strings.TrimSpace(cur.String()); part != "" {
				out = append(out, part)
			}
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if part := strings.TrimSpace(cur.String()); part != "" {
		out = append(out, part)
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
	a.mu.Lock()
	domain := firstVoiceNonEmpty(a.Domain, a.Profile.Domain, domainFromURI(a.Registration.PublicIdentity))
	a.mu.Unlock()
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
	for _, part := range splitVoiceHeaderParams(value) {
		key, raw, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "tag") {
			return strings.Trim(strings.TrimSpace(raw), `"`)
		}
	}
	return ""
}

func domainFromURI(uri string) string {
	uri = strings.TrimSpace(uri)
	lower := strings.ToLower(uri)
	switch {
	case strings.HasPrefix(lower, "sip:"):
		uri = uri[4:]
	case strings.HasPrefix(lower, "sips:"):
		uri = uri[5:]
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
