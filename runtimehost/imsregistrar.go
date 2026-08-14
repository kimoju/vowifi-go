package runtimehost

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kimoju/vowifi-go/runtimehost/carrier"
	"github.com/kimoju/vowifi-go/runtimehost/identity"
	"github.com/kimoju/vowifi-go/runtimehost/messaging"
	"github.com/kimoju/vowifi-go/runtimehost/voiceclient"
	"github.com/kimoju/vowifi-go/runtimehost/voicehost"
)

type IMSRegisterTransportFactory func(IMSRegistrationConfig, voiceclient.IMSProfile, string, string) voiceclient.SIPRegisterTransport
type IMSVoiceTransportFactory func(IMSRegistrationConfig, voiceclient.IMSProfile, voiceclient.RegistrationBinding) voiceclient.SIPRequestTransport
type IMSSMSTransportFactory func(IMSRegistrationConfig, voiceclient.IMSProfile, voiceclient.RegistrationBinding, voiceclient.SIPRequestTransport) messaging.SMSTransport
type IMSUSSDTransportFactory func(IMSRegistrationConfig, voiceclient.IMSProfile, voiceclient.RegistrationBinding, voiceclient.SIPRequestTransport) messaging.USSDTransport
type imsRegistrationWaitFunc func(context.Context, time.Duration) bool

const (
	// imsCloseDeregisterTimeout keeps a best-effort SIP deregistration from
	// consuming the whole application shutdown deadline. Local IPsec, routing,
	// and socket cleanup must still have time to run when the P-CSCF is silent.
	imsCloseDeregisterTimeout = 2 * time.Second

	// IMSRegisterResponseActionNone means the status does not imply local registration recovery.
	IMSRegisterResponseActionNone = "none"

	// IMSRegisterResponseActionReauthenticate means the UE should obtain a fresh digest challenge.
	IMSRegisterResponseActionReauthenticate = "reauthenticate"

	// IMSRegisterResponseActionRefreshIdentity means local IMS identity material should be refreshed before retrying.
	IMSRegisterResponseActionRefreshIdentity = "refresh_identity"

	// IMSRegisterResponseActionRetryWithMinExpires means the UE should honor Min-Expires and retry.
	IMSRegisterResponseActionRetryWithMinExpires = "retry_with_min_expires"

	// IMSRegisterResponseActionBackoffRetry means the UE should retry registration conservatively after delay/backoff.
	IMSRegisterResponseActionBackoffRetry = "backoff_retry"

	// IMSRegisterResponseActionRefreshSecurity means the UE should rebuild Security-Agree state before retrying.
	IMSRegisterResponseActionRefreshSecurity = "refresh_security"
)

// IMSRegisterResponseDecision is a local recovery hint for a SIP REGISTER response.
type IMSRegisterResponseDecision struct {
	StatusCode      int
	Action          string
	Recoverable     bool
	Retry           bool
	Reauthenticate  bool
	RefreshIdentity bool
	RefreshSecurity bool
	Backoff         bool
	RetryAfter      time.Duration
}

type WireIMSRegistrar struct {
	Transport                   voiceclient.SIPRegisterTransport
	TransportFactory            IMSRegisterTransportFactory
	VoiceTransport              voiceclient.SIPRequestTransport
	VoiceFactory                IMSVoiceTransportFactory
	SMSTransport                messaging.SMSTransport
	SMSFactory                  IMSSMSTransportFactory
	USSDTransport               messaging.USSDTransport
	USSDFactory                 IMSUSSDTransportFactory
	RegistrarURI                string
	ContactURI                  string
	ContactHost                 string
	ContactPort                 int
	Network                     string
	ServerAddr                  string
	LocalAddr                   string
	Resolver                    voiceclient.SIPServerResolver
	Timeout                     time.Duration
	Expires                     int
	PurgeBindingsBeforeRegister bool
	DisableRefresh              bool
	RefreshInterval             time.Duration
	RefreshLead                 time.Duration
	RefreshRetryInterval        time.Duration
	RecoveryBackoffInitial      time.Duration
	RecoveryBackoffMax          time.Duration
	DisableKeepalive            bool
	KeepaliveInterval           time.Duration
	UserAgent                   string
	CallID                      string
	CNonce                      string
	RetransmitInterval          time.Duration
	MaxRetransmitInterval       time.Duration
	MaxRetransmits              int
	SecurityPlanInstaller       voiceclient.SecurityPlanInstaller
}

// ClassifyIMSRegisterResponse maps SIP REGISTER status codes to conservative local recovery hints.
func ClassifyIMSRegisterResponse(statusCode int, retryAfter time.Duration) IMSRegisterResponseDecision {
	decision := IMSRegisterResponseDecision{
		StatusCode: statusCode,
		Action:     IMSRegisterResponseActionNone,
	}
	switch {
	case statusCode == 401 || statusCode == 407:
		decision.Action = IMSRegisterResponseActionReauthenticate
		decision.Recoverable = true
		decision.Retry = true
		decision.Reauthenticate = true
	case statusCode == 403:
		decision.Action = IMSRegisterResponseActionRefreshIdentity
		decision.RefreshIdentity = true
	case statusCode == 423:
		decision.Action = IMSRegisterResponseActionRetryWithMinExpires
		decision.Recoverable = true
		decision.Retry = true
	case statusCode == 494:
		decision.Action = IMSRegisterResponseActionRefreshSecurity
		decision.Recoverable = true
		decision.Retry = true
		decision.RefreshSecurity = true
	case isBackoffIMSRegisterStatus(statusCode):
		decision.Action = IMSRegisterResponseActionBackoffRetry
		decision.Recoverable = true
		decision.Retry = true
		decision.Backoff = true
		if retryAfter > 0 {
			decision.RetryAfter = retryAfter
		}
	}
	return decision
}

func (r WireIMSRegistrar) RegisterIMS(ctx context.Context, cfg IMSRegistrationConfig) (IMSRegistrationResult, error) {
	profile, err := r.profileFromConfig(cfg)
	if err != nil {
		return IMSRegistrationResult{}, err
	}
	registrarURI := firstRuntimeNonEmpty(r.RegistrarURI, registrarURIForProfile(profile))
	if registrarURI == "" {
		return IMSRegistrationResult{}, errors.New("IMS registrar URI is empty")
	}
	contactURI := firstRuntimeNonEmpty(r.ContactURI, r.contactURIForProfile(profile))
	if contactURI == "" {
		return IMSRegistrationResult{}, errors.New("IMS contact URI is empty")
	}
	transport := r.Transport
	var defaultFlow *voiceclient.WireSIPFlow
	if transport == nil && r.TransportFactory != nil {
		transport = r.TransportFactory(cfg, profile, registrarURI, contactURI)
	}
	if transport == nil {
		defaultFlow = r.defaultSIPFlow(cfg)
		transport = defaultFlow
	}
	expires := r.Expires
	if expires <= 0 {
		expires = 3600
	}
	registerSession := r.registerSession(cfg, profile, registrarURI, contactURI, transport, expires)
	result, err := registerSession.Register(ctx)
	if err != nil {
		refreshedCfg, refreshedProfile, refreshedRegistrarURI, refreshedContactURI, refreshed, refreshErr := r.refreshIdentityAfterForbidden(ctx, cfg, profile, result, err)
		if refreshErr != nil {
			err = errors.Join(err, refreshErr)
		} else if refreshed {
			cfg = refreshedCfg
			profile = refreshedProfile
			registrarURI = refreshedRegistrarURI
			contactURI = refreshedContactURI
			if r.Transport == nil {
				transport = nil
				if r.TransportFactory != nil {
					transport = r.TransportFactory(cfg, profile, registrarURI, contactURI)
				}
				if transport == nil {
					if defaultFlow == nil {
						defaultFlow = r.defaultSIPFlow(cfg)
					}
					transport = defaultFlow
				}
			}
			registerSession = r.registerSession(cfg, profile, registrarURI, contactURI, transport, expires)
			result, err = registerSession.Register(ctx)
		}
		if err != nil {
			cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 5*time.Second)
			cleanupErr := cleanupIMSRegistrationSecurityPlans(cleanupCtx, r.SecurityPlanInstaller)
			cancelCleanup()
			var closeErr error
			if defaultFlow != nil {
				closeErr = defaultFlow.Close()
			}
			err = errors.Join(err, cleanupErr, closeErr)
			return imsRegisterFailureResult(result, profile, err), err
		}
	}
	registeredAt := time.Now()
	expiresAt, refreshDelay, nextRefreshAt := imsRegistrationSchedule(r, result.Binding, registerSession, registeredAt, result.Registered)
	voiceTransport := r.voiceTransport(cfg, profile, result.Binding, defaultFlow)
	smsTransport := r.smsTransport(cfg, profile, result.Binding, voiceTransport)
	ussdTransport := r.ussdTransport(cfg, profile, result.Binding, voiceTransport)
	maintenance := newIMSRegistrationMaintenance(defaultFlow, registerSession, result, r, cfg, profile, registeredAt)
	var closeRegistration func(context.Context) error
	var recoverRegistration func(context.Context) (IMSRegistrationResult, error)
	var bindInbound func(voicehost.IMSMessageHandler) error
	if maintenance != nil {
		closeRegistration = maintenance.Close
		recoverRegistration = maintenance.Recover
		bindInbound = maintenance.BindInbound
	}
	return IMSRegistrationResult{
		Registered:     result.Registered,
		StatusCode:     result.StatusCode,
		Reason:         firstRuntimeNonEmpty(result.Reason, "ims registered"),
		Server:         firstRuntimeNonEmpty(result.Binding.PublicIdentity, profile.Domain),
		Profile:        profile,
		Binding:        result.Binding,
		RegisteredAt:   registeredAt,
		ExpiresAt:      expiresAt,
		RefreshDelay:   refreshDelay,
		NextRefreshAt:  nextRefreshAt,
		VoiceTransport: voiceTransport,
		SMSTransport:   smsTransport,
		USSDTransport:  ussdTransport,
		BindInbound:    bindInbound,
		Close:          closeRegistration,
		Recover:        recoverRegistration,
	}, nil
}

func (r WireIMSRegistrar) voiceTransport(cfg IMSRegistrationConfig, profile voiceclient.IMSProfile, binding voiceclient.RegistrationBinding, fallback voiceclient.SIPRequestTransport) voiceclient.SIPRequestTransport {
	if r.VoiceTransport != nil {
		return r.VoiceTransport
	}
	if r.VoiceFactory != nil {
		return r.VoiceFactory(cfg, profile, binding)
	}
	if fallback != nil {
		return fallback
	}
	return voiceclient.WireSIPTransport{
		Network:               r.Network,
		ServerAddr:            r.ServerAddr,
		LocalAddr:             r.sipLocalAddrForConfig(cfg),
		Resolver:              r.resolverForConfig(cfg),
		Timeout:               r.Timeout,
		RetransmitInterval:    r.RetransmitInterval,
		MaxRetransmitInterval: r.MaxRetransmitInterval,
		MaxRetransmits:        r.MaxRetransmits,
	}
}

func (r WireIMSRegistrar) defaultSIPFlow(cfg IMSRegistrationConfig) *voiceclient.WireSIPFlow {
	return &voiceclient.WireSIPFlow{
		Network:               r.Network,
		ServerAddr:            r.ServerAddr,
		LocalAddr:             r.sipLocalAddrForConfig(cfg),
		Resolver:              r.resolverForConfig(cfg),
		Timeout:               r.Timeout,
		RetransmitInterval:    r.RetransmitInterval,
		MaxRetransmitInterval: r.MaxRetransmitInterval,
		MaxRetransmits:        r.MaxRetransmits,
	}
}

func (r WireIMSRegistrar) registerSession(cfg IMSRegistrationConfig, profile voiceclient.IMSProfile, registrarURI, contactURI string, transport voiceclient.SIPRegisterTransport, expires int) voiceclient.RegisterSession {
	return voiceclient.RegisterSession{
		Transport:                   transport,
		AKAProvider:                 cfg.SIM,
		AKAAppPreference:            imsAKAAppPreferenceFromConfig(cfg),
		Profile:                     profile,
		RegistrarURI:                registrarURI,
		ContactURI:                  contactURI,
		CallID:                      firstRuntimeNonEmpty(r.CallID, cfg.TraceID, cfg.DeviceID+"-ims-register"),
		CNonce:                      firstRuntimeNonEmpty(r.CNonce, cfg.TraceID, cfg.DeviceID),
		Expires:                     expires,
		InitialAuthorization:        true,
		PurgeBindingsBeforeRegister: r.PurgeBindingsBeforeRegister,
		SecurityPlanInstaller:       r.SecurityPlanInstaller,
		SecurityLocalAddr:           firstRuntimeNonEmpty(r.ContactHost, profile.LocalIP, r.LocalAddr),
		SecurityRemoteAddr:          r.ServerAddr,
	}
}

func imsRegisterFailureResult(result voiceclient.RegisterResult, profile voiceclient.IMSProfile, err error) IMSRegistrationResult {
	reason := result.Reason
	if reason == "" && err != nil {
		reason = err.Error()
	}
	return IMSRegistrationResult{
		Registered: result.Registered,
		StatusCode: result.StatusCode,
		Reason:     reason,
		Server:     firstRuntimeNonEmpty(result.Binding.PublicIdentity, profile.Domain),
		Profile:    profile,
		Binding:    result.Binding,
	}
}

func (r WireIMSRegistrar) refreshIdentityAfterForbidden(ctx context.Context, cfg IMSRegistrationConfig, current voiceclient.IMSProfile, result voiceclient.RegisterResult, cause error) (IMSRegistrationConfig, voiceclient.IMSProfile, string, string, bool, error) {
	_ = ctx
	_ = cause
	if !ClassifyIMSRegisterResponse(result.StatusCode, result.RetryAfter).RefreshIdentity {
		return cfg, current, "", "", false, nil
	}
	if cfg.Access == nil {
		return cfg, current, "", "", false, nil
	}
	id, err := cfg.Access.GetISIMIdentity()
	if err != nil {
		return cfg, current, "", "", false, fmt.Errorf("refresh IMS identity after 403: %w", err)
	}
	impu := refreshedISIMPublicIdentity(id, cfg.Profile)
	if strings.TrimSpace(id.IMPI) == "" || impu == "" || strings.TrimSpace(id.Domain) == "" {
		return cfg, current, "", "", false, errors.New("refresh IMS identity after 403: incomplete ISIM identity")
	}
	if strings.TrimSpace(id.IMPI) == strings.TrimSpace(current.IMPI) &&
		impu == strings.TrimSpace(current.IMPU) &&
		strings.TrimSpace(id.Domain) == strings.TrimSpace(current.Domain) {
		return cfg, current, "", "", false, nil
	}
	prepared := clonePreparedSession(cfg.Prepared)
	prepared.Profile = cfg.Profile
	if cfg.Prepared != nil {
		prepared.Profile = cfg.Prepared.Profile
	}
	prepared.IMSIdentity = identity.IMSIdentityResolution{
		RequestedSource:  identity.IMSIdentitySourceISIM,
		ActualSource:     identity.IMSIdentitySourceISIM,
		AKAAppPreference: identity.AKAAppPreferenceISIMStrict,
		Applied:          true,
		IMPI:             strings.TrimSpace(id.IMPI),
		IMPU:             impu,
		Domain:           strings.TrimSpace(id.Domain),
	}
	nextCfg := cfg
	nextCfg.Prepared = &prepared
	nextProfile, err := r.profileFromConfig(nextCfg)
	if err != nil {
		return cfg, current, "", "", false, err
	}
	registrarURI := firstRuntimeNonEmpty(r.RegistrarURI, registrarURIForProfile(nextProfile))
	contactURI := firstRuntimeNonEmpty(r.ContactURI, r.contactURIForProfile(nextProfile))
	if registrarURI == "" || contactURI == "" {
		return cfg, current, "", "", false, errors.New("refresh IMS identity after 403: registrar URI or contact URI is empty")
	}
	return nextCfg, nextProfile, registrarURI, contactURI, true, nil
}

func clonePreparedSession(in *identity.PreparedSession) identity.PreparedSession {
	if in == nil {
		return identity.PreparedSession{}
	}
	out := *in
	out.PCSCFFQDNs = append([]string(nil), in.PCSCFFQDNs...)
	out.Fallbacks = append([]identity.FallbackMetadata(nil), in.Fallbacks...)
	return out
}

func refreshedISIMPublicIdentity(id identity.Identity, profile identity.Profile) string {
	domain := strings.ToLower(strings.TrimSpace(id.Domain))
	imsi := strings.TrimSpace(profile.IMSI)
	for _, impu := range id.IMPU {
		impu = strings.TrimSpace(impu)
		if impu == "" {
			continue
		}
		lower := strings.ToLower(impu)
		if imsi != "" && strings.Contains(impu, imsi) {
			return impu
		}
		if domain != "" && strings.Contains(lower, "@"+domain) {
			return impu
		}
	}
	if len(id.IMPU) == 0 {
		return ""
	}
	return strings.TrimSpace(id.IMPU[0])
}

func (r WireIMSRegistrar) resolverForConfig(cfg IMSRegistrationConfig) voiceclient.SIPServerResolver {
	if r.Resolver != nil {
		return r.Resolver
	}
	if candidates := preparedPCSCFCandidates(cfg); len(candidates) > 0 {
		return preparedPCSCFResolver{
			Candidates: candidates,
			DNSServers: append([]string(nil), cfg.Tunnel.DNSServers...),
			LocalAddr:  r.dnsLocalAddrForConfig(cfg),
			Timeout:    r.Timeout,
		}
	}
	if len(cfg.Tunnel.DNSServers) == 0 {
		return nil
	}
	return voiceclient.NetSIPResolver{
		DNSServers: append([]string(nil), cfg.Tunnel.DNSServers...),
		LocalAddr:  r.dnsLocalAddrForConfig(cfg),
		Timeout:    r.Timeout,
	}
}

type preparedPCSCFResolver struct {
	Candidates []string
	DNSServers []string
	LocalAddr  string
	Timeout    time.Duration
}

func (r preparedPCSCFResolver) ResolveSIPServer(ctx context.Context, network, uri string) (string, error) {
	targets, err := r.ResolveSIPServers(ctx, network, uri)
	if err != nil {
		return "", err
	}
	if len(targets) == 0 {
		return "", errors.New("SIP resolver returned no P-CSCF targets")
	}
	return targets[0], nil
}

func (r preparedPCSCFResolver) ResolveSIPServers(ctx context.Context, network, uri string) ([]string, error) {
	resolver := voiceclient.NetSIPResolver{
		DNSServers: append([]string(nil), r.DNSServers...),
		LocalAddr:  r.LocalAddr,
		Timeout:    r.Timeout,
	}
	var out []string
	var lastErr error
	for _, candidate := range r.Candidates {
		candidateURI := pcscfCandidateSIPURI(candidate)
		if candidateURI == "" {
			continue
		}
		targets, err := resolver.ResolveSIPServers(ctx, network, candidateURI)
		if err != nil {
			lastErr = err
			continue
		}
		out = appendRuntimeTargets(out, targets...)
	}
	if len(out) == 0 && strings.TrimSpace(uri) != "" {
		targets, err := resolver.ResolveSIPServers(ctx, network, uri)
		if err != nil {
			lastErr = err
		} else {
			out = appendRuntimeTargets(out, targets...)
		}
	}
	if len(out) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return out, nil
}

func (r WireIMSRegistrar) sipLocalAddrForConfig(cfg IMSRegistrationConfig) string {
	if local := strings.TrimSpace(r.LocalAddr); local != "" {
		return local
	}
	host := tunnelInnerHost(cfg.Tunnel.LocalInnerIP)
	if host == "" {
		return ""
	}
	port := r.ContactPort
	if port <= 0 {
		port = 5060
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func (r WireIMSRegistrar) dnsLocalAddrForConfig(cfg IMSRegistrationConfig) string {
	host := tunnelInnerHost(cfg.Tunnel.LocalInnerIP)
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, "0")
}

func tunnelInnerHost(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if ip, _, err := net.ParseCIDR(value); err == nil {
		return ip.String()
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return strings.Trim(host, "[] ")
	}
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return ip.String()
	}
	return ""
}

func preparedPCSCFCandidates(cfg IMSRegistrationConfig) []string {
	out := appendRuntimeTargets(nil, cfg.Tunnel.PCSCFServers...)
	if cfg.Prepared != nil {
		out = appendRuntimeTargets(out, cfg.Prepared.PCSCFFQDNs...)
	}
	return out
}

func pcscfCandidateSIPURI(candidate string) string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return ""
	}
	lower := strings.ToLower(candidate)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") {
		return candidate
	}
	if ip := net.ParseIP(strings.Trim(candidate, "[]")); ip != nil && strings.Contains(ip.String(), ":") {
		return "sip:[" + ip.String() + "]"
	}
	return "sip:" + candidate
}

func appendRuntimeTargets(out []string, targets ...string) []string {
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		duplicate := false
		for _, existing := range out {
			if existing == target {
				duplicate = true
				break
			}
		}
		if !duplicate {
			out = append(out, target)
		}
	}
	return out
}

type imsRegistrationMaintenance struct {
	flow          *voiceclient.WireSIPFlow
	session       voiceclient.RegisterSession
	config        WireIMSRegistrar
	runtimeConfig IMSRegistrationConfig
	profile       voiceclient.IMSProfile

	recoverMu      sync.Mutex
	mu             sync.Mutex
	registered     bool
	statusCode     int
	reason         string
	binding        voiceclient.RegistrationBinding
	registeredAt   time.Time
	nextCSeq       int
	authHeader     string
	authHeaderName string
	authState      voiceclient.DigestAuthState
	recoveryCount  int
	recoveryState  IMSRegistrationRecoveryState
	waitFunc       imsRegistrationWaitFunc
	cancel         context.CancelFunc
	done           chan struct{}
	wg             sync.WaitGroup
	inboundCancel  context.CancelFunc
	inboundDone    chan struct{}
	closed         bool
}

func (m *imsRegistrationMaintenance) BindInbound(handler voicehost.IMSMessageHandler) error {
	if m == nil || m.flow == nil {
		return errors.New("IMS inbound flow unavailable")
	}
	if handler == nil {
		return errors.New("IMS inbound message handler unavailable")
	}
	m.mu.Lock()
	binding := m.binding
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return errors.New("IMS registration maintenance closed")
	}
	server := &voicehost.IMSInboundWireServer{
		MessageHandler: voicehost.IMSMessageHandlerFunc(func(ctx context.Context, req voicehost.IMSMessageRequest) (voicehost.IMSMessageResult, error) {
			result, err := handler.HandleIMSMessage(ctx, req)
			if report, ok := imsInboundDeliveryReport(req, result); ok {
				// 3GPP TS 24.341 requires an empty final response for the
				// inbound transaction followed by a separate MESSAGE carrying
				// RP-ACK/RP-ERROR. Starting this asynchronously also ensures the
				// WireSIPFlow can write the SIP response and release its lock
				// before the report starts another client transaction.
				result.ContentType = ""
				result.Body = nil
				go m.sendInboundDeliveryReport(handler, report)
			}
			return result, err
		}),
		ContactURI: binding.ContactURI,
		UserAgent:  firstRuntimeNonEmpty(m.config.UserAgent, m.profile.UserAgent, "vowifi-go"),
	}
	if infoHandler, ok := handler.(voicehost.IMSInfoHandler); ok {
		server.InfoHandler = infoHandler
	}
	if byeHandler, ok := handler.(voicehost.IMSByeHandler); ok {
		server.ByeHandler = byeHandler
	}
	if provider, ok := handler.(interface {
		IMSInboundVoiceAgent() *voicehost.IMSInboundAgent
	}); ok {
		server.Agent = provider.IMSInboundVoiceAgent()
	}
	if err := m.flow.SetIncomingRequestHandler(server.HandleRequestWire); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("IMS registration maintenance closed")
	}
	if m.inboundCancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	m.inboundCancel = cancel
	m.inboundDone = done
	go func() {
		defer close(done)
		_ = m.flow.ServeIncomingRequests(ctx)
	}()
	return nil
}

type imsInboundDeliveryReportRequest struct {
	gatewayURI  string
	inReplyTo   string
	contentType string
	body        []byte
}

func imsInboundDeliveryReport(req voicehost.IMSMessageRequest, result voicehost.IMSMessageResult) (imsInboundDeliveryReportRequest, bool) {
	if result.StatusCode < 200 || result.StatusCode >= 300 || len(result.Body) == 0 {
		return imsInboundDeliveryReportRequest{}, false
	}
	contentType := strings.TrimSpace(result.ContentType)
	if contentType == "" {
		return imsInboundDeliveryReportRequest{}, false
	}
	gatewayURI := runtimeSIPHeaderURI(runtimeSIPHeaderValue(req.Headers, "P-Asserted-Identity"))
	if gatewayURI == "" {
		gatewayURI = strings.TrimSpace(req.FromURI)
	}
	return imsInboundDeliveryReportRequest{
		gatewayURI:  gatewayURI,
		inReplyTo:   strings.TrimSpace(req.CallID),
		contentType: contentType,
		body:        append([]byte(nil), result.Body...),
	}, true
}

func (m *imsRegistrationMaintenance) sendInboundDeliveryReport(handler voicehost.IMSMessageHandler, report imsInboundDeliveryReportRequest) {
	result := voicehost.IMSMessageDeliveryReportResult{
		InReplyTo: report.inReplyTo,
		Time:      time.Now(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := m.roundTripInboundDeliveryReport(ctx, report)
	result.StatusCode = resp.StatusCode
	result.Reason = strings.TrimSpace(resp.Reason)
	if err != nil {
		result.Error = err.Error()
	} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Error = fmt.Sprintf("IMS SMS delivery report rejected: %d %s", resp.StatusCode, strings.TrimSpace(resp.Reason))
	}
	if observer, ok := handler.(voicehost.IMSMessageDeliveryReportObserver); ok {
		observer.HandleIMSMessageDeliveryReportResult(context.Background(), result)
	}
}

func (m *imsRegistrationMaintenance) roundTripInboundDeliveryReport(ctx context.Context, report imsInboundDeliveryReportRequest) (voiceclient.SIPResponse, error) {
	if m == nil || m.flow == nil {
		return voiceclient.SIPResponse{}, errors.New("IMS inbound delivery report flow unavailable")
	}
	if strings.TrimSpace(report.gatewayURI) == "" {
		return voiceclient.SIPResponse{}, errors.New("IMS inbound delivery report gateway URI is empty")
	}
	m.mu.Lock()
	binding := m.binding
	m.mu.Unlock()
	callIDBase := strings.TrimSpace(report.inReplyTo)
	if callIDBase == "" {
		callIDBase = "ims-sms"
	}
	msg, err := voiceclient.BuildMessageRequest(voiceclient.DialogRequestConfig{
		Profile:         m.profile,
		Registration:    binding,
		ContactURI:      binding.ContactURI,
		LocalURI:        firstRuntimeNonEmpty(binding.PublicIdentity, m.profile.IMPU),
		RemoteURI:       report.gatewayURI,
		RemoteTargetURI: report.gatewayURI,
		CallID:          fmt.Sprintf("%s-rp-%d", callIDBase, time.Now().UnixNano()),
		LocalTag:        "sms-rp",
		CSeq:            1,
		UserAgent:       firstRuntimeNonEmpty(m.config.UserAgent, m.profile.UserAgent, "vowifi-go"),
	}, report.contentType, report.body)
	if err != nil {
		return voiceclient.SIPResponse{}, err
	}
	msg.Headers["In-Reply-To"] = report.inReplyTo
	msg.Headers["Content-Transfer-Encoding"] = "binary"
	return voiceclient.RoundTripRequestWithDigestAuth(ctx, m.flow, msg)
}

func runtimeSIPHeaderValue(headers map[string][]string, name string) string {
	for key, values := range headers {
		if !strings.EqualFold(strings.TrimSpace(key), strings.TrimSpace(name)) {
			continue
		}
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		}
	}
	return ""
}

func runtimeSIPHeaderURI(value string) string {
	value = strings.TrimSpace(value)
	if start := strings.IndexByte(value, '<'); start >= 0 {
		if end := strings.IndexByte(value[start+1:], '>'); end >= 0 {
			return strings.TrimSpace(value[start+1 : start+1+end])
		}
	}
	if comma := strings.IndexByte(value, ','); comma >= 0 {
		value = value[:comma]
	}
	if semi := strings.IndexByte(value, ';'); semi >= 0 {
		value = value[:semi]
	}
	return strings.Trim(strings.TrimSpace(value), "<>")
}

func newIMSRegistrationMaintenance(flow *voiceclient.WireSIPFlow, session voiceclient.RegisterSession, result voiceclient.RegisterResult, config WireIMSRegistrar, runtimeConfig IMSRegistrationConfig, profile voiceclient.IMSProfile, registeredAt time.Time) *imsRegistrationMaintenance {
	if flow == nil {
		return nil
	}
	nextCSeq := result.NextCSeq
	if nextCSeq <= 0 {
		nextCSeq = 1
	}
	m := &imsRegistrationMaintenance{
		flow:          flow,
		session:       session,
		config:        config,
		runtimeConfig: runtimeConfig,
		profile:       profile,

		registered:     result.Registered,
		statusCode:     result.StatusCode,
		reason:         result.Reason,
		binding:        result.Binding,
		registeredAt:   registeredAt,
		nextCSeq:       nextCSeq,
		authHeader:     result.AuthHeader,
		authHeaderName: result.AuthHeaderName,
		authState:      result.AuthState,
	}
	if result.Registered && (!config.DisableRefresh || !config.DisableKeepalive) {
		ctx, cancel := context.WithCancel(context.Background())
		m.cancel = cancel
		m.done = make(chan struct{})
		if !config.DisableRefresh {
			m.wg.Add(1)
			go func() {
				defer m.wg.Done()
				m.refreshLoop(ctx)
			}()
		}
		if !config.DisableKeepalive {
			m.wg.Add(1)
			go func() {
				defer m.wg.Done()
				m.keepaliveLoop(ctx)
			}()
		}
		go func() {
			m.wg.Wait()
			close(m.done)
		}()
	}
	return m
}

func (m *imsRegistrationMaintenance) Recover(ctx context.Context) (IMSRegistrationResult, error) {
	if m == nil {
		return IMSRegistrationResult{}, errors.New("IMS registration maintenance unavailable")
	}
	if err := m.recoverRegistration(ctx, errors.New("requested IMS registration recovery"), 0); err != nil {
		return IMSRegistrationResult{}, err
	}
	return m.result("IMS registration recovered"), nil
}

func (m *imsRegistrationMaintenance) result(defaultReason string) IMSRegistrationResult {
	if m == nil {
		return IMSRegistrationResult{}
	}
	m.mu.Lock()
	registered := m.registered
	statusCode := m.statusCode
	reason := m.reason
	binding := m.binding
	registeredAt := m.registeredAt
	session := m.session
	recoveryState := m.recoveryState
	m.mu.Unlock()

	if statusCode == 0 && registered {
		statusCode = 200
	}
	expiresAt, refreshDelay, nextRefreshAt := imsRegistrationSchedule(m.config, binding, session, registeredAt, registered)
	voiceTransport := m.config.voiceTransport(m.runtimeConfig, m.profile, binding, m.flow)
	smsTransport := m.config.smsTransport(m.runtimeConfig, m.profile, binding, voiceTransport)
	ussdTransport := m.config.ussdTransport(m.runtimeConfig, m.profile, binding, voiceTransport)
	return IMSRegistrationResult{
		Registered:     registered,
		StatusCode:     statusCode,
		Reason:         firstRuntimeNonEmpty(reason, defaultReason),
		Server:         firstRuntimeNonEmpty(binding.PublicIdentity, m.profile.Domain),
		Profile:        m.profile,
		Binding:        binding,
		RegisteredAt:   registeredAt,
		ExpiresAt:      expiresAt,
		RefreshDelay:   refreshDelay,
		NextRefreshAt:  nextRefreshAt,
		RecoveryState:  recoveryState,
		VoiceTransport: voiceTransport,
		SMSTransport:   smsTransport,
		USSDTransport:  ussdTransport,
		BindInbound:    m.BindInbound,
		Close:          m.Close,
		Recover:        m.Recover,
	}
}

func (m *imsRegistrationMaintenance) Close(ctx context.Context) error {
	if m == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	cancel := m.cancel
	done := m.done
	inboundCancel := m.inboundCancel
	inboundDone := m.inboundDone
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if inboundCancel != nil {
		inboundCancel()
	}
	var waitErr error
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			waitErr = errors.Join(waitErr, ctx.Err())
		}
	}
	if inboundDone != nil {
		select {
		case <-inboundDone:
		case <-ctx.Done():
			waitErr = errors.Join(waitErr, ctx.Err())
		}
	}

	m.mu.Lock()
	registered := m.registered
	req := voiceclient.DeregisterRequest{
		Binding:        m.binding,
		CSeq:           m.nextCSeq,
		AuthHeader:     m.authHeader,
		AuthHeaderName: m.authHeaderName,
		AuthState:      m.authState,
	}
	m.registered = false
	m.mu.Unlock()

	var deregisterErr error
	if registered && ctx.Err() == nil {
		deregisterTimeout := m.config.Timeout
		if deregisterTimeout <= 0 || deregisterTimeout > imsCloseDeregisterTimeout {
			deregisterTimeout = imsCloseDeregisterTimeout
		}
		deregisterCtx, cancelDeregister := context.WithTimeout(ctx, deregisterTimeout)
		_, deregisterErr = m.session.Deregister(deregisterCtx, req)
		bestEffortTimeout := errors.Is(deregisterCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil
		cancelDeregister()
		if bestEffortTimeout {
			// The remote endpoint did not acknowledge the best-effort
			// deregistration. Continue with mandatory local cleanup without
			// treating the bounded wait as a teardown failure.
			deregisterErr = nil
		}
	}
	return errors.Join(waitErr, deregisterErr, cleanupIMSRegistrationSecurityPlans(ctx, m.session.SecurityPlanInstaller), m.flow.Close())
}

func cleanupIMSRegistrationSecurityPlans(ctx context.Context, installer voiceclient.SecurityPlanInstaller) error {
	cleaner, ok := installer.(interface {
		Cleanup(context.Context) error
	})
	if !ok {
		return nil
	}
	return cleaner.Cleanup(ctx)
}

func (m *imsRegistrationMaintenance) refreshLoop(ctx context.Context) {
	for {
		if !m.wait(ctx, m.refreshDelay()) {
			return
		}
		for {
			if err := m.refresh(ctx); err != nil {
				if !m.wait(ctx, m.refreshRetryInterval()) {
					return
				}
				continue
			}
			break
		}
	}
}

func (m *imsRegistrationMaintenance) keepaliveLoop(ctx context.Context) {
	for {
		if !m.wait(ctx, m.keepaliveInterval()) {
			return
		}
		if !m.isRegistered() {
			continue
		}
		if err := m.flow.SendCRLFKeepalive(ctx); err != nil {
			if ctx.Err() != nil || errors.Is(err, voiceclient.ErrSIPFlowClosed) {
				return
			}
			_ = m.recoverRegistration(ctx, err, 0)
		}
	}
}

func (m *imsRegistrationMaintenance) wait(ctx context.Context, delay time.Duration) bool {
	if m != nil && m.waitFunc != nil {
		return m.waitFunc(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (m *imsRegistrationMaintenance) refresh(ctx context.Context) error {
	m.mu.Lock()
	if !m.registered {
		m.mu.Unlock()
		return nil
	}
	req := voiceclient.RefreshRequest{
		Binding:        m.binding,
		CSeq:           m.nextCSeq,
		AuthHeader:     m.authHeader,
		AuthHeaderName: m.authHeaderName,
		AuthState:      m.authState,
	}
	m.mu.Unlock()

	result, err := m.session.Refresh(ctx, req)
	if err != nil {
		// A refresh is normally sent before the current binding expires. A
		// transient timeout must not tear down the protected server socket:
		// that socket is still the only path for incoming calls and SMS while
		// the registrar binding remains valid. Keep serving inbound traffic and
		// let refreshLoop retry; perform full recovery once the binding expires.
		if m.canKeepCurrentBindingAfterRefreshError(err) {
			return err
		}
		if m.shouldRecoverRegistration(result, err) {
			return m.recoverRegistration(ctx, err, result.RetryAfter)
		}
		return err
	}
	m.mu.Lock()
	if result.Refreshed {
		m.registered = true
		m.statusCode = result.StatusCode
		m.reason = result.Reason
		m.binding = result.Binding
		m.registeredAt = time.Now()
		m.nextCSeq = result.NextCSeq
		m.authHeader = result.AuthHeader
		m.authHeaderName = result.AuthHeaderName
		m.authState = result.AuthState
	}
	m.mu.Unlock()
	return nil
}

func (m *imsRegistrationMaintenance) canKeepCurrentBindingAfterRefreshError(err error) bool {
	if m == nil || err == nil {
		return false
	}
	var netErr net.Error
	if !errors.Is(err, context.DeadlineExceeded) &&
		!errors.Is(err, voiceclient.ErrSIPFinalResponseTimeout) &&
		(!errors.As(err, &netErr) || !netErr.Timeout()) {
		return false
	}
	m.mu.Lock()
	registered := m.registered
	registeredAt := m.registeredAt
	expires := m.binding.Expires
	if expires <= 0 {
		expires = m.session.Expires
	}
	m.mu.Unlock()
	if !registered || registeredAt.IsZero() {
		return false
	}
	if expires <= 0 {
		expires = 3600
	}
	return time.Now().Before(registeredAt.Add(time.Duration(expires) * time.Second))
}

func (m *imsRegistrationMaintenance) recoverRegistration(ctx context.Context, cause error, retryAfter time.Duration) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	m.recoverMu.Lock()
	defer m.recoverMu.Unlock()

	m.mu.Lock()
	if m.closed || !m.registered {
		m.mu.Unlock()
		return nil
	}
	if !m.recoveryState.NextAttemptAt.IsZero() {
		delay := time.Until(m.recoveryState.NextAttemptAt)
		m.mu.Unlock()
		if delay > 0 && !m.wait(ctx, delay) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return context.Canceled
		}
		m.mu.Lock()
		if m.closed || !m.registered {
			m.mu.Unlock()
			return nil
		}
	}
	m.mu.Unlock()
	switchedTarget, err := m.resetFlowForRecovery(ctx)
	if err != nil {
		return err
	}
	if retryAfter > 0 && !switchedTarget {
		m.scheduleRecoveryRetryAfter(cause, retryAfter)
		if !m.wait(ctx, retryAfter) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return context.Canceled
		}
	}
	m.mu.Lock()
	if m.closed || !m.registered {
		m.mu.Unlock()
		return nil
	}
	m.recoveryCount++
	m.recoveryState.Attempts = m.recoveryCount
	m.recoveryState.LastReason = strings.TrimSpace(fmt.Sprint(cause))
	m.recoveryState.LastError = ""
	m.recoveryState.LastAttemptAt = time.Now()
	m.recoveryState.LastSwitchedTarget = switchedTarget
	session := m.session
	session.CallID = imsRecoveryCallID(session.CallID, m.recoveryCount)
	m.mu.Unlock()

	result, err := session.Register(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		m.recordRecoveryFailure(cause, err)
		return fmt.Errorf("IMS registration recovery failed after %v: %w", cause, err)
	}
	if !result.Registered {
		m.mu.Lock()
		m.registered = false
		m.statusCode = result.StatusCode
		m.reason = result.Reason
		m.recordRecoveryFailureLocked(cause, fmt.Errorf("%d %s", result.StatusCode, result.Reason))
		m.mu.Unlock()
		return fmt.Errorf("IMS registration recovery did not register: %d %s", result.StatusCode, result.Reason)
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.session = session
	m.registered = true
	m.statusCode = result.StatusCode
	m.reason = result.Reason
	m.binding = result.Binding
	m.registeredAt = time.Now()
	m.nextCSeq = result.NextCSeq
	m.authHeader = result.AuthHeader
	m.authHeaderName = result.AuthHeaderName
	m.authState = result.AuthState
	m.recordRecoverySuccessLocked()
	m.mu.Unlock()
	return nil
}

func (m *imsRegistrationMaintenance) scheduleRecoveryRetryAfter(cause error, delay time.Duration) {
	if m == nil || delay <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || !m.registered {
		return
	}
	m.recoveryState.LastReason = strings.TrimSpace(fmt.Sprint(cause))
	m.recoveryState.NextAttemptAt = time.Now().Add(delay)
}

func (m *imsRegistrationMaintenance) recordRecoveryFailure(cause, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recordRecoveryFailureLocked(cause, err)
}

func (m *imsRegistrationMaintenance) recordRecoveryFailureLocked(cause, err error) {
	if m == nil {
		return
	}
	m.recoveryState.ConsecutiveFailures++
	m.recoveryState.LastReason = strings.TrimSpace(fmt.Sprint(cause))
	m.recoveryState.LastError = strings.TrimSpace(fmt.Sprint(err))
	if m.recoveryState.LastAttemptAt.IsZero() {
		m.recoveryState.LastAttemptAt = time.Now()
	}
	delay := m.recoveryBackoffDelayLocked()
	if delay > 0 {
		m.recoveryState.NextAttemptAt = time.Now().Add(delay)
	} else {
		m.recoveryState.NextAttemptAt = time.Time{}
	}
}

func (m *imsRegistrationMaintenance) recordRecoverySuccessLocked() {
	if m == nil {
		return
	}
	m.recoveryState.ConsecutiveFailures = 0
	m.recoveryState.LastError = ""
	m.recoveryState.NextAttemptAt = time.Time{}
	m.recoveryState.LastSucceededAt = time.Now()
}

func (m *imsRegistrationMaintenance) recoveryBackoffDelayLocked() time.Duration {
	if m == nil || m.recoveryState.ConsecutiveFailures <= 0 {
		return 0
	}
	base := m.config.RecoveryBackoffInitial
	if base <= 0 {
		return 0
	}
	maxDelay := m.config.RecoveryBackoffMax
	if maxDelay <= 0 {
		maxDelay = 30 * time.Second
	}
	delay := base
	for i := 1; i < m.recoveryState.ConsecutiveFailures; i++ {
		if delay >= maxDelay/2 {
			delay = maxDelay
			break
		}
		delay *= 2
	}
	if delay > maxDelay {
		delay = maxDelay
	}
	return delay
}

func (m *imsRegistrationMaintenance) resetFlowForRecovery(ctx context.Context) (bool, error) {
	switched, err := m.flow.ResetToNextTarget()
	if err == nil {
		return switched, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	return false, fmt.Errorf("IMS registration recovery reset failed: %w", err)
}

func (m *imsRegistrationMaintenance) shouldRecoverRegistration(result voiceclient.RefreshResult, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, voiceclient.ErrSIPFlowClosed) ||
		errors.Is(err, voiceclient.ErrInvalidChallenge) || errors.Is(err, voiceclient.ErrInvalidAuthenticationInfo) {
		return false
	}
	if errors.Is(err, voiceclient.ErrRegistrationRejected) {
		return ClassifyIMSRegisterResponse(result.StatusCode, result.RetryAfter).Recoverable
	}
	return true
}

func isRecoverableIMSRegistrationStatus(code int) bool {
	return ClassifyIMSRegisterResponse(code, 0).Recoverable
}

func isBackoffIMSRegisterStatus(code int) bool {
	switch code {
	case 408, 430, 480, 481, 500, 502, 503, 504, 580:
		return true
	default:
		return code >= 500 && code < 600
	}
}

func imsRecoveryCallID(base string, n int) string {
	base = strings.TrimSpace(base)
	if base == "" {
		base = "vowifi-go-register"
	}
	if n <= 0 {
		n = 1
	}
	return base + "-recovery-" + strconv.Itoa(n)
}

func (m *imsRegistrationMaintenance) isRegistered() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.registered
}

func (m *imsRegistrationMaintenance) refreshDelay() time.Duration {
	m.mu.Lock()
	expires := m.binding.Expires
	sessionExpires := m.session.Expires
	m.mu.Unlock()
	return imsRegistrationRefreshDelay(m.config, expires, sessionExpires)
}

func imsRegistrationSchedule(config WireIMSRegistrar, binding voiceclient.RegistrationBinding, session voiceclient.RegisterSession, registeredAt time.Time, registered bool) (time.Time, time.Duration, time.Time) {
	if !registered || registeredAt.IsZero() {
		return time.Time{}, 0, time.Time{}
	}
	expires := binding.Expires
	if expires <= 0 {
		expires = session.Expires
	}
	if expires <= 0 {
		expires = 3600
	}
	expiresAt := registeredAt.Add(time.Duration(expires) * time.Second)
	if config.DisableRefresh {
		return expiresAt, 0, time.Time{}
	}
	refreshDelay := imsRegistrationRefreshDelay(config, binding.Expires, session.Expires)
	if refreshDelay <= 0 {
		return expiresAt, 0, time.Time{}
	}
	return expiresAt, refreshDelay, registeredAt.Add(refreshDelay)
}

func imsRegistrationRefreshDelay(config WireIMSRegistrar, bindingExpires, sessionExpires int) time.Duration {
	if config.RefreshInterval > 0 {
		return config.RefreshInterval
	}
	expires := bindingExpires
	if expires <= 0 {
		expires = sessionExpires
	}
	if expires <= 0 {
		expires = 3600
	}
	ttl := time.Duration(expires) * time.Second
	lead := config.RefreshLead
	if lead <= 0 {
		// SIP registrations are conventionally refreshed around half their
		// lifetime. Waiting until one minute before a one-hour expiry proved too
		// late for carriers that retire the downlink binding ahead of Expires.
		return ttl / 2
	}
	delay := ttl - lead
	if delay <= 0 {
		delay = ttl / 2
	}
	if delay <= 0 {
		delay = 30 * time.Second
	}
	return delay
}

func (m *imsRegistrationMaintenance) refreshRetryInterval() time.Duration {
	if m.config.RefreshRetryInterval > 0 {
		return m.config.RefreshRetryInterval
	}
	return 30 * time.Second
}

func (m *imsRegistrationMaintenance) keepaliveInterval() time.Duration {
	if m.config.KeepaliveInterval > 0 {
		return m.config.KeepaliveInterval
	}
	return 25 * time.Second
}

func (r WireIMSRegistrar) smsTransport(cfg IMSRegistrationConfig, profile voiceclient.IMSProfile, binding voiceclient.RegistrationBinding, voiceTransport voiceclient.SIPRequestTransport) messaging.SMSTransport {
	if r.SMSTransport != nil {
		return r.SMSTransport
	}
	if r.SMSFactory != nil {
		return r.SMSFactory(cfg, profile, binding, voiceTransport)
	}
	if voiceTransport == nil {
		return nil
	}
	return messaging.IMSSMSTransport{
		Transport:    voiceTransport,
		Profile:      profile,
		Registration: binding,
		Domain:       profile.Domain,
		SMSC:         strings.TrimSpace(cfg.Profile.SMSC),
		UserAgent:    firstRuntimeNonEmpty(r.UserAgent, profile.UserAgent),
	}
}

func (r WireIMSRegistrar) ussdTransport(cfg IMSRegistrationConfig, profile voiceclient.IMSProfile, binding voiceclient.RegistrationBinding, voiceTransport voiceclient.SIPRequestTransport) messaging.USSDTransport {
	if r.USSDTransport != nil {
		return r.USSDTransport
	}
	if r.USSDFactory != nil {
		return r.USSDFactory(cfg, profile, binding, voiceTransport)
	}
	if voiceTransport == nil {
		return nil
	}
	return &messaging.IMSUSSDTransport{
		Transport:    voiceTransport,
		Profile:      profile,
		Registration: binding,
		Domain:       profile.Domain,
		UserAgent:    firstRuntimeNonEmpty(r.UserAgent, profile.UserAgent),
	}
}

func (r WireIMSRegistrar) profileFromConfig(cfg IMSRegistrationConfig) (voiceclient.IMSProfile, error) {
	preparedIdentity := identity.IMSIdentityResolution{}
	if cfg.Prepared != nil {
		preparedIdentity = cfg.Prepared.IMSIdentity
	}
	imsi := strings.TrimSpace(cfg.Profile.IMSI)
	if imsi == "" && cfg.Prepared != nil {
		imsi = strings.TrimSpace(cfg.Prepared.Profile.IMSI)
	}
	domain := firstRuntimeNonEmpty(preparedIdentity.Domain, defaultIMSRealm(cfg))
	impi := firstRuntimeNonEmpty(preparedIdentity.IMPI, defaultIMPI(imsi, domain))
	impu := firstRuntimeNonEmpty(preparedIdentity.IMPU, defaultIMPU(impi, domain))
	if impi == "" {
		return voiceclient.IMSProfile{}, errors.New("IMS private identity is empty")
	}
	if impu == "" {
		return voiceclient.IMSProfile{}, errors.New("IMS public identity is empty")
	}
	accessNetworkInfo, visitedNetworkID := imsRegistrationNetworkHeaders(cfg)
	return voiceclient.IMSProfile{
		IMPI:              impi,
		IMPU:              impu,
		Domain:            domain,
		LocalIP:           firstRuntimeNonEmpty(r.ContactHost, cfg.Tunnel.LocalInnerIP),
		InstanceID:        imsInstanceID(cfg, impi),
		UserAgent:         firstRuntimeNonEmpty(r.UserAgent, "vowifi-go"),
		AccessNetworkInfo: accessNetworkInfo,
		VisitedNetworkID:  visitedNetworkID,
	}, nil
}

func imsInstanceID(cfg IMSRegistrationConfig, impi string) string {
	imei := strings.TrimSpace(cfg.Profile.IMEI)
	if imei == "" && cfg.Prepared != nil {
		imei = strings.TrimSpace(cfg.Prepared.Profile.IMEI)
	}
	if len(imei) == 15 {
		valid := true
		for _, r := range imei {
			if r < '0' || r > '9' {
				valid = false
				break
			}
		}
		if valid {
			return "urn:gsma:imei:" + imei[:8] + "-" + imei[8:14] + "-" + imei[14:]
		}
	}
	return stableIMSUUID(impi)
}

func stableIMSUUID(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

func imsAKAAppPreferenceFromConfig(cfg IMSRegistrationConfig) string {
	if cfg.Prepared == nil {
		return ""
	}
	return strings.TrimSpace(cfg.Prepared.IMSIdentity.AKAAppPreference)
}

func imsRegistrationNetworkHeaders(cfg IMSRegistrationConfig) (string, string) {
	imsi := strings.TrimSpace(cfg.Profile.IMSI)
	if imsi == "" && cfg.Prepared != nil {
		imsi = strings.TrimSpace(cfg.Prepared.Profile.IMSI)
	}
	mcc, mnc := cfgMCCMNC(cfg)
	profile := carrier.IMSAccessProfileForSubscriber(carrier.IMSAccessProfileInput{
		IMSI: imsi,
		MCC:  mcc,
		MNC:  mnc,
	})
	return strings.TrimSpace(profile.AccessNetworkInfo), strings.TrimSpace(profile.VisitedNetworkID)
}

func (r WireIMSRegistrar) contactURIForProfile(profile voiceclient.IMSProfile) string {
	host := strings.TrimSpace(r.ContactHost)
	if host == "" {
		host = strings.TrimSpace(profile.LocalIP)
	}
	if host == "" {
		return ""
	}
	port := r.ContactPort
	if port <= 0 {
		port = 5060
	}
	user := sipUser(profile.IMPU)
	if user == "" {
		user = strings.TrimSpace(profile.IMPI)
	}
	if user == "" {
		user = "ue"
	}
	return "sip:" + user + "@" + formatSIPHost(host) + ":" + strconv.Itoa(port)
}

func registrarURIForProfile(profile voiceclient.IMSProfile) string {
	if strings.TrimSpace(profile.Domain) == "" {
		return ""
	}
	return "sip:" + strings.TrimSpace(profile.Domain)
}

func defaultIMSRealm(cfg IMSRegistrationConfig) string {
	mcc, mnc := cfgMCCMNC(cfg)
	if mcc == "" || mnc == "" {
		return ""
	}
	return fmt.Sprintf("ims.mnc%s.mcc%s.3gppnetwork.org", leftPadRuntime(mnc, 3), mcc)
}

func cfgMCCMNC(cfg IMSRegistrationConfig) (string, string) {
	mcc := strings.TrimSpace(cfg.Profile.MCC)
	mnc := strings.TrimSpace(cfg.Profile.MNC)
	imsi := strings.TrimSpace(cfg.Profile.IMSI)
	if cfg.Prepared != nil {
		if imsi == "" {
			imsi = strings.TrimSpace(cfg.Prepared.Profile.IMSI)
		}
		if mcc == "" {
			mcc = strings.TrimSpace(cfg.Prepared.Profile.MCC)
		}
		if mnc == "" {
			mnc = strings.TrimSpace(cfg.Prepared.Profile.MNC)
		}
		if mcc == "" {
			mcc = strings.TrimSpace(cfg.Prepared.EffectiveCarrier.MCC)
		}
		if mnc == "" {
			mnc = strings.TrimSpace(cfg.Prepared.EffectiveCarrier.MNC)
		}
	}
	if mcc == "" && len(imsi) >= 3 {
		mcc = imsi[:3]
	}
	if mnc == "" && len(imsi) >= 6 {
		mnc = imsi[3:6]
	}
	trimmedMNC := strings.TrimLeft(mnc, "0")
	if trimmedMNC == "" && mnc != "" {
		trimmedMNC = mnc
	}
	return mcc, trimmedMNC
}

func defaultIMPI(imsi, domain string) string {
	imsi = strings.TrimSpace(imsi)
	domain = strings.TrimSpace(domain)
	if imsi == "" {
		return ""
	}
	if domain == "" || strings.Contains(imsi, "@") {
		return imsi
	}
	return imsi + "@" + domain
}

func defaultIMPU(impi, domain string) string {
	impi = strings.TrimSpace(impi)
	domain = strings.TrimSpace(domain)
	if impi == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(impi), "sip:") || strings.HasPrefix(strings.ToLower(impi), "tel:") {
		return impi
	}
	if strings.Contains(impi, "@") {
		return "sip:" + impi
	}
	if domain != "" {
		return "sip:" + impi + "@" + domain
	}
	return "sip:" + impi
}

func sipUser(uri string) string {
	uri = strings.TrimSpace(uri)
	if strings.HasPrefix(strings.ToLower(uri), "sip:") {
		uri = uri[4:]
	}
	if user, _, ok := strings.Cut(uri, "@"); ok {
		return strings.TrimSpace(user)
	}
	return strings.TrimSpace(uri)
}

func leftPadRuntime(s string, n int) string {
	for len(s) < n {
		s = "0" + s
	}
	return s
}

func formatSIPHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}
