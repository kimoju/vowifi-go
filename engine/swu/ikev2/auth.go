package ikev2

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/kimoju/vowifi-go/engine/sim"
	"github.com/kimoju/vowifi-go/engine/swu/eapaka"
)

var (
	ErrInvalidAuthConfig   = errors.New("invalid ikev2 auth config")
	ErrInvalidAuthResponse = errors.New("invalid ikev2 auth response")
)

const (
	maxAKAControlFollowups  = 3
	maxFullAuthEAPExchanges = 8
)

type AuthConfig struct {
	Transport             InitTransport
	Init                  InitResult
	Keys                  IKEKeys
	InitiatorID           Identity
	ExpectedResponderID   *Identity
	RootCAs               *x509.CertPool
	EAPOnlyAuthentication bool
	RequireResponderCert  bool
	SendCertReq           bool
	CertReqCAs            []*x509.Certificate
	EAPIdentity           string
	EAPPseudonym          string
	EAPReauthIdentity     string
	ChildSA               SecurityAssociation
	ChildSPI              []byte
	TSi                   TrafficSelectors
	TSr                   TrafficSelectors
	Configuration         Configuration
	Random                io.Reader
	InitialIV             []byte
	EAPIdentityIV         []byte
	InitialMessageID      uint32
	MaxFragmentSize       int
}

type AuthResult struct {
	InitialRequestBytes   []byte
	InitialResponseBytes  []byte
	IdentityRequestBytes  []byte
	IdentityResponseBytes []byte
	InitialResponseInner  []Payload
	IdentityResponseInner []Payload
	EAPRequest            *eapaka.Packet
	EAPAfterIdentity      *eapaka.Packet
	EAPIdentityUsed       string
	IdentityTranscript    [][]byte
	NextMessageID         uint32
}

type AKAChallengeConfig struct {
	Transport           InitTransport
	Init                InitResult
	Keys                IKEKeys
	SIM                 sim.AKAProvider
	EAPKeys             eapaka.Keys
	Identity            string
	ExpectedNetworkName string
	Request             eapaka.Packet
	IdentityTranscript  [][]byte
	ChildSPI            []byte
	TSi                 TrafficSelectors
	TSr                 TrafficSelectors
	MessageID           uint32
	Random              io.Reader
	IV                  []byte
	EAPReauthIV         []byte
	EAPReauthCounter    uint16
	EAPReauthCounterOK  bool
	MaxFragmentSize     int
}

type AKAChallengeResult struct {
	RequestBytes             []byte
	ResponseBytes            []byte
	ResponseInner            []Payload
	EAPResponse              eapaka.Packet
	EAPNext                  *eapaka.Packet
	EAPKeys                  eapaka.Keys
	EAPEncryptedAttributes   []eapaka.Attribute
	EAPNextPseudonym         string
	EAPNextReauthID          string
	EAPReauthenticated       bool
	EAPReauthCounter         uint16
	EAPReauthCounterTooSmall bool
	EAPNotifications         []eapaka.Packet
	EAPClientError           bool
	ChildSA                  *ChildSAResult
	SyncFailure              bool
	AuthFailure              bool
	KDFNegotiated            bool
	NextMessageID            uint32
	FollowupRequestBytes     [][]byte
	FollowupResponseBytes    [][]byte
	FinalResponseBytes       []byte
	FinalResponseInner       []Payload
}

type FullAuthConfig struct {
	Transport             InitTransport
	Init                  InitResult
	Keys                  IKEKeys
	SIM                   sim.AKAProvider
	EAPKeys               eapaka.Keys
	InitiatorID           Identity
	ExpectedResponderID   *Identity
	RootCAs               *x509.CertPool
	EAPOnlyAuthentication bool
	RequireResponderCert  bool
	SendCertReq           bool
	CertReqCAs            []*x509.Certificate
	EAPIdentity           string
	ExpectedNetworkName   string
	EAPPseudonym          string
	EAPReauthIdentity     string
	EAPReauthCounter      uint16
	EAPReauthCounterOK    bool
	ChildSA               SecurityAssociation
	ChildSPI              []byte
	TSi                   TrafficSelectors
	TSr                   TrafficSelectors
	Configuration         Configuration
	Random                io.Reader
	InitialIV             []byte
	EAPIdentityIV         []byte
	EAPReauthIV           []byte
	InitialMessageID      uint32
	MaxFragmentSize       int
}

type FullAuthResult struct {
	Auth                     AuthResult
	IdentityExchanges        []EAPIdentityExchange
	AKAChallenges            []AKAChallengeResult
	ChildSA                  *ChildSAResult
	EAPKeys                  eapaka.Keys
	EAPLast                  *eapaka.Packet
	EAPNotifications         []eapaka.Packet
	EAPClientError           bool
	EAPNextPseudonym         string
	EAPNextReauthID          string
	EAPReauthenticated       bool
	EAPReauthCounter         uint16
	EAPReauthCounterTooSmall bool
	SyncFailure              bool
	AuthFailure              bool
	KDFNegotiations          int
	NextMessageID            uint32
	FinalResponseBytes       []byte
	FinalResponseInner       []Payload
}

type EAPIdentityExchange struct {
	Request       eapaka.Packet
	Response      eapaka.Packet
	Identity      string
	RequestBytes  []byte
	ResponseBytes []byte
	ResponseInner []Payload
	EAPNext       *eapaka.Packet
	Transcript    [][]byte
	NextMessageID uint32
}

func RunIKE_AUTH_EAPIdentity(ctx context.Context, cfg AuthConfig) (AuthResult, error) {
	if cfg.Transport == nil {
		return AuthResult{}, fmt.Errorf("%w: transport is nil", ErrInvalidAuthConfig)
	}
	keys := cfg.Keys
	if keys.Profile.RequiredLength() == 0 {
		keys = cfg.Init.Keys
	}
	if err := validateKeySet(keys); err != nil {
		return AuthResult{}, err
	}
	spiI, spiR := cfg.Init.InitiatorSPI, cfg.Init.ResponderSPI
	if spiI == 0 || spiR == 0 {
		return AuthResult{}, fmt.Errorf("%w: missing IKE SPIs", ErrInvalidAuthConfig)
	}
	messageID := cfg.InitialMessageID
	if messageID == 0 {
		messageID = 1
	}
	initialInner, err := BuildIKEAuthInitialPayloads(cfg)
	if err != nil {
		return AuthResult{}, err
	}
	initialIV, err := authIV(cfg.Random, keys.Profile, cfg.InitialIV)
	if err != nil {
		return AuthResult{}, err
	}
	initialReqBytes, initialRespBytes, initialInnerResp, err := exchangeAuthMessage(ctx, cfg.Transport, cfg.Init, keys, messageID, initialInner, initialIV, cfg.MaxFragmentSize, "initial IKE_AUTH")
	if err != nil {
		return AuthResult{}, err
	}
	if hasPayload(initialInnerResp, PayloadSA) {
		return AuthResult{}, fmt.Errorf("%w: premature CHILD_SA in initial IKE_AUTH response before EAP completion", ErrInvalidAuthResponse)
	}
	if err := verifyInitialResponderAuth(cfg, keys, initialInnerResp); err != nil {
		return AuthResult{}, err
	}
	eapReq, eapReqRaw, hasEAP, err := firstEAPPacketWithRaw(initialInnerResp)
	if err != nil {
		return AuthResult{}, err
	}
	out := AuthResult{
		InitialRequestBytes:  append([]byte(nil), initialReqBytes...),
		InitialResponseBytes: append([]byte(nil), initialRespBytes...),
		InitialResponseInner: clonePayloads(initialInnerResp),
		NextMessageID:        messageID + 1,
	}
	if !hasEAP {
		return out, nil
	}
	if err := checkEAPOnlyMethod(cfg.EAPOnlyAuthentication, eapReq); err != nil {
		return AuthResult{}, err
	}
	out.EAPRequest = &eapReq
	if eapReq.Code != eapaka.CodeRequest || eapReq.Subtype != eapaka.SubtypeIdentity {
		return out, nil
	}
	permanentIdentity := authPermanentIdentity(cfg.EAPIdentity, cfg.InitiatorID)
	identity := identityForEAPRequest(eapReq, eapIdentityOptions{
		PermanentIdentity: permanentIdentity,
		Pseudonym:         cfg.EAPPseudonym,
		ReauthIdentity:    cfg.EAPReauthIdentity,
	})
	if identity == "" {
		return AuthResult{}, fmt.Errorf("%w: eap identity is empty", ErrInvalidAuthConfig)
	}
	identityResponse, err := eapaka.BuildIdentityResponse(identity, eapReq)
	if err != nil {
		return AuthResult{}, err
	}
	identityPacket, err := identityResponse.MarshalBinary()
	if err != nil {
		return AuthResult{}, err
	}
	identityIV, err := authIV(cfg.Random, keys.Profile, cfg.EAPIdentityIV)
	if err != nil {
		return AuthResult{}, err
	}
	identityReqBytes, identityRespBytes, identityInnerResp, err := exchangeAuthMessage(ctx, cfg.Transport, cfg.Init, keys, messageID+1, []Payload{EAPPayload(identityPacket)}, identityIV, cfg.MaxFragmentSize, "EAP identity IKE_AUTH")
	if err != nil {
		return AuthResult{}, err
	}
	if hasPayload(identityInnerResp, PayloadSA) {
		return AuthResult{}, fmt.Errorf("%w: premature CHILD_SA in EAP identity response", ErrInvalidAuthResponse)
	}
	out.IdentityRequestBytes = append([]byte(nil), identityReqBytes...)
	out.IdentityResponseBytes = append([]byte(nil), identityRespBytes...)
	out.IdentityResponseInner = clonePayloads(identityInnerResp)
	out.EAPIdentityUsed = identity
	out.IdentityTranscript = cloneByteSlices([][]byte{eapReqRaw, identityPacket})
	out.NextMessageID = messageID + 2
	if nextEAP, ok, err := firstEAPPacket(identityInnerResp); err != nil {
		return AuthResult{}, err
	} else if ok {
		if err := checkEAPOnlyMethod(cfg.EAPOnlyAuthentication, nextEAP); err != nil {
			return AuthResult{}, err
		}
		out.EAPAfterIdentity = &nextEAP
	}
	return out, nil
}

func verifyInitialResponderAuth(cfg AuthConfig, keys IKEKeys, initialInnerResp []Payload) error {
	initialIDr, hasInitialIDr, err := firstIKEAuthIdentity(initialInnerResp, PayloadIDr)
	if err != nil {
		return fmt.Errorf("%w: parse responder IDr: %w", ErrInvalidAuthResponse, err)
	}
	if hasInitialIDr && cfg.ExpectedResponderID != nil && !identitiesEqual(initialIDr, *cfg.ExpectedResponderID) {
		return fmt.Errorf("%w: responder IDr does not match expected identity", ErrInvalidAuthResponse)
	}
	certs, err := parseAuthCertificates(initialInnerResp)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidAuthResponse, err)
	}
	initialAUTH, hasInitialAUTH := firstIKEAuthPayload(initialInnerResp, PayloadAUTH)
	if hasInitialAUTH || len(certs) > 0 {
		if !hasInitialIDr {
			return fmt.Errorf("%w: responder certificate AUTH missing IDr", ErrInvalidAuthResponse)
		}
		if !hasInitialAUTH {
			return fmt.Errorf("%w: responder sent CERT without AUTH payload", ErrInvalidAuthResponse)
		}
		if len(certs) == 0 {
			return fmt.Errorf("%w: responder sent public-key AUTH without CERT payload", ErrInvalidAuthResponse)
		}
		if err := verifyResponderPublicKeyAUTH(cfg.Init, keys, initialIDr, initialAUTH, certs, cfg.RootCAs); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidAuthResponse, err)
		}
		return nil
	}
	if cfg.RequireResponderCert || (cfg.RootCAs != nil && !cfg.EAPOnlyAuthentication) {
		return fmt.Errorf("%w: responder omitted certificate AUTH without EAP_ONLY_AUTHENTICATION", ErrInvalidAuthResponse)
	}
	return nil
}

func checkEAPOnlyMethod(eapOnly bool, pkt eapaka.Packet) error {
	if !eapOnly {
		return nil
	}
	if pkt.Code == eapaka.CodeRequest && pkt.Type == eapaka.TypeAKA {
		return fmt.Errorf("%w: EAP_ONLY_AUTHENTICATION forbids legacy EAP-AKA (RFC 5998 §3)", ErrInvalidAuthResponse)
	}
	return nil
}

func RunIKE_AUTH_Full(ctx context.Context, cfg FullAuthConfig) (FullAuthResult, error) {
	localChildSPI, err := fullAuthLocalChildSPI(cfg)
	if err != nil {
		return FullAuthResult{}, err
	}
	auth, err := RunIKE_AUTH_EAPIdentity(ctx, AuthConfig{
		Transport:             cfg.Transport,
		Init:                  cfg.Init,
		Keys:                  cfg.Keys,
		InitiatorID:           cfg.InitiatorID,
		ExpectedResponderID:   cfg.ExpectedResponderID,
		RootCAs:               cfg.RootCAs,
		EAPOnlyAuthentication: cfg.EAPOnlyAuthentication,
		RequireResponderCert:  cfg.RequireResponderCert,
		SendCertReq:           cfg.SendCertReq,
		CertReqCAs:            cfg.CertReqCAs,
		EAPIdentity:           cfg.EAPIdentity,
		EAPPseudonym:          cfg.EAPPseudonym,
		EAPReauthIdentity:     cfg.EAPReauthIdentity,
		ChildSA:               cfg.ChildSA,
		ChildSPI:              localChildSPI,
		TSi:                   cfg.TSi,
		TSr:                   cfg.TSr,
		Configuration:         cfg.Configuration,
		Random:                cfg.Random,
		InitialIV:             cfg.InitialIV,
		EAPIdentityIV:         cfg.EAPIdentityIV,
		InitialMessageID:      cfg.InitialMessageID,
		MaxFragmentSize:       cfg.MaxFragmentSize,
	})
	if err != nil {
		return FullAuthResult{}, err
	}
	finalInner, finalBytes := authFinalResponse(auth)
	out := FullAuthResult{
		Auth:               auth,
		EAPKeys:            cfg.EAPKeys,
		NextMessageID:      auth.NextMessageID,
		FinalResponseBytes: append([]byte(nil), finalBytes...),
		FinalResponseInner: clonePayloads(finalInner),
	}
	if hasPayload(finalInner, PayloadSA) {
		return out, fmt.Errorf("%w: premature CHILD_SA before EAP authentication", ErrInvalidAuthResponse)
	}
	offeredChildSA, err := authOfferedChildSA(cfg.ChildSA, localChildSPI)
	if err != nil {
		return FullAuthResult{}, err
	}
	offeredTSi := trafficSelectorsOrSWuAny(cfg.TSi)
	offeredTSr := trafficSelectorsOrSWuAny(cfg.TSr)
	next := authNextEAP(auth)
	identity := authPermanentIdentity(cfg.EAPIdentity, cfg.InitiatorID)
	currentFullAuthIdentity := firstIKEAuthNonEmpty(auth.EAPIdentityUsed, identity)
	identityTranscript := cloneByteSlices(auth.IdentityTranscript)
	eapAuthenticated := false
	for i := 0; i < maxFullAuthEAPExchanges; i++ {
		if next == nil {
			return out, fmt.Errorf("%w: IKE_AUTH did not complete EAP", ErrInvalidAuthResponse)
		}
		out.EAPLast = cloneEAPPacketPtr(next)
		if err := checkEAPOnlyMethod(cfg.EAPOnlyAuthentication, *next); err != nil {
			return out, err
		}
		if next.Code == eapaka.CodeSuccess {
			if hasPayload(out.FinalResponseInner, PayloadSA) {
				return out, fmt.Errorf("%w: premature CHILD_SA in EAP-Success before MSK AUTH exchange", ErrInvalidAuthResponse)
			}
			if !eapAuthenticated || len(out.EAPKeys.MSK) == 0 {
				return out, fmt.Errorf("%w: EAP success without completed AKA authentication", ErrInvalidAuthResponse)
			}
			child, responseBytes, responseInner, err := runIKEAuthEAPFinal(ctx, cfg, out, localChildSPI, offeredChildSA, offeredTSi, offeredTSr)
			if err != nil {
				return out, err
			}
			out.ChildSA = &child
			out.FinalResponseBytes = responseBytes
			out.FinalResponseInner = responseInner
			out.NextMessageID++
			return out, nil
		}
		if next.Code == eapaka.CodeFailure {
			return out, fmt.Errorf("%w: EAP failure", ErrInvalidAuthResponse)
		}
		if next.Code != eapaka.CodeRequest {
			return out, fmt.Errorf("%w: unexpected EAP code %d", ErrInvalidAuthResponse, next.Code)
		}
		if next.Subtype == eapaka.SubtypeIdentity {
			_, requestRaw, _, err := firstEAPPacketWithRaw(out.FinalResponseInner)
			if err != nil {
				return FullAuthResult{}, err
			}
			exchangeIdentity := identityForEAPRequest(*next, eapIdentityOptions{
				PermanentIdentity: identity,
				Pseudonym:         firstIKEAuthNonEmpty(out.EAPNextPseudonym, cfg.EAPPseudonym),
				ReauthIdentity:    cfg.EAPReauthIdentity,
			})
			exchange, err := runIKEAuthIdentityExchange(ctx, identityExchangeConfig{
				Transport:       cfg.Transport,
				Init:            cfg.Init,
				Keys:            cfg.Keys,
				Random:          cfg.Random,
				Request:         *next,
				RequestRaw:      requestRaw,
				Identity:        exchangeIdentity,
				MessageID:       out.NextMessageID,
				MaxFragmentSize: cfg.MaxFragmentSize,
			})
			if err != nil {
				return FullAuthResult{}, err
			}
			currentFullAuthIdentity = exchange.Identity
			out.IdentityExchanges = append(out.IdentityExchanges, exchange)
			identityTranscript = append(identityTranscript, exchange.Transcript...)
			out.NextMessageID = exchange.NextMessageID
			out.FinalResponseBytes = append([]byte(nil), exchange.ResponseBytes...)
			out.FinalResponseInner = clonePayloads(exchange.ResponseInner)
			if hasPayload(out.FinalResponseInner, PayloadSA) {
				return out, fmt.Errorf("%w: premature CHILD_SA in EAP identity exchange", ErrInvalidAuthResponse)
			}
			next = exchange.EAPNext
			continue
		}
		challengeIdentity := currentFullAuthIdentity
		if len(auth.IdentityTranscript) == 0 && len(identityTranscript) == 0 {
			challengeIdentity = adaptPermanentNAIForEAPType(challengeIdentity, next.Type)
		}
		if next.Subtype == eapaka.SubtypeReauthentication && strings.TrimSpace(cfg.EAPReauthIdentity) != "" {
			challengeIdentity = strings.TrimSpace(cfg.EAPReauthIdentity)
		}
		challenge, err := runIKE_AUTH_AKAChallenge(ctx, AKAChallengeConfig{
			Transport:           cfg.Transport,
			Init:                cfg.Init,
			Keys:                cfg.Keys,
			SIM:                 cfg.SIM,
			EAPKeys:             out.EAPKeys,
			Identity:            challengeIdentity,
			ExpectedNetworkName: cfg.ExpectedNetworkName,
			Request:             *next,
			IdentityTranscript:  identityTranscript,
			ChildSPI:            localChildSPI,
			TSi:                 offeredTSi,
			TSr:                 offeredTSr,
			MessageID:           out.NextMessageID,
			Random:              cfg.Random,
			EAPReauthIV:         cfg.EAPReauthIV,
			EAPReauthCounter:    cfg.EAPReauthCounter,
			EAPReauthCounterOK:  cfg.EAPReauthCounterOK,
			MaxFragmentSize:     cfg.MaxFragmentSize,
		}, offeredChildSA, offeredTSi, offeredTSr)
		if err != nil {
			return FullAuthResult{}, err
		}
		out.AKAChallenges = append(out.AKAChallenges, challenge)
		out.NextMessageID = challenge.NextMessageID
		out.FinalResponseBytes = append([]byte(nil), challenge.FinalResponseBytes...)
		out.FinalResponseInner = clonePayloads(challenge.FinalResponseInner)
		out.EAPNotifications = append(out.EAPNotifications, challenge.EAPNotifications...)
		out.EAPClientError = out.EAPClientError || challenge.EAPClientError
		if challenge.EAPNextPseudonym != "" {
			out.EAPNextPseudonym = challenge.EAPNextPseudonym
		}
		if challenge.EAPNextReauthID != "" {
			out.EAPNextReauthID = challenge.EAPNextReauthID
		}
		out.EAPReauthenticated = out.EAPReauthenticated || challenge.EAPReauthenticated
		if challenge.EAPReauthCounter != 0 {
			out.EAPReauthCounter = challenge.EAPReauthCounter
		}
		out.EAPReauthCounterTooSmall = out.EAPReauthCounterTooSmall || challenge.EAPReauthCounterTooSmall
		out.SyncFailure = out.SyncFailure || challenge.SyncFailure
		out.AuthFailure = out.AuthFailure || challenge.AuthFailure
		if challenge.KDFNegotiated {
			out.KDFNegotiations++
		}
		if len(challenge.EAPKeys.KAut) > 0 {
			out.EAPKeys = challenge.EAPKeys
		}
		if !challenge.SyncFailure && !challenge.AuthFailure && !challenge.KDFNegotiated &&
			!challenge.EAPClientError && !challenge.EAPReauthCounterTooSmall && len(challenge.EAPKeys.MSK) > 0 {
			eapAuthenticated = true
		}
		next = challenge.EAPNext
	}
	return out, fmt.Errorf("%w: too many IKE_AUTH EAP exchanges", ErrInvalidAuthResponse)
}

func runIKEAuthEAPFinal(ctx context.Context, cfg FullAuthConfig, current FullAuthResult, localChildSPI []byte, offeredChildSA SecurityAssociation, offeredTSi, offeredTSr TrafficSelectors) (ChildSAResult, []byte, []Payload, error) {
	keys := cfg.Keys
	if keys.Profile.RequiredLength() == 0 {
		keys = cfg.Init.Keys
	}
	if len(current.EAPKeys.MSK) == 0 {
		return ChildSAResult{}, nil, nil, fmt.Errorf("%w: EAP success without MSK", ErrInvalidAuthResponse)
	}
	authData, err := eapSharedKeyAUTH(cfg.Init, keys, cfg.InitiatorID, current.EAPKeys.MSK, true)
	if err != nil {
		return ChildSAResult{}, nil, nil, err
	}
	authPayload, err := AuthenticationPayload(AuthMethodSharedKeyMIC, authData)
	if err != nil {
		return ChildSAResult{}, nil, nil, err
	}
	iv, err := authIV(cfg.Random, keys.Profile, nil)
	if err != nil {
		return ChildSAResult{}, nil, nil, err
	}
	_, responseBytes, inner, err := exchangeAuthMessage(ctx, cfg.Transport, cfg.Init, keys, current.NextMessageID, []Payload{authPayload}, iv, cfg.MaxFragmentSize, "final EAP AUTH")
	if err != nil {
		return ChildSAResult{}, nil, nil, err
	}
	initialIDr, hasInitialIDr, err := firstIKEAuthIdentity(current.Auth.InitialResponseInner, PayloadIDr)
	if err != nil {
		return ChildSAResult{}, nil, nil, err
	}
	finalIDr, hasFinalIDr, err := firstIKEAuthIdentity(inner, PayloadIDr)
	if err != nil {
		return ChildSAResult{}, nil, nil, err
	}
	if hasInitialIDr && hasFinalIDr && !identitiesEqual(initialIDr, finalIDr) {
		return ChildSAResult{}, nil, nil, fmt.Errorf("%w: responder IDr changed between initial and final IKE_AUTH responses", ErrInvalidAuthResponse)
	}
	var responderID Identity
	switch {
	case hasInitialIDr:
		responderID = initialIDr
	case hasFinalIDr:
		responderID = finalIDr
	default:
		return ChildSAResult{}, nil, nil, fmt.Errorf("%w: final EAP AUTH response missing IDr", ErrInvalidAuthResponse)
	}
	if cfg.ExpectedResponderID != nil && !identitiesEqual(responderID, *cfg.ExpectedResponderID) {
		return ChildSAResult{}, nil, nil, fmt.Errorf("%w: responder IDr does not match expected identity", ErrInvalidAuthResponse)
	}
	responderAUTH, ok := firstIKEAuthPayload(inner, PayloadAUTH)
	if !ok {
		return ChildSAResult{}, nil, nil, fmt.Errorf("%w: final EAP AUTH response missing AUTH", ErrInvalidAuthResponse)
	}
	if err := verifyEAPSharedKeyAUTH(cfg.Init, keys, responderID, current.EAPKeys.MSK, responderAUTH, false); err != nil {
		return ChildSAResult{}, nil, nil, fmt.Errorf("%w: responder AUTH: %w", ErrInvalidAuthResponse, err)
	}
	child, ok, err := parseChildSAIfPresent(cfg.Init, inner, localChildSPI, current.NextMessageID+1, offeredChildSA, offeredTSi, offeredTSr)
	if err != nil {
		return ChildSAResult{}, nil, nil, err
	}
	if !ok {
		return ChildSAResult{}, nil, nil, fmt.Errorf("%w: final EAP AUTH response missing CHILD_SA", ErrInvalidAuthResponse)
	}
	return child, append([]byte(nil), responseBytes...), clonePayloads(inner), nil
}

func firstIKEAuthIdentity(payloads []Payload, payloadType uint8) (Identity, bool, error) {
	payload, ok := firstIKEAuthPayload(payloads, payloadType)
	if !ok {
		return Identity{}, false, nil
	}
	identity, err := ParseIdentity(payload.Body)
	return identity, true, err
}

func firstIKEAuthPayload(payloads []Payload, payloadType uint8) (Payload, bool) {
	for _, payload := range payloads {
		if payload.Type == payloadType {
			return payload, true
		}
	}
	return Payload{}, false
}

func RunIKE_AUTH_AKAChallenge(ctx context.Context, cfg AKAChallengeConfig) (AKAChallengeResult, error) {
	var offeredChildSA SecurityAssociation
	if len(cfg.ChildSPI) > 0 {
		offeredChildSA = DefaultESPProposal(cfg.ChildSPI)
	}
	return runIKE_AUTH_AKAChallenge(ctx, cfg, offeredChildSA, cfg.TSi, cfg.TSr)
}

func runIKE_AUTH_AKAChallenge(ctx context.Context, cfg AKAChallengeConfig, offeredChildSA SecurityAssociation, offeredTSi, offeredTSr TrafficSelectors) (AKAChallengeResult, error) {
	_ = offeredChildSA
	_ = offeredTSi
	_ = offeredTSr
	if cfg.Transport == nil {
		return AKAChallengeResult{}, fmt.Errorf("%w: transport is nil", ErrInvalidAuthConfig)
	}
	keys := cfg.Keys
	if keys.Profile.RequiredLength() == 0 {
		keys = cfg.Init.Keys
	}
	if err := validateKeySet(keys); err != nil {
		return AKAChallengeResult{}, err
	}
	if cfg.MessageID == 0 {
		return AKAChallengeResult{}, fmt.Errorf("%w: message_id is zero", ErrInvalidAuthConfig)
	}
	var eapResp eapaka.Packet
	var eapKeys eapaka.Keys
	var syncFailure bool
	var authFailure bool
	var kdfNegotiated bool
	var clientError bool
	var reauthenticated bool
	var reauthCounter uint16
	var reauthCounterTooSmall bool
	var notifications []eapaka.Packet
	var encryptedAttributes []eapaka.Attribute
	var identityState eapaka.EncryptedIdentityState
	if cfg.Request.Code == eapaka.CodeRequest && cfg.Request.Subtype == eapaka.SubtypeReauthentication && len(cfg.EAPKeys.KAut) > 0 {
		parsed, err := eapaka.ParseReauthenticationRequest(cfg.Request, cfg.EAPKeys)
		if err != nil {
			clientErrResp, buildErr := eapaka.BuildClientErrorResponse(cfg.Request, eapaka.ClientErrorUnableToProcessPacket)
			if buildErr != nil {
				return AKAChallengeResult{}, err
			}
			eapResp = clientErrResp
			eapKeys = cfg.EAPKeys
			clientError = true
		} else {
			reauthCounter = parsed.Counter
			encryptedAttributes = parsed.EncryptedAttributes
			identityState = parsed.IdentityState
			eapIV, err := eapReauthIV(cfg.Random, cfg.EAPReauthIV)
			if err != nil {
				return AKAChallengeResult{}, err
			}
			if cfg.EAPReauthCounterOK && parsed.Counter <= cfg.EAPReauthCounter {
				eapResp, err = eapaka.BuildReauthenticationCounterTooSmallResponse(cfg.Request, cfg.EAPKeys, eapIV)
				if err != nil {
					return AKAChallengeResult{}, err
				}
				eapKeys = cfg.EAPKeys
				reauthCounterTooSmall = true
			} else {
				identity := strings.TrimSpace(cfg.Identity)
				if identity == "" {
					return AKAChallengeResult{}, fmt.Errorf("%w: reauthentication identity is empty", ErrInvalidAuthConfig)
				}
				eapResp, eapKeys, err = eapaka.BuildReauthenticationResponse(identity, cfg.Request, cfg.EAPKeys, eapIV)
				if err != nil {
					return AKAChallengeResult{}, err
				}
				reauthenticated = true
			}
		}
	} else if response, handled, isClientErr, err := buildAKAControlResponse(cfg.Request, cfg.EAPKeys, false, 0, nil); err != nil {
		return AKAChallengeResult{}, err
	} else if handled {
		eapResp = response
		clientError = isClientErr || response.Subtype == eapaka.SubtypeClientError
		if response.Subtype == eapaka.SubtypeNotification {
			notifications = append(notifications, cloneEAPPacket(cfg.Request))
		}
	} else if response, negotiated, err := eapaka.BuildAKAPrimeKDFNegotiationResponse(cfg.Request); err != nil {
		return AKAChallengeResult{}, err
	} else if negotiated {
		eapResp = response
		kdfNegotiated = true
	} else {
		if cfg.SIM == nil {
			return AKAChallengeResult{}, fmt.Errorf("%w: SIM provider is nil", ErrInvalidAuthConfig)
		}
		expectedNet := strings.TrimSpace(cfg.ExpectedNetworkName)
		if expectedNet == "" {
			expectedNet = eapaka.DefaultNetworkName
		}
		challenge, err := eapaka.BuildChallengeResponseFromProviderWithOptions(cfg.Identity, cfg.Request, cfg.SIM, eapaka.ChallengeOptions{
			IdentityPackets:     cfg.IdentityTranscript,
			ExpectedNetworkName: expectedNet,
		})
		if err != nil {
			if strings.TrimSpace(cfg.Identity) == "" && errors.Is(err, eapaka.ErrInvalidKeyMaterial) {
				return AKAChallengeResult{}, fmt.Errorf("%w: identity is empty", ErrInvalidAuthConfig)
			}
			return AKAChallengeResult{}, err
		}
		eapResp = challenge.Response
		eapKeys = challenge.Keys
		syncFailure = challenge.SyncFailure
		authFailure = challenge.AuthFailure
		clientError = challenge.ClientError
		if !syncFailure && !authFailure && !clientError {
			if attrs, _, err := eapaka.DecryptChallengeEncryptedAttributes(cfg.Request, eapKeys); err != nil {
				clientErrResp, buildErr := eapaka.BuildClientErrorResponse(cfg.Request, eapaka.ClientErrorUnableToProcessPacket)
				if buildErr != nil {
					return AKAChallengeResult{}, err
				}
				eapResp = clientErrResp
				eapKeys = eapaka.Keys{}
				clientError = true
			} else if len(attrs) > 0 {
				encryptedAttributes = attrs
				identityState, err = eapaka.IdentityStateFromAttributes(attrs)
				if err != nil {
					clientErrResp, buildErr := eapaka.BuildClientErrorResponse(cfg.Request, eapaka.ClientErrorUnableToProcessPacket)
					if buildErr != nil {
						return AKAChallengeResult{}, err
					}
					eapResp = clientErrResp
					eapKeys = eapaka.Keys{}
					encryptedAttributes = nil
					identityState = eapaka.EncryptedIdentityState{}
					clientError = true
				}
			}
		}
	}
	eapRaw, err := eapResp.MarshalBinary()
	if err != nil {
		return AKAChallengeResult{}, err
	}
	iv, err := authIV(cfg.Random, keys.Profile, cfg.IV)
	if err != nil {
		return AKAChallengeResult{}, err
	}
	reqBytes, respBytes, inner, err := exchangeAuthMessage(ctx, cfg.Transport, cfg.Init, keys, cfg.MessageID, []Payload{EAPPayload(eapRaw)}, iv, cfg.MaxFragmentSize, "EAP-AKA challenge IKE_AUTH")
	if err != nil {
		return AKAChallengeResult{}, err
	}
	if hasPayload(inner, PayloadSA) {
		return AKAChallengeResult{}, fmt.Errorf("%w: premature CHILD_SA in EAP-AKA response before MSK AUTH exchange", ErrInvalidAuthResponse)
	}
	controlKeys := eapKeys
	if len(controlKeys.KAut) == 0 {
		controlKeys = cfg.EAPKeys
	}
	resultEAPKeys := eapKeys
	if len(resultEAPKeys.KAut) == 0 {
		resultEAPKeys = cfg.EAPKeys
	}
	followups, err := runAKAControlFollowups(ctx, cfg, keys, inner, cfg.MessageID+1, controlKeys, reauthenticated || reauthCounterTooSmall, reauthCounter)
	if err != nil {
		return AKAChallengeResult{}, err
	}
	notifications = append(notifications, followups.Notifications...)
	finalRespBytes := respBytes
	finalInner := inner
	nextMessageID := cfg.MessageID + 1
	if len(followups.ResponseBytes) > 0 {
		finalRespBytes = followups.ResponseBytes[len(followups.ResponseBytes)-1]
		finalInner = followups.FinalInner
		nextMessageID = followups.NextMessageID
		clientError = clientError || followups.ClientError
	}
	if hasPayload(finalInner, PayloadSA) {
		return AKAChallengeResult{}, fmt.Errorf("%w: premature CHILD_SA in EAP-AKA followup response before MSK AUTH exchange", ErrInvalidAuthResponse)
	}
	out := AKAChallengeResult{
		RequestBytes:             append([]byte(nil), reqBytes...),
		ResponseBytes:            append([]byte(nil), respBytes...),
		ResponseInner:            clonePayloads(inner),
		EAPResponse:              eapResp,
		EAPKeys:                  resultEAPKeys,
		EAPEncryptedAttributes:   cloneEAPAttributes(encryptedAttributes),
		EAPNextPseudonym:         identityState.NextPseudonym,
		EAPNextReauthID:          identityState.NextReauthID,
		EAPReauthenticated:       reauthenticated,
		EAPReauthCounter:         reauthCounter,
		EAPReauthCounterTooSmall: reauthCounterTooSmall,
		EAPNotifications:         cloneEAPPackets(notifications),
		EAPClientError:           clientError,
		SyncFailure:              syncFailure,
		AuthFailure:              authFailure,
		KDFNegotiated:            kdfNegotiated,
		NextMessageID:            nextMessageID,
		FollowupRequestBytes:     cloneByteSlices(followups.RequestBytes),
		FollowupResponseBytes:    cloneByteSlices(followups.ResponseBytes),
		FinalResponseBytes:       append([]byte(nil), finalRespBytes...),
		FinalResponseInner:       clonePayloads(finalInner),
	}
	if next, ok, err := firstEAPPacket(finalInner); err != nil {
		return AKAChallengeResult{}, err
	} else if ok {
		out.EAPNext = &next
	}
	return out, nil
}

type akaControlFollowups struct {
	RequestBytes  [][]byte
	ResponseBytes [][]byte
	FinalInner    []Payload
	NextMessageID uint32
	Notifications []eapaka.Packet
	ClientError   bool
}

func runAKAControlFollowups(ctx context.Context, cfg AKAChallengeConfig, keys IKEKeys, initialInner []Payload, messageID uint32, eapKeys eapaka.Keys, fastReauth bool, expectedCounter uint16) (akaControlFollowups, error) {
	out := akaControlFollowups{
		FinalInner:    clonePayloads(initialInner),
		NextMessageID: messageID,
	}
	for i := 0; i < maxAKAControlFollowups; i++ {
		next, ok, err := firstEAPPacket(out.FinalInner)
		if err != nil {
			return akaControlFollowups{}, err
		}
		if !ok {
			return out, nil
		}
		var notifIV []byte
		if fastReauth {
			notifIV, err = eapReauthIV(cfg.Random, nil)
			if err != nil {
				return akaControlFollowups{}, err
			}
		}
		response, handled, isClientErr, err := buildAKAControlResponse(next, eapKeys, fastReauth, expectedCounter, notifIV)
		if err != nil {
			return akaControlFollowups{}, err
		}
		if !handled {
			return out, nil
		}
		if response.Subtype == eapaka.SubtypeNotification {
			out.Notifications = append(out.Notifications, cloneEAPPacket(next))
		}
		if isClientErr || response.Subtype == eapaka.SubtypeClientError {
			out.ClientError = true
		}
		raw, err := response.MarshalBinary()
		if err != nil {
			return akaControlFollowups{}, err
		}
		iv, err := authIV(cfg.Random, keys.Profile, nil)
		if err != nil {
			return akaControlFollowups{}, err
		}
		reqBytes, respBytes, inner, err := exchangeAuthMessage(ctx, cfg.Transport, cfg.Init, keys, out.NextMessageID, []Payload{EAPPayload(raw)}, iv, cfg.MaxFragmentSize, "EAP-AKA control followup")
		if err != nil {
			return akaControlFollowups{}, err
		}
		if hasPayload(inner, PayloadSA) {
			return akaControlFollowups{}, fmt.Errorf("%w: premature CHILD_SA in EAP-AKA control followup", ErrInvalidAuthResponse)
		}
		out.RequestBytes = append(out.RequestBytes, append([]byte(nil), reqBytes...))
		out.ResponseBytes = append(out.ResponseBytes, append([]byte(nil), respBytes...))
		out.FinalInner = clonePayloads(inner)
		out.NextMessageID++
	}
	next, ok, err := firstEAPPacket(out.FinalInner)
	if err != nil {
		return akaControlFollowups{}, err
	}
	if ok {
		if _, handled, _, err := buildAKAControlResponse(next, eapKeys, fastReauth, expectedCounter, nil); err != nil {
			return akaControlFollowups{}, err
		} else if handled {
			return akaControlFollowups{}, fmt.Errorf("%w: too many EAP-AKA control followups", ErrInvalidAuthResponse)
		}
	}
	return out, nil
}

func buildAKAControlResponse(request eapaka.Packet, keys eapaka.Keys, fastReauth bool, expectedCounter uint16, responseIV []byte) (eapaka.Packet, bool, bool, error) {
	response, handled, isClientErr, err := eapaka.BuildNotificationOrClientErrorResponse(request, eapaka.NotificationOptions{
		Authenticated:   len(keys.KAut) > 0,
		Keys:            keys,
		FastReauth:      fastReauth,
		ExpectedCounter: expectedCounter,
		ResponseIV:      responseIV,
	})
	if err != nil || handled {
		return response, handled, isClientErr, err
	}
	if request.Code == eapaka.CodeRequest && request.Subtype != eapaka.SubtypeChallenge && request.Subtype != eapaka.SubtypeIdentity {
		resp, buildErr := eapaka.BuildClientErrorResponse(request, eapaka.ClientErrorUnableToProcessPacket)
		return resp, true, true, buildErr
	}
	return eapaka.Packet{}, false, false, nil
}

type identityExchangeConfig struct {
	Transport       InitTransport
	Init            InitResult
	Keys            IKEKeys
	Random          io.Reader
	Request         eapaka.Packet
	RequestRaw      []byte
	Identity        string
	MessageID       uint32
	MaxFragmentSize int
}

type eapIdentityOptions struct {
	PermanentIdentity string
	Pseudonym         string
	ReauthIdentity    string
}

func authPermanentIdentity(identity string, initiator Identity) string {
	out := strings.TrimSpace(identity)
	if out == "" {
		out = strings.TrimSpace(string(initiator.Data))
	}
	return out
}

func identityForEAPRequest(request eapaka.Packet, opts eapIdentityOptions) string {
	permanent := adaptPermanentNAIForEAPType(strings.TrimSpace(opts.PermanentIdentity), request.Type)
	pseudonym := strings.TrimSpace(opts.Pseudonym)
	reauth := strings.TrimSpace(opts.ReauthIdentity)
	switch {
	case hasEAPIdentityRequestAttribute(request, eapaka.AttributePermanentIDReq):
		return permanent
	case hasEAPIdentityRequestAttribute(request, eapaka.AttributeFullAuthIDReq):
		return firstIKEAuthNonEmpty(pseudonym, permanent)
	case hasEAPIdentityRequestAttribute(request, eapaka.AttributeAnyIDReq):
		return firstIKEAuthNonEmpty(reauth, pseudonym, permanent)
	default:
		return permanent
	}
}

// adaptPermanentNAIForEAPType rewrites a 3GPP permanent IMSI NAI leading digit
// ('0' for EAP-AKA vs '6' for EAP-AKA' per 3GPP TS 23.003 §19.3.2) when the
// responder requests a specific EAP method.
func adaptPermanentNAIForEAPType(identity string, eapType uint8) string {
	identity = strings.TrimSpace(identity)
	if identity == "" || (eapType != eapaka.TypeAKA && eapType != eapaka.TypeAKAPrime) {
		return identity
	}
	user, realm, hasAt := strings.Cut(identity, "@")
	if !hasAt || realm == "" || len(user) < 15 || len(user) > 16 {
		return identity
	}
	if user[0] != '0' && user[0] != '6' {
		return identity
	}
	for i := 1; i < len(user); i++ {
		if user[i] < '0' || user[i] > '9' {
			return identity
		}
	}
	if len(user) == 15 {
		lowerRealm := strings.ToLower(realm)
		if !strings.Contains(lowerRealm, "mcc"+user[1:4]) || strings.Contains(lowerRealm, "mcc"+user[0:3]) {
			return identity
		}
	}
	prefix := byte('0')
	if eapType == eapaka.TypeAKAPrime {
		prefix = '6'
	}
	if user[0] == prefix {
		return identity
	}
	return string(prefix) + user[1:] + "@" + realm
}

func hasEAPIdentityRequestAttribute(request eapaka.Packet, typ uint8) bool {
	_, ok := eapaka.FindAttribute(request.Attributes, typ)
	return ok
}

func firstIKEAuthNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func runIKEAuthIdentityExchange(ctx context.Context, cfg identityExchangeConfig) (EAPIdentityExchange, error) {
	if cfg.Transport == nil {
		return EAPIdentityExchange{}, fmt.Errorf("%w: transport is nil", ErrInvalidAuthConfig)
	}
	if cfg.MessageID == 0 {
		return EAPIdentityExchange{}, fmt.Errorf("%w: message_id is zero", ErrInvalidAuthConfig)
	}
	if cfg.Request.Code != eapaka.CodeRequest || cfg.Request.Subtype != eapaka.SubtypeIdentity {
		return EAPIdentityExchange{}, fmt.Errorf("%w: not an EAP identity request", ErrInvalidAuthConfig)
	}
	identity := strings.TrimSpace(cfg.Identity)
	if identity == "" {
		return EAPIdentityExchange{}, fmt.Errorf("%w: eap identity is empty", ErrInvalidAuthConfig)
	}
	keys := cfg.Keys
	if keys.Profile.RequiredLength() == 0 {
		keys = cfg.Init.Keys
	}
	if err := validateKeySet(keys); err != nil {
		return EAPIdentityExchange{}, err
	}
	requestRaw := append([]byte(nil), cfg.RequestRaw...)
	if len(requestRaw) == 0 {
		encoded, err := cfg.Request.MarshalBinary()
		if err != nil {
			return EAPIdentityExchange{}, err
		}
		requestRaw = encoded
	}
	response, err := eapaka.BuildIdentityResponse(identity, cfg.Request)
	if err != nil {
		return EAPIdentityExchange{}, err
	}
	raw, err := response.MarshalBinary()
	if err != nil {
		return EAPIdentityExchange{}, err
	}
	iv, err := authIV(cfg.Random, keys.Profile, nil)
	if err != nil {
		return EAPIdentityExchange{}, err
	}
	reqBytes, respBytes, inner, err := exchangeAuthMessage(ctx, cfg.Transport, cfg.Init, keys, cfg.MessageID, []Payload{EAPPayload(raw)}, iv, cfg.MaxFragmentSize, "EAP identity followup")
	if err != nil {
		return EAPIdentityExchange{}, err
	}
	if hasPayload(inner, PayloadSA) {
		return EAPIdentityExchange{}, fmt.Errorf("%w: premature CHILD_SA in EAP identity followup", ErrInvalidAuthResponse)
	}
	out := EAPIdentityExchange{
		Request:       cloneEAPPacket(cfg.Request),
		Response:      cloneEAPPacket(response),
		Identity:      identity,
		RequestBytes:  append([]byte(nil), reqBytes...),
		ResponseBytes: append([]byte(nil), respBytes...),
		ResponseInner: clonePayloads(inner),
		Transcript:    cloneByteSlices([][]byte{requestRaw, raw}),
		NextMessageID: cfg.MessageID + 1,
	}
	if next, ok, err := firstEAPPacket(inner); err != nil {
		return EAPIdentityExchange{}, err
	} else if ok {
		out.EAPNext = &next
	}
	return out, nil
}

func BuildIKEAuthInitialPayloads(cfg AuthConfig) ([]Payload, error) {
	idPayload, err := IdentityPayload(PayloadIDi, cfg.InitiatorID)
	if err != nil {
		return nil, err
	}
	childSA := cfg.ChildSA
	if len(childSA.Proposals) == 0 {
		spi := append([]byte(nil), cfg.ChildSPI...)
		if len(spi) == 0 {
			random := cfg.Random
			if random == nil {
				random = rand.Reader
			}
			var err error
			spi, err = randomBytes(random, 4)
			if err != nil {
				return nil, err
			}
		}
		if len(spi) != 4 {
			return nil, fmt.Errorf("%w: child SPI length %d", ErrInvalidAuthConfig, len(spi))
		}
		childSA = DefaultESPProposal(spi)
	} else {
		childSA, err = childSAWithLocalSPI(childSA, cfg.ChildSPI)
		if err != nil {
			return nil, err
		}
	}
	saPayload, err := SecurityAssociationPayload(childSA)
	if err != nil {
		return nil, err
	}
	tsi := cfg.TSi
	if len(tsi.Selectors) == 0 {
		tsi = SWuAnyTrafficSelectors()
	}
	tsiPayload, err := TrafficSelectorsPayload(PayloadTSi, tsi)
	if err != nil {
		return nil, err
	}
	tsr := cfg.TSr
	if len(tsr.Selectors) == 0 {
		tsr = SWuAnyTrafficSelectors()
	}
	tsrPayload, err := TrafficSelectorsPayload(PayloadTSr, tsr)
	if err != nil {
		return nil, err
	}
	cfgPayload, err := ConfigurationPayload(firstConfiguration(cfg.Configuration, SWuConfigurationRequest()))
	if err != nil {
		return nil, err
	}
	// Keep the first IKE_AUTH request in the RFC 7296 canonical order. Some
	// deployed ePDGs reject a CP payload placed before SAi2 with INVALID_SYNTAX.
	payloads := make([]Payload, 0, 7)
	payloads = append(payloads, idPayload)
	if cfg.SendCertReq || len(cfg.CertReqCAs) > 0 {
		certReq, err := CertReqForCAs(cfg.CertReqCAs)
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, certReq)
	}
	payloads = append(payloads, saPayload, tsiPayload, tsrPayload, cfgPayload)
	if cfg.EAPOnlyAuthentication {
		payloads = append(payloads, EAPOnlyAuthenticationNotify())
	}
	return payloads, nil
}

func authHeader(init InitResult, messageID uint32, fromInitiator bool) Header {
	flags := uint8(0)
	if fromInitiator {
		flags |= FlagInitiator
	} else {
		flags |= FlagResponse
	}
	return Header{
		InitiatorSPI: init.InitiatorSPI,
		ResponderSPI: init.ResponderSPI,
		ExchangeType: ExchangeIKE_AUTH,
		Flags:        flags,
		MessageID:    messageID,
	}
}

func exchangeAuthMessage(ctx context.Context, transport InitTransport, init InitResult, keys IKEKeys, messageID uint32, inner []Payload, iv []byte, maxFragmentSize int, stage string) ([]byte, []byte, []Payload, error) {
	reqBytes, respBytes, msg, respInner, err := exchangeProtectedIKE(ctx, protectedExchangeConfig{
		Transport:              transport,
		Header:                 authHeader(init, messageID, true),
		Keys:                   keys,
		FromInitiator:          true,
		Inner:                  inner,
		IV:                     iv,
		FragmentationSupported: init.FragmentationSupported,
		MaxFragmentSize:        maxFragmentSize,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s exchange: %w", stage, err)
	}
	if err := validateAuthResponseHeaderAndNotify(msg.Header, respInner, init, messageID); err != nil {
		return nil, nil, nil, fmt.Errorf("%s response: %w", stage, err)
	}
	return reqBytes, respBytes, respInner, nil
}

func validateAuthResponseHeaderAndNotify(h Header, inner []Payload, init InitResult, messageID uint32) error {
	if h.InitiatorSPI != init.InitiatorSPI || h.ResponderSPI != init.ResponderSPI ||
		h.ExchangeType != ExchangeIKE_AUTH || h.MessageID != messageID || h.Flags&FlagResponse == 0 {
		return fmt.Errorf("%w: unexpected IKE_AUTH response header", ErrInvalidAuthResponse)
	}
	if err := FirstNotifyError(inner); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidAuthResponse, err)
	}
	return nil
}

func unprotectAuthResponse(raw []byte, init InitResult, keys IKEKeys, messageID uint32) (Message, []Payload, error) {
	msg, inner, err := UnprotectMessage(raw, keys, false)
	if err != nil {
		return Message{}, nil, err
	}
	if err := validateAuthResponseHeaderAndNotify(msg.Header, inner, init, messageID); err != nil {
		return Message{}, nil, err
	}
	return msg, inner, nil
}

func firstEAPPacket(payloads []Payload) (eapaka.Packet, bool, error) {
	pkt, _, ok, err := firstEAPPacketWithRaw(payloads)
	return pkt, ok, err
}

func firstEAPPacketWithRaw(payloads []Payload) (eapaka.Packet, []byte, bool, error) {
	for _, p := range payloads {
		if p.Type != PayloadEAP {
			continue
		}
		pkt, err := eapaka.ParsePacket(p.Body)
		if err != nil {
			return eapaka.Packet{}, nil, false, err
		}
		return pkt, append([]byte(nil), p.Body...), true, nil
	}
	return eapaka.Packet{}, nil, false, nil
}

func authFinalResponse(auth AuthResult) ([]Payload, []byte) {
	if len(auth.IdentityResponseInner) > 0 || len(auth.IdentityResponseBytes) > 0 {
		return clonePayloads(auth.IdentityResponseInner), append([]byte(nil), auth.IdentityResponseBytes...)
	}
	return clonePayloads(auth.InitialResponseInner), append([]byte(nil), auth.InitialResponseBytes...)
}

func authNextEAP(auth AuthResult) *eapaka.Packet {
	if auth.EAPAfterIdentity != nil {
		return cloneEAPPacketPtr(auth.EAPAfterIdentity)
	}
	if auth.EAPRequest != nil {
		if auth.EAPRequest.Code == eapaka.CodeRequest && auth.EAPRequest.Subtype == eapaka.SubtypeIdentity && len(auth.IdentityResponseBytes) > 0 {
			return nil
		}
		return cloneEAPPacketPtr(auth.EAPRequest)
	}
	return nil
}

func parseChildSAIfPresent(init InitResult, inner []Payload, localSPI []byte, nextMessageID uint32, offeredSA SecurityAssociation, offeredTSi, offeredTSr TrafficSelectors) (ChildSAResult, bool, error) {
	if !hasPayload(inner, PayloadSA) {
		return ChildSAResult{}, false, nil
	}
	var offered *SecurityAssociation
	if len(offeredSA.Proposals) > 0 {
		offered = &offeredSA
	}
	child, err := parseChildSAResultWithNonces(init, inner, localSPI, init.NonceI, init.NonceR, offered, offeredTSi, offeredTSr)
	if err != nil {
		return ChildSAResult{}, false, err
	}
	child.NextMessageID = nextMessageID
	return child, true, nil
}

func fullAuthLocalChildSPI(cfg FullAuthConfig) ([]byte, error) {
	if len(cfg.ChildSA.Proposals) > 0 && len(cfg.ChildSA.Proposals[0].SPI) > 0 {
		return append([]byte(nil), cfg.ChildSA.Proposals[0].SPI...), nil
	}
	if len(cfg.ChildSPI) > 0 {
		if len(cfg.ChildSPI) != 4 {
			return nil, fmt.Errorf("%w: child SPI length %d", ErrInvalidAuthConfig, len(cfg.ChildSPI))
		}
		return append([]byte(nil), cfg.ChildSPI...), nil
	}
	random := cfg.Random
	if random == nil {
		random = rand.Reader
	}
	return randomBytes(random, 4)
}

func authOfferedChildSA(sa SecurityAssociation, localSPI []byte) (SecurityAssociation, error) {
	if len(sa.Proposals) == 0 {
		if len(localSPI) == 0 {
			return SecurityAssociation{}, nil
		}
		return DefaultESPProposal(localSPI), nil
	}
	return childSAWithLocalSPI(sa, localSPI)
}

func childSAWithLocalSPI(sa SecurityAssociation, localSPI []byte) (SecurityAssociation, error) {
	out := cloneSecurityAssociation(sa)
	for i := range out.Proposals {
		proposal := &out.Proposals[i]
		if proposal.ProtocolID != ProtocolESP || len(proposal.SPI) != 0 {
			continue
		}
		if len(localSPI) != 4 {
			return SecurityAssociation{}, fmt.Errorf("%w: child SPI length %d", ErrInvalidAuthConfig, len(localSPI))
		}
		proposal.SPI = append([]byte(nil), localSPI...)
	}
	return out, nil
}

func authIV(random io.Reader, profile KeyMaterialProfile, override []byte) ([]byte, error) {
	if len(override) > 0 {
		if len(override) != profile.EncryptionBlockSize {
			return nil, fmt.Errorf("%w: IV length %d != %d", ErrInvalidAuthConfig, len(override), profile.EncryptionBlockSize)
		}
		return append([]byte(nil), override...), nil
	}
	if profile.EncryptionID == ENCR_AES_GCM_16 {
		return nil, nil
	}
	return RandomIV(random, profile)
}

func eapReauthIV(random io.Reader, override []byte) ([]byte, error) {
	if len(override) > 0 {
		if len(override) != aes.BlockSize {
			return nil, fmt.Errorf("%w: EAP reauthentication IV length %d != %d", ErrInvalidAuthConfig, len(override), aes.BlockSize)
		}
		return append([]byte(nil), override...), nil
	}
	if random == nil {
		random = rand.Reader
	}
	return randomBytes(random, aes.BlockSize)
}

func firstConfiguration(value, fallback Configuration) Configuration {
	if value.Type != 0 || len(value.Attributes) > 0 {
		return value
	}
	return fallback
}

func trafficSelectorsOrSWuAny(ts TrafficSelectors) TrafficSelectors {
	if len(ts.Selectors) == 0 {
		return SWuAnyTrafficSelectors()
	}
	return ts
}

func clonePayloads(in []Payload) []Payload {
	out := make([]Payload, len(in))
	for i, p := range in {
		out[i] = Payload{
			Type:        p.Type,
			NextPayload: p.NextPayload,
			Critical:    p.Critical,
			Body:        append([]byte(nil), p.Body...),
		}
	}
	return out
}

func cloneByteSlices(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i, item := range in {
		out[i] = append([]byte(nil), item...)
	}
	return out
}

func cloneEAPPackets(in []eapaka.Packet) []eapaka.Packet {
	out := make([]eapaka.Packet, len(in))
	for i, packet := range in {
		out[i] = cloneEAPPacket(packet)
	}
	return out
}

func cloneEAPPacketPtr(packet *eapaka.Packet) *eapaka.Packet {
	if packet == nil {
		return nil
	}
	out := cloneEAPPacket(*packet)
	return &out
}

func cloneEAPPacket(packet eapaka.Packet) eapaka.Packet {
	out := packet
	out.Attributes = cloneEAPAttributes(packet.Attributes)
	out.Data = append([]byte(nil), packet.Data...)
	return out
}

func cloneEAPAttributes(in []eapaka.Attribute) []eapaka.Attribute {
	out := make([]eapaka.Attribute, len(in))
	for i, attr := range in {
		out[i] = eapaka.Attribute{
			Type: attr.Type,
			Data: append([]byte(nil), attr.Data...),
		}
	}
	return out
}

func hasPayload(payloads []Payload, payloadType uint8) bool {
	for _, p := range payloads {
		if p.Type == payloadType {
			return true
		}
	}
	return false
}
