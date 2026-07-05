package ikev2

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/engine/swu/eapaka"
)

var (
	ErrInvalidAuthConfig   = errors.New("invalid ikev2 auth config")
	ErrInvalidAuthResponse = errors.New("invalid ikev2 auth response")
)

type AuthConfig struct {
	Transport        InitTransport
	Init             InitResult
	Keys             IKEKeys
	InitiatorID      Identity
	EAPIdentity      string
	ChildSA          SecurityAssociation
	ChildSPI         []byte
	TSi              TrafficSelectors
	TSr              TrafficSelectors
	Configuration    Configuration
	Random           io.Reader
	InitialIV        []byte
	EAPIdentityIV    []byte
	InitialMessageID uint32
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
	NextMessageID         uint32
}

type AKAChallengeConfig struct {
	Transport InitTransport
	Init      InitResult
	Keys      IKEKeys
	SIM       sim.AKAProvider
	Identity  string
	Request   eapaka.Packet
	ChildSPI  []byte
	MessageID uint32
	Random    io.Reader
	IV        []byte
}

type AKAChallengeResult struct {
	RequestBytes  []byte
	ResponseBytes []byte
	ResponseInner []Payload
	EAPResponse   eapaka.Packet
	EAPNext       *eapaka.Packet
	EAPKeys       eapaka.Keys
	ChildSA       *ChildSAResult
	SyncFailure   bool
	KDFNegotiated bool
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
	_, initialReqBytes, err := ProtectMessage(authHeader(cfg.Init, messageID, true), keys, true, initialInner, initialIV)
	if err != nil {
		return AuthResult{}, err
	}
	initialRespBytes, err := cfg.Transport.ExchangeIKE(ctx, initialReqBytes)
	if err != nil {
		return AuthResult{}, err
	}
	initialResp, initialInnerResp, err := unprotectAuthResponse(initialRespBytes, cfg.Init, keys, messageID)
	if err != nil {
		return AuthResult{}, err
	}
	eapReq, hasEAP, err := firstEAPPacket(initialInnerResp)
	if err != nil {
		return AuthResult{}, err
	}
	out := AuthResult{
		InitialRequestBytes:  append([]byte(nil), initialReqBytes...),
		InitialResponseBytes: append([]byte(nil), initialRespBytes...),
		InitialResponseInner: clonePayloads(initialInnerResp),
		NextMessageID:        messageID + 1,
	}
	_ = initialResp
	if !hasEAP {
		return out, nil
	}
	out.EAPRequest = &eapReq
	if eapReq.Code != eapaka.CodeRequest || eapReq.Subtype != eapaka.SubtypeIdentity {
		return out, nil
	}
	identity := strings.TrimSpace(cfg.EAPIdentity)
	if identity == "" {
		identity = strings.TrimSpace(string(cfg.InitiatorID.Data))
	}
	if identity == "" {
		return AuthResult{}, fmt.Errorf("%w: eap identity is empty", ErrInvalidAuthConfig)
	}
	identityPacket, err := (eapaka.Packet{
		Code:       eapaka.CodeResponse,
		Identifier: eapReq.Identifier,
		Type:       eapReq.Type,
		Subtype:    eapaka.SubtypeIdentity,
		Attributes: []eapaka.Attribute{eapaka.IdentityAttribute(identity)},
	}).MarshalBinary()
	if err != nil {
		return AuthResult{}, err
	}
	identityIV, err := authIV(cfg.Random, keys.Profile, cfg.EAPIdentityIV)
	if err != nil {
		return AuthResult{}, err
	}
	_, identityReqBytes, err := ProtectMessage(authHeader(cfg.Init, messageID+1, true), keys, true, []Payload{EAPPayload(identityPacket)}, identityIV)
	if err != nil {
		return AuthResult{}, err
	}
	identityRespBytes, err := cfg.Transport.ExchangeIKE(ctx, identityReqBytes)
	if err != nil {
		return AuthResult{}, err
	}
	_, identityInnerResp, err := unprotectAuthResponse(identityRespBytes, cfg.Init, keys, messageID+1)
	if err != nil {
		return AuthResult{}, err
	}
	out.IdentityRequestBytes = append([]byte(nil), identityReqBytes...)
	out.IdentityResponseBytes = append([]byte(nil), identityRespBytes...)
	out.IdentityResponseInner = clonePayloads(identityInnerResp)
	out.NextMessageID = messageID + 2
	if nextEAP, ok, err := firstEAPPacket(identityInnerResp); err != nil {
		return AuthResult{}, err
	} else if ok {
		out.EAPAfterIdentity = &nextEAP
	}
	return out, nil
}

func RunIKE_AUTH_AKAChallenge(ctx context.Context, cfg AKAChallengeConfig) (AKAChallengeResult, error) {
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
	var kdfNegotiated bool
	if response, negotiated, err := eapaka.BuildAKAPrimeKDFNegotiationResponse(cfg.Request); err != nil {
		return AKAChallengeResult{}, err
	} else if negotiated {
		eapResp = response
		kdfNegotiated = true
	} else {
		if cfg.SIM == nil {
			return AKAChallengeResult{}, fmt.Errorf("%w: SIM provider is nil", ErrInvalidAuthConfig)
		}
		rand16, autn16, err := eapaka.ChallengeRANDAndAUTN(cfg.Request)
		if err != nil {
			return AKAChallengeResult{}, err
		}
		aka, err := cfg.SIM.CalculateAKA(rand16, autn16)
		if err != nil {
			if errors.Is(err, sim.ErrSyncFailure) && len(aka.AUTS) > 0 {
				eapResp, err = eapaka.BuildSynchronizationFailureResponse(cfg.Request, aka.AUTS)
				syncFailure = true
			}
			if err != nil {
				return AKAChallengeResult{}, err
			}
		} else {
			identity := strings.TrimSpace(cfg.Identity)
			if identity == "" {
				return AKAChallengeResult{}, fmt.Errorf("%w: identity is empty", ErrInvalidAuthConfig)
			}
			eapResp, eapKeys, err = eapaka.BuildChallengeResponse(identity, cfg.Request, aka)
			if err != nil {
				return AKAChallengeResult{}, err
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
	_, reqBytes, err := ProtectMessage(authHeader(cfg.Init, cfg.MessageID, true), keys, true, []Payload{EAPPayload(eapRaw)}, iv)
	if err != nil {
		return AKAChallengeResult{}, err
	}
	respBytes, err := cfg.Transport.ExchangeIKE(ctx, reqBytes)
	if err != nil {
		return AKAChallengeResult{}, err
	}
	_, inner, err := unprotectAuthResponse(respBytes, cfg.Init, keys, cfg.MessageID)
	if err != nil {
		return AKAChallengeResult{}, err
	}
	out := AKAChallengeResult{
		RequestBytes:  append([]byte(nil), reqBytes...),
		ResponseBytes: append([]byte(nil), respBytes...),
		ResponseInner: clonePayloads(inner),
		EAPResponse:   eapResp,
		EAPKeys:       eapKeys,
		SyncFailure:   syncFailure,
		KDFNegotiated: kdfNegotiated,
		NextMessageID: cfg.MessageID + 1,
	}
	if next, ok, err := firstEAPPacket(inner); err != nil {
		return AKAChallengeResult{}, err
	} else if ok {
		out.EAPNext = &next
	}
	if hasPayload(inner, PayloadSA) {
		child, err := ParseChildSAResult(cfg.Init, inner, cfg.ChildSPI)
		if err != nil {
			return AKAChallengeResult{}, err
		}
		child.NextMessageID = cfg.MessageID + 1
		out.ChildSA = &child
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
	}
	saPayload, err := SecurityAssociationPayload(childSA)
	if err != nil {
		return nil, err
	}
	tsi := cfg.TSi
	if len(tsi.Selectors) == 0 {
		tsi = IPv4AnyTrafficSelectors()
	}
	tsiPayload, err := TrafficSelectorsPayload(PayloadTSi, tsi)
	if err != nil {
		return nil, err
	}
	tsr := cfg.TSr
	if len(tsr.Selectors) == 0 {
		tsr = IPv4AnyTrafficSelectors()
	}
	tsrPayload, err := TrafficSelectorsPayload(PayloadTSr, tsr)
	if err != nil {
		return nil, err
	}
	cfgPayload, err := ConfigurationPayload(firstConfiguration(cfg.Configuration, SWuConfigurationRequest()))
	if err != nil {
		return nil, err
	}
	return []Payload{idPayload, cfgPayload, saPayload, tsiPayload, tsrPayload}, nil
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

func unprotectAuthResponse(raw []byte, init InitResult, keys IKEKeys, messageID uint32) (Message, []Payload, error) {
	msg, inner, err := UnprotectMessage(raw, keys, false)
	if err != nil {
		return Message{}, nil, err
	}
	h := msg.Header
	if h.InitiatorSPI != init.InitiatorSPI || h.ResponderSPI != init.ResponderSPI ||
		h.ExchangeType != ExchangeIKE_AUTH || h.MessageID != messageID || h.Flags&FlagResponse == 0 {
		return Message{}, nil, fmt.Errorf("%w: unexpected IKE_AUTH response header", ErrInvalidAuthResponse)
	}
	return msg, inner, nil
}

func firstEAPPacket(payloads []Payload) (eapaka.Packet, bool, error) {
	for _, p := range payloads {
		if p.Type != PayloadEAP {
			continue
		}
		pkt, err := eapaka.ParsePacket(p.Body)
		if err != nil {
			return eapaka.Packet{}, false, err
		}
		return pkt, true, nil
	}
	return eapaka.Packet{}, false, nil
}

func authIV(random io.Reader, profile KeyMaterialProfile, override []byte) ([]byte, error) {
	if len(override) > 0 {
		if len(override) != profile.EncryptionBlockSize {
			return nil, fmt.Errorf("%w: IV length %d != %d", ErrInvalidAuthConfig, len(override), profile.EncryptionBlockSize)
		}
		return append([]byte(nil), override...), nil
	}
	return RandomIV(random, profile)
}

func firstConfiguration(value, fallback Configuration) Configuration {
	if value.Type != 0 || len(value.Attributes) > 0 {
		return value
	}
	return fallback
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

func hasPayload(payloads []Payload, payloadType uint8) bool {
	for _, p := range payloads {
		if p.Type == payloadType {
			return true
		}
	}
	return false
}
