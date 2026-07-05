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

const maxAKAControlFollowups = 3

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
	EAPKeys   eapaka.Keys
	Identity  string
	Request   eapaka.Packet
	ChildSPI  []byte
	MessageID uint32
	Random    io.Reader
	IV        []byte
}

type AKAChallengeResult struct {
	RequestBytes          []byte
	ResponseBytes         []byte
	ResponseInner         []Payload
	EAPResponse           eapaka.Packet
	EAPNext               *eapaka.Packet
	EAPKeys               eapaka.Keys
	EAPNotifications      []eapaka.Packet
	EAPClientError        bool
	ChildSA               *ChildSAResult
	SyncFailure           bool
	KDFNegotiated         bool
	NextMessageID         uint32
	FollowupRequestBytes  [][]byte
	FollowupResponseBytes [][]byte
	FinalResponseBytes    []byte
	FinalResponseInner    []Payload
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
	var clientError bool
	var notifications []eapaka.Packet
	if response, handled, err := buildAKAControlResponse(cfg.Request, cfg.EAPKeys); err != nil {
		return AKAChallengeResult{}, err
	} else if handled {
		eapResp = response
		clientError = response.Subtype == eapaka.SubtypeClientError
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
	controlKeys := eapKeys
	if len(controlKeys.KAut) == 0 {
		controlKeys = cfg.EAPKeys
	}
	resultEAPKeys := eapKeys
	if len(resultEAPKeys.KAut) == 0 {
		resultEAPKeys = cfg.EAPKeys
	}
	followups, err := runAKAControlFollowups(ctx, cfg, keys, inner, cfg.MessageID+1, controlKeys)
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
	out := AKAChallengeResult{
		RequestBytes:          append([]byte(nil), reqBytes...),
		ResponseBytes:         append([]byte(nil), respBytes...),
		ResponseInner:         clonePayloads(inner),
		EAPResponse:           eapResp,
		EAPKeys:               resultEAPKeys,
		EAPNotifications:      cloneEAPPackets(notifications),
		EAPClientError:        clientError,
		SyncFailure:           syncFailure,
		KDFNegotiated:         kdfNegotiated,
		NextMessageID:         nextMessageID,
		FollowupRequestBytes:  cloneByteSlices(followups.RequestBytes),
		FollowupResponseBytes: cloneByteSlices(followups.ResponseBytes),
		FinalResponseBytes:    append([]byte(nil), finalRespBytes...),
		FinalResponseInner:    clonePayloads(finalInner),
	}
	if next, ok, err := firstEAPPacket(finalInner); err != nil {
		return AKAChallengeResult{}, err
	} else if ok {
		out.EAPNext = &next
	}
	if hasPayload(finalInner, PayloadSA) {
		child, err := ParseChildSAResult(cfg.Init, finalInner, cfg.ChildSPI)
		if err != nil {
			return AKAChallengeResult{}, err
		}
		child.NextMessageID = nextMessageID
		out.ChildSA = &child
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

func runAKAControlFollowups(ctx context.Context, cfg AKAChallengeConfig, keys IKEKeys, initialInner []Payload, messageID uint32, eapKeys eapaka.Keys) (akaControlFollowups, error) {
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
		response, handled, err := buildAKAControlResponse(next, eapKeys)
		if err != nil {
			return akaControlFollowups{}, err
		}
		if !handled {
			return out, nil
		}
		if response.Subtype == eapaka.SubtypeNotification {
			out.Notifications = append(out.Notifications, cloneEAPPacket(next))
		}
		if response.Subtype == eapaka.SubtypeClientError {
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
		_, reqBytes, err := ProtectMessage(authHeader(cfg.Init, out.NextMessageID, true), keys, true, []Payload{EAPPayload(raw)}, iv)
		if err != nil {
			return akaControlFollowups{}, err
		}
		respBytes, err := cfg.Transport.ExchangeIKE(ctx, reqBytes)
		if err != nil {
			return akaControlFollowups{}, err
		}
		_, inner, err := unprotectAuthResponse(respBytes, cfg.Init, keys, out.NextMessageID)
		if err != nil {
			return akaControlFollowups{}, err
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
		if _, handled, err := buildAKAControlResponse(next, eapKeys); err != nil {
			return akaControlFollowups{}, err
		} else if handled {
			return akaControlFollowups{}, fmt.Errorf("%w: too many EAP-AKA control followups", ErrInvalidAuthResponse)
		}
	}
	return out, nil
}

func buildAKAControlResponse(request eapaka.Packet, keys eapaka.Keys) (eapaka.Packet, bool, error) {
	if response, handled, err := eapaka.BuildNotificationResponse(request); err != nil {
		if errors.Is(err, eapaka.ErrInvalidKeyMaterial) && len(keys.KAut) > 0 {
			return eapaka.BuildAuthenticatedNotificationResponse(request, keys.KAut)
		}
		return eapaka.Packet{}, handled, err
	} else if handled {
		return response, true, nil
	}
	if request.Code == eapaka.CodeRequest && request.Subtype != eapaka.SubtypeChallenge {
		response, err := eapaka.BuildClientErrorResponse(request, eapaka.ClientErrorUnableToProcessPacket)
		return response, true, err
	}
	return eapaka.Packet{}, false, nil
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

func cloneEAPPacket(packet eapaka.Packet) eapaka.Packet {
	out := packet
	out.Attributes = make([]eapaka.Attribute, len(packet.Attributes))
	for i, attr := range packet.Attributes {
		out.Attributes[i] = eapaka.Attribute{
			Type: attr.Type,
			Data: append([]byte(nil), attr.Data...),
		}
	}
	out.Data = append([]byte(nil), packet.Data...)
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
