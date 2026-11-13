package ikev2

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

var ErrInvalidCreateChild = errors.New("invalid ikev2 create child sa exchange")

func CreateChildSANotifyActionFromError(err error) (NotifyAction, bool) {
	return NotifyActionFromError(err)
}

type CreateChildSAConfig struct {
	Transport       InitTransport
	Init            InitResult
	Keys            IKEKeys
	MessageID       uint32
	ChildSA         SecurityAssociation
	ChildSPI        []byte
	TSi             TrafficSelectors
	TSr             TrafficSelectors
	Nonce           []byte
	RekeySPI        []byte
	DHGroup         uint16
	DHPrivateKey    []byte
	Random          io.Reader
	IV              []byte
	MaxFragmentSize int
}

type CreateChildSAResult struct {
	RequestBytes  []byte
	ResponseBytes []byte
	RequestNonce  []byte
	ResponseNonce []byte
	ResponseInner []Payload
	ChildSA       ChildSAResult
	NextMessageID uint32
	Rekeyed       bool
}

func RunCREATE_CHILD_SA(ctx context.Context, cfg CreateChildSAConfig) (CreateChildSAResult, error) {
	if cfg.Transport == nil {
		return CreateChildSAResult{}, fmt.Errorf("%w: transport is nil", ErrInvalidCreateChild)
	}
	keys := cfg.Keys
	if keys.Profile.RequiredLength() == 0 {
		keys = cfg.Init.Keys
	}
	if err := validateKeySet(keys); err != nil {
		return CreateChildSAResult{}, err
	}
	if cfg.Init.InitiatorSPI == 0 || cfg.Init.ResponderSPI == 0 {
		return CreateChildSAResult{}, fmt.Errorf("%w: missing IKE SPIs", ErrInvalidCreateChild)
	}
	if cfg.MessageID == 0 && !cfg.Init.Rekeyed {
		return CreateChildSAResult{}, fmt.Errorf("%w: message_id is zero", ErrInvalidCreateChild)
	}
	payloads, requestNonce, localSPI, dhEx, dhGroup, err := buildCreateChildSAPayloadsWithDH(cfg)
	if err != nil {
		return CreateChildSAResult{}, err
	}
	offeredSA, ok, err := firstSecurityAssociation(payloads)
	if err != nil {
		return CreateChildSAResult{}, err
	}
	if !ok {
		return CreateChildSAResult{}, fmt.Errorf("%w: missing request SA", ErrInvalidCreateChild)
	}
	iv, err := createChildIV(cfg.Random, keys.Profile, cfg.IV)
	if err != nil {
		return CreateChildSAResult{}, err
	}
	fromOriginalInitiator := !cfg.Init.LocalIsResponder
	reqBytes, respBytes, respMsg, inner, err := exchangeProtectedIKE(ctx, protectedExchangeConfig{
		Transport:              cfg.Transport,
		Header:                 createChildHeaderForRole(cfg.Init, cfg.MessageID, false),
		Keys:                   keys,
		FromInitiator:          fromOriginalInitiator,
		Inner:                  payloads,
		IV:                     iv,
		FragmentationSupported: cfg.Init.FragmentationSupported,
		MaxFragmentSize:        cfg.MaxFragmentSize,
	})
	if err != nil {
		return CreateChildSAResult{}, err
	}
	if err := validateCreateChildResponseHeader(respMsg.Header, cfg.Init, cfg.MessageID); err != nil {
		return CreateChildSAResult{}, err
	}
	if err := FirstNotifyError(inner); err != nil {
		return CreateChildSAResult{}, fmt.Errorf("%w: %w", ErrInvalidCreateChild, err)
	}
	responseNonce, err := firstNonce(inner)
	if err != nil {
		return CreateChildSAResult{}, err
	}
	var dhShared []byte
	if dhGroup != 0 {
		ke, ok, err := firstKeyExchange(inner)
		if err != nil {
			return CreateChildSAResult{}, err
		}
		if !ok {
			return CreateChildSAResult{}, fmt.Errorf("%w: missing responder KE for PFS group %d", ErrInvalidCreateChild, dhGroup)
		}
		if ke.DHGroup != dhGroup {
			return CreateChildSAResult{}, fmt.Errorf("%w: responder KE group %d != %d", ErrInvalidCreateChild, ke.DHGroup, dhGroup)
		}
		dhShared, err = dhEx.shared(ke.KeyData)
		if err != nil {
			return CreateChildSAResult{}, fmt.Errorf("%w: PFS DH: %w", ErrInvalidCreateChild, err)
		}
	}
	parseInit := cfg.Init
	parseInit.Keys = keys
	child, err := parseChildSAResultWithNoncesAndDH(
		parseInit,
		inner,
		localSPI,
		dhShared,
		requestNonce,
		responseNonce,
		&offeredSA,
		trafficSelectorsOrSWuAny(cfg.TSi),
		trafficSelectorsOrSWuAny(cfg.TSr),
		true,
	)
	if err != nil {
		return CreateChildSAResult{}, err
	}
	child.NextMessageID = cfg.MessageID + 1
	return CreateChildSAResult{
		RequestBytes:  append([]byte(nil), reqBytes...),
		ResponseBytes: append([]byte(nil), respBytes...),
		RequestNonce:  append([]byte(nil), requestNonce...),
		ResponseNonce: append([]byte(nil), responseNonce...),
		ResponseInner: clonePayloads(inner),
		ChildSA:       child,
		NextMessageID: cfg.MessageID + 1,
		Rekeyed:       len(cfg.RekeySPI) > 0,
	}, nil
}

func BuildCreateChildSAPayloads(cfg CreateChildSAConfig) ([]Payload, []byte, []byte, error) {
	payloads, nonce, localSPI, _, _, err := buildCreateChildSAPayloadsWithDH(cfg)
	return payloads, nonce, localSPI, err
}

func buildCreateChildSAPayloadsWithDH(cfg CreateChildSAConfig) ([]Payload, []byte, []byte, dhKeyExchange, uint16, error) {
	random := cfg.Random
	if random == nil {
		random = rand.Reader
	}
	childSA, localSPI, err := createChildProposal(cfg, random)
	if err != nil {
		return nil, nil, nil, dhKeyExchange{}, 0, err
	}
	dhGroup := cfg.DHGroup
	if dhGroup == 0 {
		if tr, ok := findTransform(childSA.Proposals[0], TransformDHRGroup); ok {
			dhGroup = tr.ID
		}
	} else if !proposalHasDHGroup(childSA.Proposals[0], dhGroup) {
		childSA.Proposals[0].Transforms = append(childSA.Proposals[0].Transforms, Transform{
			Type: TransformDHRGroup,
			ID:   dhGroup,
		})
	}
	var dhEx dhKeyExchange
	if dhGroup != 0 {
		dhEx, err = newDHKeyExchange(dhGroup, cfg.DHPrivateKey, random)
		if err != nil {
			return nil, nil, nil, dhKeyExchange{}, 0, err
		}
	}
	nonce := append([]byte(nil), cfg.Nonce...)
	if len(nonce) == 0 {
		nonce, err = randomBytes(random, DefaultNonceLength)
		if err != nil {
			return nil, nil, nil, dhKeyExchange{}, 0, err
		}
	}
	if len(nonce) == 0 {
		return nil, nil, nil, dhKeyExchange{}, 0, fmt.Errorf("%w: nonce is empty", ErrInvalidCreateChild)
	}
	saPayload, err := SecurityAssociationPayload(childSA)
	if err != nil {
		return nil, nil, nil, dhKeyExchange{}, 0, err
	}
	tsi := trafficSelectorsOrSWuAny(cfg.TSi)
	tsiPayload, err := TrafficSelectorsPayload(PayloadTSi, tsi)
	if err != nil {
		return nil, nil, nil, dhKeyExchange{}, 0, err
	}
	tsr := trafficSelectorsOrSWuAny(cfg.TSr)
	tsrPayload, err := TrafficSelectorsPayload(PayloadTSr, tsr)
	if err != nil {
		return nil, nil, nil, dhKeyExchange{}, 0, err
	}
	payloads := make([]Payload, 0, 6)
	if len(cfg.RekeySPI) > 0 {
		if len(cfg.RekeySPI) != 4 {
			return nil, nil, nil, dhKeyExchange{}, 0, fmt.Errorf("%w: rekey SPI length %d", ErrInvalidCreateChild, len(cfg.RekeySPI))
		}
		rekey, err := NotifyPayload(Notify{
			ProtocolID: ProtocolESP,
			NotifyType: NotifyRekeySA,
			SPI:        append([]byte(nil), cfg.RekeySPI...),
		})
		if err != nil {
			return nil, nil, nil, dhKeyExchange{}, 0, err
		}
		payloads = append(payloads, rekey)
	}
	payloads = append(payloads, saPayload, NoncePayload(nonce))
	if dhGroup != 0 {
		payloads = append(payloads, KeyExchangePayload(dhGroup, dhEx.public))
	}
	payloads = append(payloads, tsiPayload, tsrPayload)
	return payloads, nonce, localSPI, dhEx, dhGroup, nil
}

func proposalHasDHGroup(p Proposal, dhGroup uint16) bool {
	for _, tr := range p.Transforms {
		if tr.Type == TransformDHRGroup && tr.ID == dhGroup {
			return true
		}
	}
	return false
}

func firstKeyExchange(payloads []Payload) (KeyExchange, bool, error) {
	for _, p := range payloads {
		if p.Type == PayloadKE {
			ke, err := ParseKeyExchange(p.Body)
			if err != nil {
				return KeyExchange{}, false, err
			}
			return ke, true, nil
		}
	}
	return KeyExchange{}, false, nil
}

func createChildProposal(cfg CreateChildSAConfig, random io.Reader) (SecurityAssociation, []byte, error) {
	sa := cfg.ChildSA
	spi := append([]byte(nil), cfg.ChildSPI...)
	if len(sa.Proposals) == 0 {
		if len(spi) == 0 {
			var err error
			spi, err = randomBytes(random, 4)
			if err != nil {
				return SecurityAssociation{}, nil, err
			}
		}
		if len(spi) != 4 {
			return SecurityAssociation{}, nil, fmt.Errorf("%w: child SPI length %d", ErrInvalidCreateChild, len(spi))
		}
		return DefaultESPProposal(spi), spi, nil
	}
	if len(sa.Proposals) != 1 {
		return SecurityAssociation{}, nil, fmt.Errorf("%w: proposal count %d", ErrInvalidCreateChild, len(sa.Proposals))
	}
	sa = cloneSecurityAssociation(sa)
	if len(spi) == 0 {
		spi = append([]byte(nil), sa.Proposals[0].SPI...)
	} else {
		sa.Proposals[0].SPI = append([]byte(nil), spi...)
	}
	if len(spi) != 4 {
		return SecurityAssociation{}, nil, fmt.Errorf("%w: child SPI length %d", ErrInvalidCreateChild, len(spi))
	}
	return sa, spi, nil
}

func validateCreateChildResponseHeader(h Header, init InitResult, messageID uint32) error {
	expectedFlags := FlagResponse
	if init.LocalIsResponder {
		expectedFlags |= FlagInitiator
	}
	if h.InitiatorSPI != init.InitiatorSPI || h.ResponderSPI != init.ResponderSPI ||
		h.ExchangeType != ExchangeCREATE_CHILD_SA || h.MessageID != messageID ||
		h.Flags&(FlagInitiator|FlagResponse) != expectedFlags {
		return fmt.Errorf("%w: unexpected CREATE_CHILD_SA response header", ErrInvalidCreateChild)
	}
	return nil
}

func unprotectCreateChildResponse(raw []byte, init InitResult, keys IKEKeys, messageID uint32) (Message, []Payload, error) {
	msg, inner, err := UnprotectMessage(raw, keys, init.LocalIsResponder)
	if err != nil {
		return Message{}, nil, err
	}
	if err := validateCreateChildResponseHeader(msg.Header, init, messageID); err != nil {
		return Message{}, nil, err
	}
	return msg, inner, nil
}

func createChildHeader(init InitResult, messageID uint32, fromInitiator bool) Header {
	flags := uint8(0)
	if fromInitiator {
		flags |= FlagInitiator
	} else {
		flags |= FlagResponse
	}
	return Header{
		InitiatorSPI: init.InitiatorSPI,
		ResponderSPI: init.ResponderSPI,
		ExchangeType: ExchangeCREATE_CHILD_SA,
		Flags:        flags,
		MessageID:    messageID,
	}
}

func createChildHeaderForRole(init InitResult, messageID uint32, isResponse bool) Header {
	flags := uint8(0)
	if !init.LocalIsResponder {
		flags |= FlagInitiator
	}
	if isResponse {
		flags |= FlagResponse
	}
	return Header{
		InitiatorSPI: init.InitiatorSPI,
		ResponderSPI: init.ResponderSPI,
		ExchangeType: ExchangeCREATE_CHILD_SA,
		Flags:        flags,
		MessageID:    messageID,
	}
}

func firstNonce(payloads []Payload) ([]byte, error) {
	for _, payload := range payloads {
		if payload.Type == PayloadNonce {
			if len(payload.Body) == 0 {
				return nil, fmt.Errorf("%w: empty nonce", ErrInvalidCreateChild)
			}
			return append([]byte(nil), payload.Body...), nil
		}
	}
	return nil, fmt.Errorf("%w: missing nonce", ErrInvalidCreateChild)
}

func createChildIV(random io.Reader, profile KeyMaterialProfile, override []byte) ([]byte, error) {
	if len(override) > 0 {
		if len(override) != profile.EncryptionBlockSize {
			return nil, fmt.Errorf("%w: IV length %d != %d", ErrInvalidCreateChild, len(override), profile.EncryptionBlockSize)
		}
		return append([]byte(nil), override...), nil
	}
	if profile.EncryptionID == ENCR_AES_GCM_16 {
		return nil, nil
	}
	return RandomIV(random, profile)
}

func cloneSecurityAssociation(in SecurityAssociation) SecurityAssociation {
	out := SecurityAssociation{Proposals: make([]Proposal, len(in.Proposals))}
	for i, proposal := range in.Proposals {
		out.Proposals[i] = Proposal{
			Number:     proposal.Number,
			ProtocolID: proposal.ProtocolID,
			SPI:        append([]byte(nil), proposal.SPI...),
			Transforms: make([]Transform, len(proposal.Transforms)),
		}
		for j, transform := range proposal.Transforms {
			out.Proposals[i].Transforms[j] = Transform{
				Type:       transform.Type,
				ID:         transform.ID,
				Attributes: make([]TransformAttribute, len(transform.Attributes)),
			}
			for k, attr := range transform.Attributes {
				out.Proposals[i].Transforms[j].Attributes[k] = TransformAttribute{
					Type:  attr.Type,
					Value: append([]byte(nil), attr.Value...),
				}
			}
		}
	}
	return out
}
