package ikev2

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

type ChildSARekeyConfig struct {
	Transport       InitTransport
	Init            InitResult
	Keys            IKEKeys
	MessageID       uint32
	OldChildSA      ChildSAResult
	ChildSA         SecurityAssociation
	ChildSPI        []byte
	RekeySPI        []byte
	TSi             TrafficSelectors
	TSr             TrafficSelectors
	Nonce           []byte
	DHGroup         uint16
	DHPrivateKey    []byte
	Random          io.Reader
	IV              []byte
	MaxFragmentSize int
}

type ChildSARekeyPlan struct {
	Config       CreateChildSAConfig
	OldLocalSPI  []byte
	OldRemoteSPI []byte
	RekeySPI     []byte
	NewLocalSPI  []byte
}

func NewChildSARekeyPlan(cfg ChildSARekeyConfig) (ChildSARekeyPlan, error) {
	oldLocalSPI := append([]byte(nil), cfg.OldChildSA.LocalSPI...)
	if len(oldLocalSPI) != 4 {
		return ChildSARekeyPlan{}, fmt.Errorf("%w: old child local SPI length %d", ErrInvalidCreateChild, len(oldLocalSPI))
	}
	rekeySPI := append([]byte(nil), cfg.RekeySPI...)
	if len(rekeySPI) == 0 {
		rekeySPI = append([]byte(nil), oldLocalSPI...)
	}
	if len(rekeySPI) != 4 {
		return ChildSARekeyPlan{}, fmt.Errorf("%w: rekey SPI length %d", ErrInvalidCreateChild, len(rekeySPI))
	}
	childSA, childSPI, err := childSAForRekey(cfg)
	if err != nil {
		return ChildSARekeyPlan{}, err
	}
	tsi := cfg.TSi
	if len(tsi.Selectors) == 0 {
		tsi = cfg.OldChildSA.TSi
	}
	tsr := cfg.TSr
	if len(tsr.Selectors) == 0 {
		tsr = cfg.OldChildSA.TSr
	}
	return ChildSARekeyPlan{
		Config: CreateChildSAConfig{
			Transport:       cfg.Transport,
			Init:            cfg.Init,
			Keys:            cfg.Keys,
			MessageID:       cfg.MessageID,
			ChildSA:         childSA,
			ChildSPI:        childSPI,
			TSi:             cloneTrafficSelectors(tsi),
			TSr:             cloneTrafficSelectors(tsr),
			Nonce:           append([]byte(nil), cfg.Nonce...),
			RekeySPI:        rekeySPI,
			DHGroup:         cfg.DHGroup,
			DHPrivateKey:    append([]byte(nil), cfg.DHPrivateKey...),
			Random:          cfg.Random,
			IV:              append([]byte(nil), cfg.IV...),
			MaxFragmentSize: cfg.MaxFragmentSize,
		},
		OldLocalSPI:  oldLocalSPI,
		OldRemoteSPI: append([]byte(nil), cfg.OldChildSA.RemoteSPI...),
		RekeySPI:     append([]byte(nil), rekeySPI...),
		NewLocalSPI:  append([]byte(nil), childSPI...),
	}, nil
}

func RunCREATE_CHILD_SARekey(ctx context.Context, cfg ChildSARekeyConfig) (CreateChildSAResult, error) {
	plan, err := NewChildSARekeyPlan(cfg)
	if err != nil {
		return CreateChildSAResult{}, err
	}
	return RunCREATE_CHILD_SA(ctx, plan.Config)
}

type IKESARekeyConfig struct {
	Transport       InitTransport
	Init            InitResult
	Keys            IKEKeys
	MessageID       uint32
	SA              SecurityAssociation
	InitiatorSPI    uint64
	Nonce           []byte
	DHPrivateKey    []byte
	Random          io.Reader
	IV              []byte
	MaxFragmentSize int
}

type IKESARekeyResult struct {
	RequestBytes  []byte
	ResponseBytes []byte
	RequestNonce  []byte
	ResponseNonce []byte
	ResponseInner []Payload
	NewInit       InitResult
	NextMessageID uint32
}

// RunRekeyIKESA initiates an IKE SA rekey via CREATE_CHILD_SA per RFC 7296 §2.18.
func RunRekeyIKESA(ctx context.Context, cfg IKESARekeyConfig) (IKESARekeyResult, error) {
	if cfg.Transport == nil {
		return IKESARekeyResult{}, fmt.Errorf("%w: transport is nil", ErrInvalidCreateChild)
	}
	oldKeys := cfg.Keys
	if oldKeys.Profile.RequiredLength() == 0 {
		oldKeys = cfg.Init.Keys
	}
	if err := validateKeySet(oldKeys); err != nil {
		return IKESARekeyResult{}, err
	}
	if cfg.Init.InitiatorSPI == 0 || cfg.Init.ResponderSPI == 0 {
		return IKESARekeyResult{}, fmt.Errorf("%w: missing IKE SPIs", ErrInvalidCreateChild)
	}
	if cfg.MessageID == 0 && !cfg.Init.Rekeyed {
		return IKESARekeyResult{}, fmt.Errorf("%w: message_id is zero", ErrInvalidCreateChild)
	}
	random := cfg.Random
	if random == nil {
		random = rand.Reader
	}
	newSPII := cfg.InitiatorSPI
	var err error
	if newSPII == 0 {
		newSPII, err = randomSPI(random)
		if err != nil {
			return IKESARekeyResult{}, err
		}
	}
	offeredSA := cfg.SA
	if len(offeredSA.Proposals) == 0 {
		offeredSA = cfg.Init.SelectedSA
	}
	if len(offeredSA.Proposals) == 0 {
		offeredSA = DefaultIKEProposal()
	}
	offeredSA = cloneSecurityAssociation(offeredSA)
	var spiIBytes [8]byte
	binary.BigEndian.PutUint64(spiIBytes[:], newSPII)
	for i := range offeredSA.Proposals {
		if offeredSA.Proposals[i].ProtocolID != ProtocolIKE {
			return IKESARekeyResult{}, fmt.Errorf("%w: IKE rekey proposal protocol %d != ProtocolIKE", ErrInvalidCreateChild, offeredSA.Proposals[i].ProtocolID)
		}
		offeredSA.Proposals[i].SPI = append([]byte(nil), spiIBytes[:]...)
	}
	dhGroup, err := dhGroupFromSA(offeredSA)
	if err != nil {
		return IKESARekeyResult{}, err
	}
	dhEx, err := newDHKeyExchange(dhGroup, cfg.DHPrivateKey, random)
	if err != nil {
		return IKESARekeyResult{}, err
	}
	nonceI := append([]byte(nil), cfg.Nonce...)
	if len(nonceI) == 0 {
		nonceI, err = randomBytes(random, DefaultNonceLength)
		if err != nil {
			return IKESARekeyResult{}, err
		}
	}
	saPayload, err := SecurityAssociationPayload(offeredSA)
	if err != nil {
		return IKESARekeyResult{}, err
	}
	payloads := []Payload{
		saPayload,
		NoncePayload(nonceI),
		KeyExchangePayload(dhGroup, dhEx.public),
	}
	iv, err := createChildIV(random, oldKeys.Profile, cfg.IV)
	if err != nil {
		return IKESARekeyResult{}, err
	}
	reqBytes, respBytes, respMsg, inner, err := exchangeProtectedIKE(ctx, protectedExchangeConfig{
		Transport:              cfg.Transport,
		Header:                 createChildHeaderForRole(cfg.Init, cfg.MessageID, false),
		Keys:                   oldKeys,
		FromInitiator:          !cfg.Init.LocalIsResponder,
		Inner:                  payloads,
		IV:                     iv,
		FragmentationSupported: cfg.Init.FragmentationSupported,
		MaxFragmentSize:        cfg.MaxFragmentSize,
	})
	if err != nil {
		return IKESARekeyResult{}, err
	}
	if err := validateCreateChildResponseHeader(respMsg.Header, cfg.Init, cfg.MessageID); err != nil {
		return IKESARekeyResult{}, err
	}
	if err := FirstNotifyError(inner); err != nil {
		return IKESARekeyResult{}, fmt.Errorf("%w: %w", ErrInvalidCreateChild, err)
	}
	selectedSA, ok, err := firstSecurityAssociation(inner)
	if err != nil {
		return IKESARekeyResult{}, err
	}
	if !ok {
		return IKESARekeyResult{}, fmt.Errorf("%w: IKE rekey response missing SA", ErrInvalidCreateChild)
	}
	if err := ValidateSelectedSA(offeredSA, selectedSA); err != nil {
		return IKESARekeyResult{}, err
	}
	if len(selectedSA.Proposals[0].SPI) != 8 {
		return IKESARekeyResult{}, fmt.Errorf("%w: IKE rekey responder SPI length %d != 8", ErrInvalidCreateChild, len(selectedSA.Proposals[0].SPI))
	}
	newSPIR := binary.BigEndian.Uint64(selectedSA.Proposals[0].SPI)
	if newSPIR == 0 {
		return IKESARekeyResult{}, fmt.Errorf("%w: IKE rekey responder SPI is zero", ErrInvalidCreateChild)
	}
	nonceR, err := firstNonce(inner)
	if err != nil {
		return IKESARekeyResult{}, err
	}
	ke, ok, err := firstKeyExchange(inner)
	if err != nil {
		return IKESARekeyResult{}, err
	}
	if !ok || ke.DHGroup != dhGroup {
		return IKESARekeyResult{}, fmt.Errorf("%w: IKE rekey missing or mismatched KE", ErrInvalidCreateChild)
	}
	shared, err := dhEx.shared(ke.KeyData)
	if err != nil {
		return IKESARekeyResult{}, fmt.Errorf("%w: IKE rekey DH: %w", ErrInvalidCreateChild, err)
	}
	newProfile, err := KeyMaterialProfileFromSA(selectedSA)
	if err != nil {
		return IKESARekeyResult{}, err
	}
	skeyseed, err := RekeySKEYSEED(oldKeys.Profile.PRF, oldKeys.SKD, shared, nonceI, nonceR)
	if err != nil {
		return IKESARekeyResult{}, err
	}
	keyMat, err := DeriveIKESAKeyMaterial(newProfile.PRF, skeyseed, nonceI, nonceR, newSPII, newSPIR, newProfile.RequiredLength())
	if err != nil {
		return IKESARekeyResult{}, err
	}
	newKeys, err := SplitIKEKeys(newProfile, keyMat)
	if err != nil {
		return IKESARekeyResult{}, err
	}
	newInit := InitResult{
		SelectedSA:              selectedSA,
		InitiatorSPI:            newSPII,
		ResponderSPI:            newSPIR,
		NonceI:                  append([]byte(nil), nonceI...),
		NonceR:                  append([]byte(nil), nonceR...),
		PublicKeyI:              append([]byte(nil), dhEx.public...),
		PublicKeyR:              append([]byte(nil), ke.KeyData...),
		SharedSecret:            append([]byte(nil), shared...),
		PRF:                     newProfile.PRF,
		SKEYSEED:                skeyseed,
		KeyMaterial:             keyMat,
		Keys:                    newKeys,
		MOBIKESupported:         cfg.Init.MOBIKESupported,
		FragmentationSupported:  cfg.Init.FragmentationSupported,
		SignatureHashAlgorithms: append([]uint16(nil), cfg.Init.SignatureHashAlgorithms...),
		NATDetected:             cfg.Init.NATDetected,
		LocalIsResponder:        false,
		Rekeyed:                 true,
	}
	return IKESARekeyResult{
		RequestBytes:  append([]byte(nil), reqBytes...),
		ResponseBytes: append([]byte(nil), respBytes...),
		RequestNonce:  append([]byte(nil), nonceI...),
		ResponseNonce: append([]byte(nil), nonceR...),
		ResponseInner: clonePayloads(inner),
		NewInit:       newInit,
		NextMessageID: 0,
	}, nil
}

type ResponderCreateChildConfig struct {
	RawRequest          []byte
	Init                InitResult
	Keys                IKEKeys
	ActiveChildren      []ChildSAResult
	AllowedESPProposals SecurityAssociation
	AllowedIKEProposals SecurityAssociation
	LocalChildSPI       []byte
	LocalIKESPI         uint64
	ResponseNonce       []byte
	DHPrivateKey        []byte
	RekeyInFlight       bool
	Random              io.Reader
	IV                  []byte
}

type ResponderCreateChildResult struct {
	Message               Message
	ResponseMessage       Message
	ResponseBytes         []byte
	IsIKERekey            bool
	IsChildRekey          bool
	RekeyedChildLocalSPI  []byte
	RekeyedChildRemoteSPI []byte
	ChildSA               *ChildSAResult
	NewInit               *InitResult
	PeerNonce             []byte
	LocalNonce            []byte
	RejectedNotify        *Notify
}

// HandleResponderCreateChildSA processes an inbound peer-initiated CREATE_CHILD_SA
// request (ESP Child SA creation/rekey or IKE SA rekey) and builds the encrypted
// CREATE_CHILD_SA response per RFC 7296 §1.3.2, §1.3.3, §2.18, and §2.25.
func HandleResponderCreateChildSA(cfg ResponderCreateChildConfig) (ResponderCreateChildResult, error) {
	keys := cfg.Keys
	if keys.Profile.RequiredLength() == 0 {
		keys = cfg.Init.Keys
	}
	if err := validateKeySet(keys); err != nil {
		return ResponderCreateChildResult{}, err
	}
	random := cfg.Random
	if random == nil {
		random = rand.Reader
	}
	peerFromInitiator := cfg.Init.LocalIsResponder
	msg, inner, err := UnprotectMessage(cfg.RawRequest, keys, peerFromInitiator)
	if err != nil {
		return ResponderCreateChildResult{}, err
	}
	expectedReqFlags := uint8(0)
	if peerFromInitiator {
		expectedReqFlags |= FlagInitiator
	}
	h := msg.Header
	if h.InitiatorSPI != cfg.Init.InitiatorSPI || h.ResponderSPI != cfg.Init.ResponderSPI ||
		h.ExchangeType != ExchangeCREATE_CHILD_SA || h.Flags&(FlagInitiator|FlagResponse) != expectedReqFlags {
		return ResponderCreateChildResult{}, fmt.Errorf("%w: unexpected inbound CREATE_CHILD_SA request header", ErrInvalidCreateChild)
	}

	replyError := func(notify Notify) (ResponderCreateChildResult, error) {
		np, nErr := NotifyPayload(notify)
		if nErr != nil {
			return ResponderCreateChildResult{}, nErr
		}
		iv, ivErr := createChildIV(random, keys.Profile, cfg.IV)
		if ivErr != nil {
			return ResponderCreateChildResult{}, ivErr
		}
		respMsg, respRaw, pErr := ProtectMessage(createChildHeaderForRole(cfg.Init, h.MessageID, true), keys, !cfg.Init.LocalIsResponder, []Payload{np}, iv)
		if pErr != nil {
			return ResponderCreateChildResult{}, pErr
		}
		nCopy := cloneNotify(notify)
		return ResponderCreateChildResult{
			Message:         msg,
			ResponseMessage: respMsg,
			ResponseBytes:   respRaw,
			RejectedNotify:  &nCopy,
		}, nil
	}

	if cfg.RekeyInFlight {
		return replyError(Notify{NotifyType: NotifyTemporaryFailure})
	}

	offeredSA, hasSA, err := firstSecurityAssociation(inner)
	if err != nil || !hasSA || len(offeredSA.Proposals) == 0 {
		return replyError(Notify{NotifyType: NotifyInvalidSyntax})
	}
	peerNonce, err := firstNonce(inner)
	if err != nil {
		return replyError(Notify{NotifyType: NotifyInvalidSyntax})
	}
	peerKE, hasPeerKE, err := firstKeyExchange(inner)
	if err != nil {
		return replyError(Notify{NotifyType: NotifyInvalidSyntax})
	}

	var rekeyNotify *Notify
	for _, p := range inner {
		if p.Type != PayloadNotify {
			continue
		}
		n, nErr := ParseNotify(p.Body)
		if nErr != nil {
			return replyError(Notify{NotifyType: NotifyInvalidSyntax})
		}
		if n.NotifyType == NotifyRekeySA {
			nc := cloneNotify(n)
			rekeyNotify = &nc
		}
	}

	if offeredSA.Proposals[0].ProtocolID == ProtocolIKE && rekeyNotify == nil {
		return respondIKESARekey(cfg, keys, random, msg, offeredSA, peerNonce, peerKE, hasPeerKE, replyError)
	}
	return respondESPChildSA(cfg, keys, random, msg, inner, offeredSA, peerNonce, peerKE, hasPeerKE, rekeyNotify, replyError)
}

func respondIKESARekey(
	cfg ResponderCreateChildConfig,
	oldKeys IKEKeys,
	random io.Reader,
	reqMsg Message,
	offeredSA SecurityAssociation,
	peerNonce []byte,
	peerKE KeyExchange,
	hasPeerKE bool,
	replyError func(Notify) (ResponderCreateChildResult, error),
) (ResponderCreateChildResult, error) {
	allowed := cfg.AllowedIKEProposals
	if len(allowed.Proposals) == 0 {
		allowed = defaultResponderAllowedIKEProposals(cfg.Init.SelectedSA)
	}
	selectedProp, peerSPII, ok := selectResponderIKEProposal(offeredSA, allowed)
	if !ok {
		return replyError(Notify{NotifyType: NotifyNoProposalChosen})
	}
	dhTr, ok := findTransform(selectedProp, TransformDHRGroup)
	if !ok {
		return replyError(Notify{NotifyType: NotifyNoProposalChosen})
	}
	if !hasPeerKE || peerKE.DHGroup != dhTr.ID {
		var groupBuf [2]byte
		binary.BigEndian.PutUint16(groupBuf[:], dhTr.ID)
		return replyError(Notify{NotifyType: NotifyInvalidKEPayload, NotificationData: groupBuf[:]})
	}
	dhR, err := newDHKeyExchange(dhTr.ID, cfg.DHPrivateKey, random)
	if err != nil {
		return replyError(Notify{NotifyType: NotifyNoProposalChosen})
	}
	shared, err := dhR.shared(peerKE.KeyData)
	if err != nil {
		return replyError(Notify{NotifyType: NotifyInvalidSyntax})
	}
	localSPI := cfg.LocalIKESPI
	if localSPI == 0 {
		localSPI, err = randomSPI(random)
		if err != nil {
			return ResponderCreateChildResult{}, err
		}
	}
	var spiRBytes [8]byte
	binary.BigEndian.PutUint64(spiRBytes[:], localSPI)
	selectedProp.SPI = append([]byte(nil), spiRBytes[:]...)
	selectedSA := SecurityAssociation{Proposals: []Proposal{selectedProp}}

	localNonce := append([]byte(nil), cfg.ResponseNonce...)
	if len(localNonce) == 0 {
		localNonce, err = randomBytes(random, DefaultNonceLength)
		if err != nil {
			return ResponderCreateChildResult{}, err
		}
	}

	newProfile, err := KeyMaterialProfileFromSA(selectedSA)
	if err != nil {
		return replyError(Notify{NotifyType: NotifyNoProposalChosen})
	}
	skeyseed, err := RekeySKEYSEED(oldKeys.Profile.PRF, oldKeys.SKD, shared, peerNonce, localNonce)
	if err != nil {
		return ResponderCreateChildResult{}, err
	}
	keyMat, err := DeriveIKESAKeyMaterial(newProfile.PRF, skeyseed, peerNonce, localNonce, peerSPII, localSPI, newProfile.RequiredLength())
	if err != nil {
		return ResponderCreateChildResult{}, err
	}
	newKeys, err := SplitIKEKeys(newProfile, keyMat)
	if err != nil {
		return ResponderCreateChildResult{}, err
	}
	saPayload, err := SecurityAssociationPayload(selectedSA)
	if err != nil {
		return ResponderCreateChildResult{}, err
	}
	respInner := []Payload{
		saPayload,
		NoncePayload(localNonce),
		KeyExchangePayload(dhTr.ID, dhR.public),
	}
	iv, err := createChildIV(random, oldKeys.Profile, cfg.IV)
	if err != nil {
		return ResponderCreateChildResult{}, err
	}
	respMsg, respRaw, err := ProtectMessage(createChildHeaderForRole(cfg.Init, reqMsg.Header.MessageID, true), oldKeys, !cfg.Init.LocalIsResponder, respInner, iv)
	if err != nil {
		return ResponderCreateChildResult{}, err
	}
	newInit := InitResult{
		SelectedSA:              selectedSA,
		InitiatorSPI:            peerSPII,
		ResponderSPI:            localSPI,
		NonceI:                  append([]byte(nil), peerNonce...),
		NonceR:                  append([]byte(nil), localNonce...),
		PublicKeyI:              append([]byte(nil), peerKE.KeyData...),
		PublicKeyR:              append([]byte(nil), dhR.public...),
		SharedSecret:            append([]byte(nil), shared...),
		PRF:                     newProfile.PRF,
		SKEYSEED:                skeyseed,
		KeyMaterial:             keyMat,
		Keys:                    newKeys,
		MOBIKESupported:         cfg.Init.MOBIKESupported,
		FragmentationSupported:  cfg.Init.FragmentationSupported,
		SignatureHashAlgorithms: append([]uint16(nil), cfg.Init.SignatureHashAlgorithms...),
		NATDetected:             cfg.Init.NATDetected,
		LocalIsResponder:        true,
		Rekeyed:                 true,
	}
	return ResponderCreateChildResult{
		Message:         reqMsg,
		ResponseMessage: respMsg,
		ResponseBytes:   respRaw,
		IsIKERekey:      true,
		NewInit:         &newInit,
		PeerNonce:       append([]byte(nil), peerNonce...),
		LocalNonce:      append([]byte(nil), localNonce...),
	}, nil
}

func respondESPChildSA(
	cfg ResponderCreateChildConfig,
	keys IKEKeys,
	random io.Reader,
	reqMsg Message,
	inner []Payload,
	offeredSA SecurityAssociation,
	peerNonce []byte,
	peerKE KeyExchange,
	hasPeerKE bool,
	rekeyNotify *Notify,
	replyError func(Notify) (ResponderCreateChildResult, error),
) (ResponderCreateChildResult, error) {
	var oldChild *ChildSAResult
	if rekeyNotify != nil {
		if rekeyNotify.ProtocolID != ProtocolESP || len(rekeyNotify.SPI) != 4 {
			return replyError(Notify{NotifyType: NotifyInvalidSyntax})
		}
		for i := range cfg.ActiveChildren {
			c := &cfg.ActiveChildren[i]
			if bytes.Equal(rekeyNotify.SPI, c.RemoteSPI) || bytes.Equal(rekeyNotify.SPI, c.LocalSPI) {
				oldChild = c
				break
			}
		}
		if oldChild == nil {
			return replyError(Notify{
				ProtocolID: ProtocolESP,
				SPI:        append([]byte(nil), rekeyNotify.SPI...),
				NotifyType: NotifyChildSANotFound,
			})
		}
	}

	var wireTSi, wireTSr TrafficSelectors
	for _, p := range inner {
		switch p.Type {
		case PayloadTSi:
			ts, err := ParseTrafficSelectors(p.Body)
			if err != nil {
				return replyError(Notify{NotifyType: NotifyInvalidSyntax})
			}
			wireTSi = ts
		case PayloadTSr:
			ts, err := ParseTrafficSelectors(p.Body)
			if err != nil {
				return replyError(Notify{NotifyType: NotifyInvalidSyntax})
			}
			wireTSr = ts
		}
	}
	if len(wireTSi.Selectors) == 0 || len(wireTSr.Selectors) == 0 {
		return replyError(Notify{NotifyType: NotifyTSUnacceptable})
	}

	selectedRemoteTS := wireTSi
	selectedLocalTS := wireTSr
	if oldChild != nil {
		if len(oldChild.TSr.Selectors) > 0 {
			if err := ValidateTrafficSelectorNarrowing(wireTSi, oldChild.TSr); err == nil {
				selectedRemoteTS = cloneTrafficSelectors(oldChild.TSr)
			} else if err := ValidateTrafficSelectorNarrowing(oldChild.TSr, wireTSi); err != nil {
				return replyError(Notify{NotifyType: NotifyTSUnacceptable})
			}
		}
		if len(oldChild.TSi.Selectors) > 0 {
			if err := ValidateTrafficSelectorNarrowing(wireTSr, oldChild.TSi); err == nil {
				selectedLocalTS = cloneTrafficSelectors(oldChild.TSi)
			} else if err := ValidateTrafficSelectorNarrowing(oldChild.TSi, wireTSr); err != nil {
				return replyError(Notify{NotifyType: NotifyTSUnacceptable})
			}
		}
	}

	allowed := cfg.AllowedESPProposals
	if len(allowed.Proposals) == 0 {
		allowed = defaultResponderAllowedESPProposals(oldChild)
	}
	selectedProp, peerChildSPI, ok := selectResponderESPProposal(offeredSA, allowed)
	if !ok {
		return replyError(Notify{NotifyType: NotifyNoProposalChosen})
	}

	var dhShared []byte
	var respKE *Payload
	if dhTr, hasDH := findTransform(selectedProp, TransformDHRGroup); hasDH {
		if !hasPeerKE || peerKE.DHGroup != dhTr.ID {
			var groupBuf [2]byte
			binary.BigEndian.PutUint16(groupBuf[:], dhTr.ID)
			return replyError(Notify{NotifyType: NotifyInvalidKEPayload, NotificationData: groupBuf[:]})
		}
		dhR, err := newDHKeyExchange(dhTr.ID, cfg.DHPrivateKey, random)
		if err != nil {
			return replyError(Notify{NotifyType: NotifyNoProposalChosen})
		}
		dhShared, err = dhR.shared(peerKE.KeyData)
		if err != nil {
			return replyError(Notify{NotifyType: NotifyInvalidSyntax})
		}
		kp := KeyExchangePayload(dhTr.ID, dhR.public)
		respKE = &kp
	}

	localChildSPI := append([]byte(nil), cfg.LocalChildSPI...)
	if len(localChildSPI) == 0 {
		var err error
		localChildSPI, err = randomBytes(random, 4)
		if err != nil {
			return ResponderCreateChildResult{}, err
		}
	}
	if len(localChildSPI) != 4 {
		return ResponderCreateChildResult{}, fmt.Errorf("%w: local child SPI length %d", ErrInvalidCreateChild, len(localChildSPI))
	}
	selectedProp.SPI = append([]byte(nil), localChildSPI...)
	selectedSA := SecurityAssociation{Proposals: []Proposal{selectedProp}}

	localNonce := append([]byte(nil), cfg.ResponseNonce...)
	if len(localNonce) == 0 {
		var err error
		localNonce, err = randomBytes(random, DefaultNonceLength)
		if err != nil {
			return ResponderCreateChildResult{}, err
		}
	}

	childKeys, err := DeriveChildSAKeysForRole(keys.Profile.PRF, keys.SKD, dhShared, peerNonce, localNonce, selectedSA, false)
	if err != nil {
		return ResponderCreateChildResult{}, err
	}

	saPayload, err := SecurityAssociationPayload(selectedSA)
	if err != nil {
		return ResponderCreateChildResult{}, err
	}
	tsiPayload, err := TrafficSelectorsPayload(PayloadTSi, selectedRemoteTS)
	if err != nil {
		return ResponderCreateChildResult{}, err
	}
	tsrPayload, err := TrafficSelectorsPayload(PayloadTSr, selectedLocalTS)
	if err != nil {
		return ResponderCreateChildResult{}, err
	}
	respInner := []Payload{saPayload, NoncePayload(localNonce)}
	if respKE != nil {
		respInner = append(respInner, *respKE)
	}
	respInner = append(respInner, tsiPayload, tsrPayload)

	iv, err := createChildIV(random, keys.Profile, cfg.IV)
	if err != nil {
		return ResponderCreateChildResult{}, err
	}
	respMsg, respRaw, err := ProtectMessage(createChildHeaderForRole(cfg.Init, reqMsg.Header.MessageID, true), keys, !cfg.Init.LocalIsResponder, respInner, iv)
	if err != nil {
		return ResponderCreateChildResult{}, err
	}

	child := ChildSAResult{
		SelectedSA: selectedSA,
		TSi:        cloneTrafficSelectors(selectedLocalTS),
		TSr:        cloneTrafficSelectors(selectedRemoteTS),
		LocalSPI:   append([]byte(nil), localChildSPI...),
		RemoteSPI:  append([]byte(nil), peerChildSPI...),
		Keys:       childKeys,
	}
	out := ResponderCreateChildResult{
		Message:         reqMsg,
		ResponseMessage: respMsg,
		ResponseBytes:   respRaw,
		IsChildRekey:    oldChild != nil,
		ChildSA:         &child,
		PeerNonce:       append([]byte(nil), peerNonce...),
		LocalNonce:      append([]byte(nil), localNonce...),
	}
	if oldChild != nil {
		out.RekeyedChildLocalSPI = append([]byte(nil), oldChild.LocalSPI...)
		out.RekeyedChildRemoteSPI = append([]byte(nil), oldChild.RemoteSPI...)
	}
	return out, nil
}

// CompareRekeyCollisionNonces compares simultaneous rekey exchanges per RFC 7296
// §2.25: min(localNi, peerNr) vs min(peerNi, localNr). A return value > 0 means
// the locally initiated SA has the larger minimum nonce and wins (the peer's SA
// is redundant); < 0 means the peer-initiated SA wins and the locally initiated
// SA should be deleted.
func CompareRekeyCollisionNonces(localNi, peerNr, peerNi, localNr []byte) int {
	minLocal := minNonceBytes(localNi, peerNr)
	minPeer := minNonceBytes(peerNi, localNr)
	return bytes.Compare(minLocal, minPeer)
}

func minNonceBytes(a, b []byte) []byte {
	if bytes.Compare(a, b) <= 0 {
		return a
	}
	return b
}

func defaultResponderAllowedIKEProposals(current SecurityAssociation) SecurityAssociation {
	out := cloneSecurityAssociation(current)
	out.Proposals = append(out.Proposals, Default3GPPIKEProposal().Proposals...)
	out.Proposals = append(out.Proposals, Proposal{
		Number:     uint8(len(out.Proposals) + 1),
		ProtocolID: ProtocolIKE,
		Transforms: []Transform{
			{Type: TransformENCR, ID: ENCR_AES_GCM_16, Attributes: []TransformAttribute{KeyLengthAttribute(128)}},
			{Type: TransformENCR, ID: ENCR_AES_GCM_16, Attributes: []TransformAttribute{KeyLengthAttribute(256)}},
			{Type: TransformENCR, ID: ENCR_AES_CBC, Attributes: []TransformAttribute{KeyLengthAttribute(256)}},
			{Type: TransformPRF, ID: PRF_HMAC_SHA2_256},
			{Type: TransformPRF, ID: PRF_HMAC_SHA2_384},
			{Type: TransformPRF, ID: PRF_HMAC_SHA2_512},
			{Type: TransformDHRGroup, ID: DHGroupCurve25519},
			{Type: TransformDHRGroup, ID: DHGroup256BitECP},
			{Type: TransformDHRGroup, ID: DHGroup384BitECP},
			{Type: TransformDHRGroup, ID: DHGroup2048BitMODP},
		},
	})
	return out
}

func defaultResponderAllowedESPProposals(oldChild *ChildSAResult) SecurityAssociation {
	var out SecurityAssociation
	if oldChild != nil && len(oldChild.SelectedSA.Proposals) > 0 {
		out = cloneSecurityAssociation(oldChild.SelectedSA)
	}
	out.Proposals = append(out.Proposals, Default3GPPESPProposal([]byte{0, 0, 0, 1}).Proposals...)
	out.Proposals = append(out.Proposals,
		Proposal{
			Number:     uint8(len(out.Proposals) + 1),
			ProtocolID: ProtocolESP,
			SPI:        []byte{0, 0, 0, 1},
			Transforms: []Transform{
				{Type: TransformENCR, ID: ENCR_AES_CBC, Attributes: []TransformAttribute{KeyLengthAttribute(128)}},
				{Type: TransformENCR, ID: ENCR_AES_CBC, Attributes: []TransformAttribute{KeyLengthAttribute(256)}},
				{Type: TransformINTEG, ID: INTEG_HMAC_SHA2_256_128},
				{Type: TransformINTEG, ID: INTEG_HMAC_SHA2_384_192},
				{Type: TransformINTEG, ID: INTEG_HMAC_SHA2_512_256},
				{Type: TransformINTEG, ID: INTEG_HMAC_SHA1_96},
				{Type: TransformESN, ID: ESNNo},
				{Type: TransformESN, ID: ESNYes},
				{Type: TransformDHRGroup, ID: DHGroupCurve25519},
				{Type: TransformDHRGroup, ID: DHGroup256BitECP},
				{Type: TransformDHRGroup, ID: DHGroup2048BitMODP},
			},
		},
		Proposal{
			Number:     uint8(len(out.Proposals) + 2),
			ProtocolID: ProtocolESP,
			SPI:        []byte{0, 0, 0, 1},
			Transforms: []Transform{
				{Type: TransformENCR, ID: ENCR_AES_GCM_16, Attributes: []TransformAttribute{KeyLengthAttribute(128)}},
				{Type: TransformENCR, ID: ENCR_AES_GCM_16, Attributes: []TransformAttribute{KeyLengthAttribute(256)}},
				{Type: TransformESN, ID: ESNNo},
				{Type: TransformESN, ID: ESNYes},
				{Type: TransformDHRGroup, ID: DHGroupCurve25519},
				{Type: TransformDHRGroup, ID: DHGroup256BitECP},
				{Type: TransformDHRGroup, ID: DHGroup2048BitMODP},
			},
		},
	)
	return out
}

func selectResponderIKEProposal(offered, allowed SecurityAssociation) (Proposal, uint64, bool) {
	for _, offer := range offered.Proposals {
		if offer.ProtocolID != ProtocolIKE || len(offer.SPI) != 8 {
			continue
		}
		spi := binary.BigEndian.Uint64(offer.SPI)
		if spi == 0 {
			continue
		}
		for _, allow := range allowed.Proposals {
			if allow.ProtocolID != ProtocolIKE {
				continue
			}
			if selected, ok := matchSingleProposalTransforms(offer, allow, true); ok {
				return selected, spi, true
			}
		}
	}
	return Proposal{}, 0, false
}

func selectResponderESPProposal(offered, allowed SecurityAssociation) (Proposal, []byte, bool) {
	for _, offer := range offered.Proposals {
		if offer.ProtocolID != ProtocolESP || len(offer.SPI) != 4 {
			continue
		}
		for _, allow := range allowed.Proposals {
			if allow.ProtocolID != ProtocolESP {
				continue
			}
			if selected, ok := matchSingleProposalTransforms(offer, allow, false); ok {
				return selected, append([]byte(nil), offer.SPI...), true
			}
		}
	}
	return Proposal{}, nil, false
}

func matchSingleProposalTransforms(offer, allow Proposal, isIKE bool) (Proposal, bool) {
	encr, ok := pickMatchingTransform(offer, allow, TransformENCR)
	if !ok {
		return Proposal{}, false
	}
	transforms := []Transform{encr}
	if isIKE {
		prf, ok := pickMatchingTransform(offer, allow, TransformPRF)
		if !ok {
			return Proposal{}, false
		}
		transforms = append(transforms, prf)
	}
	if !isCombinedModeEncryption(encr.ID) {
		integ, ok := pickMatchingTransform(offer, allow, TransformINTEG)
		if !ok {
			return Proposal{}, false
		}
		transforms = append(transforms, integ)
	}
	if isIKE {
		dh, ok := pickMatchingTransform(offer, allow, TransformDHRGroup)
		if !ok {
			return Proposal{}, false
		}
		transforms = append(transforms, dh)
	} else {
		if offerHasTransformType(offer, TransformDHRGroup) {
			dh, ok := pickMatchingTransform(offer, allow, TransformDHRGroup)
			if !ok {
				return Proposal{}, false
			}
			transforms = append(transforms, dh)
		}
		esn, ok := pickMatchingTransform(offer, allow, TransformESN)
		if !ok {
			return Proposal{}, false
		}
		transforms = append(transforms, esn)
	}
	return Proposal{
		Number:     offer.Number,
		ProtocolID: offer.ProtocolID,
		Transforms: transforms,
	}, true
}

func offerHasTransformType(p Proposal, t uint8) bool {
	for _, tr := range p.Transforms {
		if tr.Type == t {
			return true
		}
	}
	return false
}

func pickMatchingTransform(offer, allow Proposal, transformType uint8) (Transform, bool) {
	for _, o := range offer.Transforms {
		if o.Type != transformType {
			continue
		}
		for _, a := range allow.Transforms {
			if a.Type == transformType && transformsEqual(o, a) {
				return cloneTransform(o), true
			}
		}
	}
	return Transform{}, false
}

func cloneTransform(in Transform) Transform {
	out := Transform{
		Type:       in.Type,
		ID:         in.ID,
		Attributes: make([]TransformAttribute, len(in.Attributes)),
	}
	for i, attr := range in.Attributes {
		out.Attributes[i] = TransformAttribute{
			Type:  attr.Type,
			Value: append([]byte(nil), attr.Value...),
		}
	}
	return out
}

func childSAForRekey(cfg ChildSARekeyConfig) (SecurityAssociation, []byte, error) {
	random := cfg.Random
	if random == nil {
		random = rand.Reader
	}
	childSPI := append([]byte(nil), cfg.ChildSPI...)
	if len(childSPI) == 0 && len(cfg.ChildSA.Proposals) > 0 {
		childSPI = append([]byte(nil), cfg.ChildSA.Proposals[0].SPI...)
	}
	if len(childSPI) == 0 {
		var err error
		childSPI, err = randomBytes(random, 4)
		if err != nil {
			return SecurityAssociation{}, nil, err
		}
	}
	if len(childSPI) != 4 {
		return SecurityAssociation{}, nil, fmt.Errorf("%w: child SPI length %d", ErrInvalidCreateChild, len(childSPI))
	}
	sa := cfg.ChildSA
	if len(sa.Proposals) == 0 {
		sa = cfg.OldChildSA.SelectedSA
	}
	if len(sa.Proposals) == 0 {
		sa = DefaultESPProposal(childSPI)
	} else {
		sa = cloneSecurityAssociation(sa)
		if len(sa.Proposals) != 1 {
			return SecurityAssociation{}, nil, fmt.Errorf("%w: proposal count %d", ErrInvalidCreateChild, len(sa.Proposals))
		}
		if sa.Proposals[0].ProtocolID != ProtocolESP {
			return SecurityAssociation{}, nil, fmt.Errorf("%w: protocol %d is not ESP", ErrInvalidCreateChild, sa.Proposals[0].ProtocolID)
		}
		sa.Proposals[0].SPI = append([]byte(nil), childSPI...)
	}
	return sa, childSPI, nil
}

func cloneTrafficSelectors(in TrafficSelectors) TrafficSelectors {
	out := TrafficSelectors{Selectors: make([]TrafficSelector, len(in.Selectors))}
	for i, selector := range in.Selectors {
		out.Selectors[i] = TrafficSelector{
			Type:       selector.Type,
			IPProtocol: selector.IPProtocol,
			StartPort:  selector.StartPort,
			EndPort:    selector.EndPort,
			StartAddr:  append([]byte(nil), selector.StartAddr...),
			EndAddr:    append([]byte(nil), selector.EndAddr...),
		}
	}
	return out
}
