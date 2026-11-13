package voicehost

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
)

type RTPRelaySRTPConfig struct {
	Profiles         []SRTPProtectionProfile
	CryptoTag        string
	SessionParams    string
	ReplayWindowSize uint
	ClientPlaintext  bool
	Random           io.Reader
}

type outboundSDESRelayNegotiation struct {
	mu                sync.Mutex
	cfg               RTPRelaySRTPConfig
	clientSDP         SDPInfo
	imsSDP            SDPInfo
	clientSecurity    SDPSecurityInfo
	clientPlaintext   bool
	imsPlaintext      bool
	established       bool
	profile           SRTPProtectionProfile
	clientSendKeys    SRTPKeys
	imsSendKeys       SRTPKeys
	relayToIMSKeys    SRTPKeys
	relayToClientKeys SRTPKeys
	imsOfferCrypto    SDPCryptoAttribute
	clientCrypto      SDPCryptoAttribute
}

type inboundSDESRelayNegotiation struct {
	mu                sync.Mutex
	cfg               RTPRelaySRTPConfig
	imsSDP            SDPInfo
	imsSecurity       SDPSecurityInfo
	imsPlaintext      bool
	clientPlaintext   bool
	established       bool
	profile           SRTPProtectionProfile
	imsSendKeys       SRTPKeys
	clientSendKeys    SRTPKeys
	relayToIMSKeys    SRTPKeys
	relayToClientKeys SRTPKeys
	clientOfferCrypto SDPCryptoAttribute
	imsAnswerCrypto   SDPCryptoAttribute
}

func newOutboundSDESRelayNegotiation(clientOffer []byte, cfg RTPRelaySRTPConfig) (*outboundSDESRelayNegotiation, error) {
	clientSDP, clientSecurity, err := ParseSDPWithSecurity(clientOffer)
	if err != nil {
		return nil, err
	}
	clientWantsSecurity := len(clientSecurity.Crypto) > 0 || isSecureSDPRTPProfile(clientSecurity.RTPProfile)
	var (
		clientPlaintext bool
		profile         SRTPProtectionProfile
		clientSendKeys  SRTPKeys
		clientAnswerTag string
		clientSessParam string
	)
	if clientWantsSecurity {
		selectedAttr, selProfile, clientParams, ok, err := SelectSDPCryptoAttribute(clientSecurity.Crypto, cfg.Profiles)
		if err != nil {
			return nil, fmt.Errorf("%w: client offer crypto: %v", ErrSDPSecurityNegotiation, err)
		}
		if !ok {
			return nil, fmt.Errorf("%w: missing compatible client SDES crypto", ErrSDPSecurityNegotiation)
		}
		keys, err := srtpKeysFromSDPCryptoAttr(selectedAttr, clientParams)
		if err != nil {
			return nil, fmt.Errorf("%w: client offer crypto keys: %v", ErrSDPSecurityNegotiation, err)
		}
		profile = selProfile
		clientSendKeys = keys
		clientAnswerTag = strings.TrimSpace(selectedAttr.Tag)
		clientSessParam = firstVoiceNonEmpty(cfg.SessionParams, selectedAttr.SessionParams)
	} else {
		clientPlaintext = true
		profile = srtpRelayPreferredProfiles(cfg.Profiles)[0]
		clientAnswerTag = firstVoiceNonEmpty(cfg.CryptoTag, "1")
		clientSessParam = cfg.SessionParams
	}
	relayToIMSKeys, err := GenerateSRTPKeys(profile, cfg.Random)
	if err != nil {
		return nil, err
	}
	relayToClientKeys, err := GenerateSRTPKeys(profile, cfg.Random)
	if err != nil {
		return nil, err
	}
	relayToIMSKeys.SessionParams = cfg.SessionParams
	relayToClientKeys.SessionParams = clientSessParam
	offerTag := firstVoiceNonEmpty(cfg.CryptoTag, "1")
	imsOfferCrypto, err := buildSDESCryptoForKeys(offerTag, profile, relayToIMSKeys, cfg.SessionParams)
	if err != nil {
		return nil, err
	}
	clientCrypto, err := buildSDESCryptoForKeys(firstVoiceNonEmpty(clientAnswerTag, offerTag), profile, relayToClientKeys, clientSessParam)
	if err != nil {
		return nil, err
	}
	return &outboundSDESRelayNegotiation{
		cfg:               cfg,
		clientSDP:         clientSDP,
		clientSecurity:    clientSecurity,
		clientPlaintext:   clientPlaintext,
		profile:           profile,
		clientSendKeys:    clientSendKeys,
		relayToIMSKeys:    relayToIMSKeys,
		relayToClientKeys: relayToClientKeys,
		imsOfferCrypto:    imsOfferCrypto,
		clientCrypto:      clientCrypto,
	}, nil
}

func newInboundSDESRelayNegotiation(imsOffer []byte, cfg RTPRelaySRTPConfig) (*inboundSDESRelayNegotiation, error) {
	imsSDP, imsSecurity, err := ParseSDPWithSecurity(imsOffer)
	if err != nil {
		return nil, err
	}
	imsWantsSecurity := len(imsSecurity.Crypto) > 0 || isSecureSDPRTPProfile(imsSecurity.RTPProfile)
	var (
		imsPlaintext  bool
		profile       SRTPProtectionProfile
		imsSendKeys   SRTPKeys
		imsAnswerTag  string
		imsSessParams string
	)
	if imsWantsSecurity {
		selectedAttr, selProfile, imsParams, ok, err := SelectSDPCryptoAttribute(imsSecurity.Crypto, cfg.Profiles)
		if err != nil {
			return nil, fmt.Errorf("%w: IMS offer crypto: %v", ErrSDPSecurityNegotiation, err)
		}
		if !ok {
			return nil, fmt.Errorf("%w: missing compatible IMS SDES crypto", ErrSDPSecurityNegotiation)
		}
		keys, err := srtpKeysFromSDPCryptoAttr(selectedAttr, imsParams)
		if err != nil {
			return nil, fmt.Errorf("%w: IMS offer crypto keys: %v", ErrSDPSecurityNegotiation, err)
		}
		profile = selProfile
		imsSendKeys = keys
		imsAnswerTag = strings.TrimSpace(selectedAttr.Tag)
		imsSessParams = firstVoiceNonEmpty(cfg.SessionParams, selectedAttr.SessionParams)
	} else {
		imsPlaintext = true
		profile = srtpRelayPreferredProfiles(cfg.Profiles)[0]
		imsAnswerTag = firstVoiceNonEmpty(cfg.CryptoTag, "1")
		imsSessParams = cfg.SessionParams
	}
	relayToIMSKeys, err := GenerateSRTPKeys(profile, cfg.Random)
	if err != nil {
		return nil, err
	}
	relayToClientKeys, err := GenerateSRTPKeys(profile, cfg.Random)
	if err != nil {
		return nil, err
	}
	relayToIMSKeys.SessionParams = imsSessParams
	relayToClientKeys.SessionParams = cfg.SessionParams
	offerTag := firstVoiceNonEmpty(cfg.CryptoTag, "1")
	clientOfferCrypto, err := buildSDESCryptoForKeys(offerTag, profile, relayToClientKeys, cfg.SessionParams)
	if err != nil {
		return nil, err
	}
	imsAnswerCrypto, err := buildSDESCryptoForKeys(firstVoiceNonEmpty(imsAnswerTag, offerTag), profile, relayToIMSKeys, imsSessParams)
	if err != nil {
		return nil, err
	}
	return &inboundSDESRelayNegotiation{
		cfg:               cfg,
		imsSDP:            imsSDP,
		imsSecurity:       imsSecurity,
		imsPlaintext:      imsPlaintext,
		clientPlaintext:   cfg.ClientPlaintext,
		profile:           profile,
		imsSendKeys:       imsSendKeys,
		relayToIMSKeys:    relayToIMSKeys,
		relayToClientKeys: relayToClientKeys,
		clientOfferCrypto: clientOfferCrypto,
		imsAnswerCrypto:   imsAnswerCrypto,
	}, nil
}

func (n *inboundSDESRelayNegotiation) ForceClientPlaintext() {
	if n == nil {
		return
	}
	n.mu.Lock()
	n.clientPlaintext = true
	n.mu.Unlock()
}

func (n *inboundSDESRelayNegotiation) IsClientPlaintext() bool {
	if n == nil {
		return true
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.clientPlaintext
}

func (n *inboundSDESRelayNegotiation) IsIMSPlaintext() bool {
	if n == nil {
		return true
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.imsPlaintext
}

func (n *outboundSDESRelayNegotiation) RewriteIMSOffer(body []byte) []byte {
	if n == nil {
		return append([]byte(nil), body...)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	security := withSDPTransportAttributes(SDPSecurityInfo{
		RTPProfile: secureSDPRTPProfile(n.clientSecurity.RTPProfile),
		Crypto:     []SDPCryptoAttribute{n.imsOfferCrypto},
	}, n.clientSecurity)
	return applySDPSecurity(body, security)
}

func (n *inboundSDESRelayNegotiation) RewriteClientOffer(body []byte) []byte {
	if n == nil {
		return append([]byte(nil), body...)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.clientPlaintext {
		return stripSDPSecurityToPlaintext(body, n.imsSecurity.RTPProfile)
	}
	security := withSDPTransportAttributes(SDPSecurityInfo{
		RTPProfile: secureSDPRTPProfile(n.imsSecurity.RTPProfile),
		Crypto:     []SDPCryptoAttribute{n.clientOfferCrypto},
	}, n.imsSecurity)
	return applySDPSecurity(body, security)
}

func (n *outboundSDESRelayNegotiation) RewriteClientAnswer(relay *RTPRelaySession, imsAnswer []byte, imsSDP SDPInfo) ([]byte, SDPInfo, error) {
	if n == nil {
		body := append([]byte(nil), imsAnswer...)
		info, err := ParseSDP(body)
		return body, info, err
	}
	if relay == nil {
		return nil, SDPInfo{}, fmt.Errorf("%w: RTP relay unavailable", ErrSDPSecurityNegotiation)
	}
	_, imsSecurity, err := ParseSDPWithSecurity(imsAnswer)
	if err != nil {
		return nil, SDPInfo{}, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.imsSDP = imsSDP
	imsWantsSecurity := len(imsSecurity.Crypto) > 0 || isSecureSDPRTPProfile(imsSecurity.RTPProfile)
	if !imsWantsSecurity {
		if n.established && !n.imsPlaintext {
			return nil, SDPInfo{}, fmt.Errorf("%w: missing compatible IMS SDES crypto", ErrSDPSecurityNegotiation)
		}
		n.imsPlaintext = true
		n.imsSendKeys = SRTPKeys{}
	} else {
		selectedAttr, _, imsParams, ok, err := SelectSDPCryptoAttribute(imsSecurity.Crypto, []SRTPProtectionProfile{n.profile})
		if err != nil {
			return nil, SDPInfo{}, fmt.Errorf("%w: IMS answer crypto: %v", ErrSDPSecurityNegotiation, err)
		}
		if !ok {
			return nil, SDPInfo{}, fmt.Errorf("%w: missing compatible IMS SDES crypto", ErrSDPSecurityNegotiation)
		}
		keys, err := srtpKeysFromSDPCryptoAttr(selectedAttr, imsParams)
		if err != nil {
			return nil, SDPInfo{}, fmt.Errorf("%w: IMS answer crypto keys: %v", ErrSDPSecurityNegotiation, err)
		}
		keysChanged := !n.established || n.imsPlaintext || !srtpKeysEqual(n.imsSendKeys, keys)
		n.imsPlaintext = false
		n.imsSendKeys = keys
		if !keysChanged {
			body := n.formatClientAnswerLocked(relay, imsAnswer, imsSecurity)
			info, err := ParseSDP(body)
			return body, info, err
		}
	}
	if err := n.installMediaTransformsLocked(relay, imsSDP); err != nil {
		return nil, SDPInfo{}, err
	}
	n.established = true
	body := n.formatClientAnswerLocked(relay, imsAnswer, imsSecurity)
	info, err := ParseSDP(body)
	if err != nil {
		return nil, SDPInfo{}, err
	}
	return body, info, nil
}

func (n *outboundSDESRelayNegotiation) formatClientAnswerLocked(relay *RTPRelaySession, imsAnswer []byte, imsSecurity SDPSecurityInfo) []byte {
	body := RewriteSDPMediaEndpoint(imsAnswer, relay.ClientEndpoint())
	if n.clientPlaintext {
		return stripSDPSecurityToPlaintext(body, n.clientSecurity.RTPProfile)
	}
	security := withSDPTransportAttributes(SDPSecurityInfo{
		RTPProfile: secureSDPRTPProfile(firstVoiceNonEmpty(imsSecurity.RTPProfile, n.clientSecurity.RTPProfile)),
		Crypto:     []SDPCryptoAttribute{n.clientCrypto},
	}, imsSecurity)
	return applySDPSecurity(body, security)
}

func (n *outboundSDESRelayNegotiation) installMediaTransformsLocked(relay *RTPRelaySession, imsSDP SDPInfo) error {
	if n.clientPlaintext && n.imsPlaintext {
		return relay.SetTransforms(RTPRelayTransforms{})
	}
	media, err := NewSRTPMediaSession(SRTPMediaConfig{
		Profile:               n.profile,
		ClientPlaintext:       n.clientPlaintext,
		IMSPlaintext:          n.imsPlaintext,
		ClientProtectKeys:     n.relayToClientKeys,
		ClientUnprotectKeys:   n.clientSendKeys,
		IMSProtectKeys:        n.relayToIMSKeys,
		IMSUnprotectKeys:      n.imsSendKeys,
		ReplayWindowSize:      n.cfg.ReplayWindowSize,
		RTCPFeedbackHandler:   relay.RTCPFeedbackHandler(),
		RTPDTMFHandler:        relay.RTPDTMFHandler(),
		RTPPlaintextHandler:   relay.RTPPlaintextHandler(),
		RTPPlaintextRewriter:  relay.RTPPlaintextRewriter(),
		ClientRTPDTMFPayloads: rtpDTMFPayloadTypesFromSDP(n.clientSDP),
		IMSRTPDTMFPayloads:    rtpDTMFPayloadTypesFromSDP(imsSDP),
	})
	if err != nil {
		return err
	}
	return relay.SetTransforms(media.RelayTransforms())
}

func (n *outboundSDESRelayNegotiation) RewriteIMSMidDialogOffer(relay *RTPRelaySession, rawOffer []byte) ([]byte, error) {
	if n == nil || len(rawOffer) == 0 {
		return append([]byte(nil), rawOffer...), nil
	}
	offerSDP, offerSec, err := ParseSDPWithSecurity(rawOffer)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.clientPlaintext && (len(offerSec.Crypto) > 0 || isSecureSDPRTPProfile(offerSec.RTPProfile)) {
		selectedAttr, _, params, ok, err := SelectSDPCryptoAttribute(offerSec.Crypto, []SRTPProtectionProfile{n.profile})
		if err != nil || !ok {
			return nil, fmt.Errorf("%w: mid-dialog client offer crypto", ErrSDPSecurityNegotiation)
		}
		keys, err := srtpKeysFromSDPCryptoAttr(selectedAttr, params)
		if err != nil {
			return nil, fmt.Errorf("%w: mid-dialog client offer crypto: %v", ErrSDPSecurityNegotiation, err)
		}
		n.clientSDP = offerSDP
		n.clientCrypto.Tag = strings.TrimSpace(selectedAttr.Tag)
		if !srtpKeysEqual(n.clientSendKeys, keys) {
			n.clientSendKeys = keys
			if relay != nil && n.established {
				_ = n.installMediaTransformsLocked(relay, n.imsSDP)
			}
		}
	}
	if n.imsPlaintext {
		return stripSDPSecurityToPlaintext(rawOffer, offerSec.RTPProfile), nil
	}
	security := withSDPTransportAttributes(SDPSecurityInfo{
		RTPProfile: secureSDPRTPProfile(firstVoiceNonEmpty(offerSec.RTPProfile, n.clientSecurity.RTPProfile)),
		Crypto:     []SDPCryptoAttribute{n.imsOfferCrypto},
	}, offerSec)
	return applySDPSecurity(rawOffer, security), nil
}

func (n *outboundSDESRelayNegotiation) RewriteIMSMidDialogAnswer(relay *RTPRelaySession, imsOffer []byte, baseAnswer []byte) ([]byte, error) {
	if n == nil {
		return append([]byte(nil), baseAnswer...), nil
	}
	imsSDP, imsSec, err := ParseSDPWithSecurity(imsOffer)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.imsSDP = imsSDP
	imsWantsSecurity := len(imsSec.Crypto) > 0 || isSecureSDPRTPProfile(imsSec.RTPProfile)
	if !n.imsPlaintext {
		if !imsWantsSecurity {
			return nil, fmt.Errorf("%w: missing compatible IMS SDES crypto in mid-dialog offer", ErrSDPSecurityNegotiation)
		}
		selectedAttr, _, imsParams, ok, err := SelectSDPCryptoAttribute(imsSec.Crypto, []SRTPProtectionProfile{n.profile})
		if err != nil || !ok {
			return nil, fmt.Errorf("%w: incompatible IMS SDES crypto in mid-dialog offer", ErrSDPSecurityNegotiation)
		}
		keys, err := srtpKeysFromSDPCryptoAttr(selectedAttr, imsParams)
		if err != nil {
			return nil, fmt.Errorf("%w: IMS mid-dialog offer crypto keys: %v", ErrSDPSecurityNegotiation, err)
		}
		n.imsOfferCrypto.Tag = strings.TrimSpace(selectedAttr.Tag)
		if !srtpKeysEqual(n.imsSendKeys, keys) {
			n.imsSendKeys = keys
			if relay != nil {
				if err := n.installMediaTransformsLocked(relay, imsSDP); err != nil {
					return nil, err
				}
			}
		}
		security := withSDPTransportAttributes(SDPSecurityInfo{
			RTPProfile: secureSDPRTPProfile(imsSec.RTPProfile),
			Crypto:     []SDPCryptoAttribute{n.imsOfferCrypto},
		}, imsSec)
		return applySDPSecurity(baseAnswer, security), nil
	}
	return stripSDPSecurityToPlaintext(baseAnswer, imsSec.RTPProfile), nil
}

func (n *inboundSDESRelayNegotiation) RewriteIMSAnswer(relay *RTPRelaySession, clientAnswer []byte, clientSDP SDPInfo) ([]byte, SDPInfo, error) {
	if n == nil {
		body := append([]byte(nil), clientAnswer...)
		info, err := ParseSDP(body)
		return body, info, err
	}
	if relay == nil {
		return nil, SDPInfo{}, fmt.Errorf("%w: RTP relay unavailable", ErrSDPSecurityNegotiation)
	}
	_, clientSecurity, err := ParseSDPWithSecurity(clientAnswer)
	if err != nil {
		return nil, SDPInfo{}, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	clientHasSecurity := len(clientSecurity.Crypto) > 0 || isSecureSDPRTPProfile(clientSecurity.RTPProfile)
	if n.clientPlaintext || !clientHasSecurity {
		if n.established && !n.clientPlaintext && !clientHasSecurity {
			return nil, SDPInfo{}, fmt.Errorf("%w: missing compatible client SDES crypto", ErrSDPSecurityNegotiation)
		}
		n.clientPlaintext = true
		n.clientSendKeys = SRTPKeys{}
	} else {
		selectedAttr, _, clientParams, ok, err := SelectSDPCryptoAttribute(clientSecurity.Crypto, []SRTPProtectionProfile{n.profile})
		if err != nil {
			return nil, SDPInfo{}, fmt.Errorf("%w: client answer crypto: %v", ErrSDPSecurityNegotiation, err)
		}
		if !ok {
			return nil, SDPInfo{}, fmt.Errorf("%w: missing compatible client SDES crypto", ErrSDPSecurityNegotiation)
		}
		keys, err := srtpKeysFromSDPCryptoAttr(selectedAttr, clientParams)
		if err != nil {
			return nil, SDPInfo{}, fmt.Errorf("%w: client answer crypto keys: %v", ErrSDPSecurityNegotiation, err)
		}
		keysChanged := !n.established || !srtpKeysEqual(n.clientSendKeys, keys)
		n.clientSendKeys = keys
		if !keysChanged {
			body := n.formatIMSAnswerLocked(relay, clientAnswer, clientSecurity)
			info, err := ParseSDP(body)
			return body, info, err
		}
	}
	if err := n.installMediaTransformsLocked(relay, clientSDP); err != nil {
		return nil, SDPInfo{}, err
	}
	n.established = true
	body := n.formatIMSAnswerLocked(relay, clientAnswer, clientSecurity)
	info, err := ParseSDP(body)
	if err != nil {
		return nil, SDPInfo{}, err
	}
	return body, info, nil
}

func (n *inboundSDESRelayNegotiation) formatIMSAnswerLocked(relay *RTPRelaySession, clientAnswer []byte, clientSecurity SDPSecurityInfo) []byte {
	body := RewriteSDPMediaEndpoint(clientAnswer, relay.IMSEndpoint())
	if n.imsPlaintext {
		return stripSDPSecurityToPlaintext(body, n.imsSecurity.RTPProfile)
	}
	security := withSDPTransportAttributes(SDPSecurityInfo{
		RTPProfile: secureSDPRTPProfile(firstVoiceNonEmpty(clientSecurity.RTPProfile, n.imsSecurity.RTPProfile)),
		Crypto:     []SDPCryptoAttribute{n.imsAnswerCrypto},
	}, clientSecurity)
	return applySDPSecurity(body, security)
}

func (n *inboundSDESRelayNegotiation) installMediaTransformsLocked(relay *RTPRelaySession, clientSDP SDPInfo) error {
	if n.clientPlaintext && n.imsPlaintext {
		return relay.SetTransforms(RTPRelayTransforms{})
	}
	media, err := NewSRTPMediaSession(SRTPMediaConfig{
		Profile:               n.profile,
		ClientPlaintext:       n.clientPlaintext,
		IMSPlaintext:          n.imsPlaintext,
		ClientProtectKeys:     n.relayToClientKeys,
		ClientUnprotectKeys:   n.clientSendKeys,
		IMSProtectKeys:        n.relayToIMSKeys,
		IMSUnprotectKeys:      n.imsSendKeys,
		ReplayWindowSize:      n.cfg.ReplayWindowSize,
		RTCPFeedbackHandler:   relay.RTCPFeedbackHandler(),
		RTPDTMFHandler:        relay.RTPDTMFHandler(),
		RTPPlaintextHandler:   relay.RTPPlaintextHandler(),
		RTPPlaintextRewriter:  relay.RTPPlaintextRewriter(),
		ClientRTPDTMFPayloads: rtpDTMFPayloadTypesFromSDP(clientSDP),
		IMSRTPDTMFPayloads:    rtpDTMFPayloadTypesFromSDP(n.imsSDP),
	})
	if err != nil {
		return err
	}
	return relay.SetTransforms(media.RelayTransforms())
}

func (n *inboundSDESRelayNegotiation) PrepareIMSMidDialogOffer(imsOffer []byte) (*inboundSDESRelayNegotiation, error) {
	if n == nil {
		return nil, nil
	}
	imsSDP, imsSec, err := ParseSDPWithSecurity(imsOffer)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	imsWantsSecurity := len(imsSec.Crypto) > 0 || isSecureSDPRTPProfile(imsSec.RTPProfile)
	if !n.imsPlaintext && !imsWantsSecurity {
		return nil, fmt.Errorf("%w: missing compatible IMS SDES crypto", ErrSDPSecurityNegotiation)
	}
	cfg := n.cfg
	cfg.ClientPlaintext = n.clientPlaintext
	next, err := newInboundSDESRelayNegotiation(imsOffer, cfg)
	if err != nil {
		return nil, err
	}
	// Preserve existing keys when peer did not rotate key material (RFC 4568 §6.1.3).
	if !n.imsPlaintext && srtpKeysEqual(next.imsSendKeys, n.imsSendKeys) {
		next.relayToIMSKeys = n.relayToIMSKeys
		next.imsAnswerCrypto.KeyParams = n.imsAnswerCrypto.KeyParams
	}
	if !n.clientPlaintext {
		next.clientSendKeys = n.clientSendKeys
		next.relayToClientKeys = n.relayToClientKeys
		next.clientOfferCrypto = n.clientOfferCrypto
	}
	next.imsSDP = imsSDP
	next.established = n.established
	return next, nil
}

func (n *inboundSDESRelayNegotiation) RewriteIMSMidDialogOfferFromClient(relay *RTPRelaySession, rawClientOffer []byte) ([]byte, error) {
	if n == nil || len(rawClientOffer) == 0 {
		return append([]byte(nil), rawClientOffer...), nil
	}
	clientSDP, clientSec, err := ParseSDPWithSecurity(rawClientOffer)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	clientHasSec := len(clientSec.Crypto) > 0 || isSecureSDPRTPProfile(clientSec.RTPProfile)
	if !n.clientPlaintext && clientHasSec {
		selectedAttr, _, params, ok, err := SelectSDPCryptoAttribute(clientSec.Crypto, []SRTPProtectionProfile{n.profile})
		if err != nil || !ok {
			return nil, fmt.Errorf("%w: mid-dialog client offer crypto", ErrSDPSecurityNegotiation)
		}
		keys, err := srtpKeysFromSDPCryptoAttr(selectedAttr, params)
		if err != nil {
			return nil, fmt.Errorf("%w: mid-dialog client offer crypto: %v", ErrSDPSecurityNegotiation, err)
		}
		n.clientOfferCrypto.Tag = strings.TrimSpace(selectedAttr.Tag)
		if !srtpKeysEqual(n.clientSendKeys, keys) {
			n.clientSendKeys = keys
			if relay != nil && n.established {
				_ = n.installMediaTransformsLocked(relay, clientSDP)
			}
		}
	}
	if n.imsPlaintext {
		return stripSDPSecurityToPlaintext(rawClientOffer, clientSec.RTPProfile), nil
	}
	security := withSDPTransportAttributes(SDPSecurityInfo{
		RTPProfile: secureSDPRTPProfile(firstVoiceNonEmpty(clientSec.RTPProfile, n.imsSecurity.RTPProfile)),
		Crypto:     []SDPCryptoAttribute{n.imsAnswerCrypto},
	}, clientSec)
	return applySDPSecurity(rawClientOffer, security), nil
}

func (n *inboundSDESRelayNegotiation) RewriteClientMidDialogAnswerFromIMS(relay *RTPRelaySession, imsAnswer []byte, clientSDP SDPInfo) ([]byte, SDPInfo, error) {
	if n == nil {
		body := append([]byte(nil), imsAnswer...)
		info, err := ParseSDP(body)
		return body, info, err
	}
	imsSDP, imsSec, err := ParseSDPWithSecurity(imsAnswer)
	if err != nil {
		return nil, SDPInfo{}, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	imsHasSec := len(imsSec.Crypto) > 0 || isSecureSDPRTPProfile(imsSec.RTPProfile)
	if !n.imsPlaintext {
		if !imsHasSec {
			return nil, SDPInfo{}, fmt.Errorf("%w: missing compatible IMS SDES crypto", ErrSDPSecurityNegotiation)
		}
		selectedAttr, _, params, ok, err := SelectSDPCryptoAttribute(imsSec.Crypto, []SRTPProtectionProfile{n.profile})
		if err != nil || !ok {
			return nil, SDPInfo{}, fmt.Errorf("%w: IMS answer crypto", ErrSDPSecurityNegotiation)
		}
		keys, err := srtpKeysFromSDPCryptoAttr(selectedAttr, params)
		if err != nil {
			return nil, SDPInfo{}, fmt.Errorf("%w: IMS answer crypto keys: %v", ErrSDPSecurityNegotiation, err)
		}
		n.imsSDP = imsSDP
		if !srtpKeysEqual(n.imsSendKeys, keys) {
			n.imsSendKeys = keys
			if relay != nil {
				if err := n.installMediaTransformsLocked(relay, clientSDP); err != nil {
					return nil, SDPInfo{}, err
				}
			}
		}
	}
	body := RewriteSDPMediaEndpoint(imsAnswer, relay.ClientEndpoint())
	if n.clientPlaintext {
		body = stripSDPSecurityToPlaintext(body, imsSec.RTPProfile)
	} else {
		security := withSDPTransportAttributes(SDPSecurityInfo{
			RTPProfile: secureSDPRTPProfile(imsSec.RTPProfile),
			Crypto:     []SDPCryptoAttribute{n.clientOfferCrypto},
		}, imsSec)
		body = applySDPSecurity(body, security)
	}
	info, err := ParseSDP(body)
	if err != nil {
		return nil, SDPInfo{}, err
	}
	return body, info, nil
}

func srtpRelayPreferredProfiles(configured []SRTPProtectionProfile) []SRTPProtectionProfile {
	if len(configured) > 0 {
		return append([]SRTPProtectionProfile(nil), configured...)
	}
	return []SRTPProtectionProfile{
		SRTPProfileAes128CmHmacSha1_80,
		SRTPProfileAes128CmHmacSha1_32,
		SRTPProfileAes256CmHmacSha1_80,
		SRTPProfileAes256CmHmacSha1_32,
		SRTPProfileAeadAes128Gcm,
		SRTPProfileAeadAes256Gcm,
	}
}

func buildSDESCryptoForKeys(tag string, profile SRTPProtectionProfile, keys SRTPKeys, sessionParams string) (SDPCryptoAttribute, error) {
	return BuildSDPCryptoAttribute(tag, profile, SDPCryptoInlineKeyParams{
		MasterKey:  append([]byte(nil), keys.MasterKey...),
		MasterSalt: append([]byte(nil), keys.MasterSalt...),
	}, sessionParams)
}

func srtpKeysFromSDPCryptoParams(params SDPCryptoInlineKeyParams) SRTPKeys {
	mki, _ := EncodeSDPCryptoMKI(params.MKIValue, params.MKILength)
	return SRTPKeys{
		MasterKey:  append([]byte(nil), params.MasterKey...),
		MasterSalt: append([]byte(nil), params.MasterSalt...),
		MKI:        mki,
	}
}

func srtpKeysFromSDPCryptoAttr(attr SDPCryptoAttribute, params SDPCryptoInlineKeyParams) (SRTPKeys, error) {
	mki, err := EncodeSDPCryptoMKI(params.MKIValue, params.MKILength)
	if err != nil {
		return SRTPKeys{}, err
	}
	return SRTPKeys{
		MasterKey:     append([]byte(nil), params.MasterKey...),
		MasterSalt:    append([]byte(nil), params.MasterSalt...),
		MKI:           mki,
		SessionParams: strings.TrimSpace(attr.SessionParams),
	}, nil
}

func srtpKeysEqual(a, b SRTPKeys) bool {
	return bytes.Equal(a.MasterKey, b.MasterKey) &&
		bytes.Equal(a.MasterSalt, b.MasterSalt) &&
		bytes.Equal(a.MKI, b.MKI) &&
		strings.EqualFold(strings.TrimSpace(a.SessionParams), strings.TrimSpace(b.SessionParams))
}

func isSecureSDPRTPProfile(profile string) bool {
	switch strings.ToUpper(strings.TrimSpace(profile)) {
	case "RTP/SAVP", "RTP/SAVPF", "UDP/TLS/RTP/SAVP", "UDP/TLS/RTP/SAVPF":
		return true
	default:
		return false
	}
}

func plainSDPRTPProfile(profile string) string {
	switch strings.ToUpper(strings.TrimSpace(profile)) {
	case "RTP/SAVPF", "RTP/AVPF", "UDP/TLS/RTP/SAVPF":
		return "RTP/AVPF"
	default:
		return "RTP/AVP"
	}
}

func stripSDPSecurityToPlaintext(body []byte, fallbackProfile string) []byte {
	lines := sdpSecurityLines(body)
	out := make([]string, 0, len(lines))
	inAudio := false
	rewroteAudio := false
	for _, line := range lines {
		if line == "" {
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "m=") {
			inAudio = false
			fields := strings.Fields(line)
			if !rewroteAudio && len(fields) >= 3 && strings.EqualFold(fields[0], "m=audio") {
				inAudio = true
				rewroteAudio = true
				fields[2] = plainSDPRTPProfile(firstVoiceNonEmpty(fields[2], fallbackProfile))
				line = strings.Join(fields, " ")
			}
			out = append(out, line)
			continue
		}
		if (!rewroteAudio || inAudio) && (strings.HasPrefix(lower, "a=crypto:") || strings.HasPrefix(lower, "a=fingerprint:") || strings.HasPrefix(lower, "a=setup:")) {
			continue
		}
		out = append(out, line)
	}
	return []byte(strings.Join(out, "\r\n") + "\r\n")
}

func secureSDPRTPProfile(profile string) string {
	switch strings.ToUpper(strings.TrimSpace(profile)) {
	case "RTP/SAVPF":
		return "RTP/SAVPF"
	case "RTP/SAVP":
		return "RTP/SAVP"
	case "RTP/AVPF":
		return "RTP/SAVPF"
	default:
		return "RTP/SAVP"
	}
}
