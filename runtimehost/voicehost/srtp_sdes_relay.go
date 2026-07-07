package voicehost

import (
	"fmt"
	"io"
	"strings"
)

type RTPRelaySRTPConfig struct {
	Profiles         []SRTPProtectionProfile
	CryptoTag        string
	SessionParams    string
	ReplayWindowSize uint
	Random           io.Reader
}

type outboundSDESRelayNegotiation struct {
	cfg               RTPRelaySRTPConfig
	clientSDP         SDPInfo
	clientSecurity    SDPSecurityInfo
	profile           SRTPProtectionProfile
	clientSendKeys    SRTPKeys
	relayToIMSKeys    SRTPKeys
	relayToClientKeys SRTPKeys
	imsOfferCrypto    SDPCryptoAttribute
	clientCrypto      SDPCryptoAttribute
}

func newOutboundSDESRelayNegotiation(clientOffer []byte, cfg RTPRelaySRTPConfig) (*outboundSDESRelayNegotiation, error) {
	clientSDP, clientSecurity, err := ParseSDPWithSecurity(clientOffer)
	if err != nil {
		return nil, err
	}
	_, profile, clientParams, ok, err := SelectSDPCryptoAttribute(clientSecurity.Crypto, srtpRelayPreferredProfiles(cfg.Profiles))
	if err != nil {
		return nil, fmt.Errorf("%w: client offer crypto: %v", ErrSDPSecurityNegotiation, err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: missing compatible client SDES crypto", ErrSDPSecurityNegotiation)
	}
	relayToIMSKeys, err := GenerateSRTPKeys(profile, cfg.Random)
	if err != nil {
		return nil, err
	}
	relayToClientKeys, err := GenerateSRTPKeys(profile, cfg.Random)
	if err != nil {
		return nil, err
	}
	tag := firstVoiceNonEmpty(cfg.CryptoTag, "1")
	imsOfferCrypto, err := buildSDESCryptoForKeys(tag, profile, relayToIMSKeys, cfg.SessionParams)
	if err != nil {
		return nil, err
	}
	clientCrypto, err := buildSDESCryptoForKeys(tag, profile, relayToClientKeys, cfg.SessionParams)
	if err != nil {
		return nil, err
	}
	return &outboundSDESRelayNegotiation{
		cfg:               cfg,
		clientSDP:         clientSDP,
		clientSecurity:    clientSecurity,
		profile:           profile,
		clientSendKeys:    srtpKeysFromSDPCryptoParams(clientParams),
		relayToIMSKeys:    relayToIMSKeys,
		relayToClientKeys: relayToClientKeys,
		imsOfferCrypto:    imsOfferCrypto,
		clientCrypto:      clientCrypto,
	}, nil
}

func (n *outboundSDESRelayNegotiation) RewriteIMSOffer(body []byte) []byte {
	if n == nil {
		return append([]byte(nil), body...)
	}
	security := withSDPTransportAttributes(SDPSecurityInfo{
		RTPProfile: secureSDPRTPProfile(n.clientSecurity.RTPProfile),
		Crypto:     []SDPCryptoAttribute{n.imsOfferCrypto},
	}, n.clientSecurity)
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
	_, _, imsParams, ok, err := SelectSDPCryptoAttribute(imsSecurity.Crypto, []SRTPProtectionProfile{n.profile})
	if err != nil {
		return nil, SDPInfo{}, fmt.Errorf("%w: IMS answer crypto: %v", ErrSDPSecurityNegotiation, err)
	}
	if !ok {
		return nil, SDPInfo{}, fmt.Errorf("%w: missing compatible IMS SDES crypto", ErrSDPSecurityNegotiation)
	}
	media, err := NewSRTPMediaSession(SRTPMediaConfig{
		Profile:               n.profile,
		ClientProtectKeys:     n.relayToClientKeys,
		ClientUnprotectKeys:   n.clientSendKeys,
		IMSProtectKeys:        n.relayToIMSKeys,
		IMSUnprotectKeys:      srtpKeysFromSDPCryptoParams(imsParams),
		ReplayWindowSize:      n.cfg.ReplayWindowSize,
		RTCPFeedbackHandler:   relay.rtcpFeedbackHandler,
		RTPDTMFHandler:        relay.rtpDTMFHandler,
		RTPPlaintextHandler:   relay.RTPPlaintextHandler(),
		ClientRTPDTMFPayloads: rtpDTMFPayloadTypesFromSDP(n.clientSDP),
		IMSRTPDTMFPayloads:    rtpDTMFPayloadTypesFromSDP(imsSDP),
	})
	if err != nil {
		return nil, SDPInfo{}, err
	}
	if err := relay.SetTransforms(media.RelayTransforms()); err != nil {
		return nil, SDPInfo{}, err
	}
	body := RewriteSDPMediaEndpoint(imsAnswer, relay.ClientEndpoint())
	security := withSDPTransportAttributes(SDPSecurityInfo{
		RTPProfile: secureSDPRTPProfile(firstVoiceNonEmpty(imsSecurity.RTPProfile, n.clientSecurity.RTPProfile)),
		Crypto:     []SDPCryptoAttribute{n.clientCrypto},
	}, imsSecurity)
	body = applySDPSecurity(body, security)
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
	return SRTPKeys{
		MasterKey:  append([]byte(nil), params.MasterKey...),
		MasterSalt: append([]byte(nil), params.MasterSalt...),
	}
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
