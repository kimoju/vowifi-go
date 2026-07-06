package voicehost

import (
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidSDPSecurity = errors.New("invalid SDP security")

var ErrSDPSecurityNegotiation = errors.New("SDP security negotiation failed")

type SDPCryptoAttribute struct {
	Tag           string
	Suite         string
	KeyParams     string
	SessionParams string
}

type SDPFingerprintAttribute struct {
	HashFunc    string
	Fingerprint string
}

type SDPSecurityInfo struct {
	RTPProfile   string
	Crypto       []SDPCryptoAttribute
	Fingerprints []SDPFingerprintAttribute
	Setup        string
}

type SDPSecurityAnswerOptions struct {
	RTPProfiles  []string
	Crypto       []SDPCryptoAttribute
	Fingerprints []SDPFingerprintAttribute
	Setup        string
	PreferCrypto bool
}

func ParseSDPWithSecurity(body []byte) (SDPInfo, SDPSecurityInfo, error) {
	info, err := ParseSDP(body)
	if err != nil {
		return SDPInfo{}, SDPSecurityInfo{}, err
	}
	security, err := ParseSDPSecurity(body)
	if err != nil {
		return SDPInfo{}, SDPSecurityInfo{}, err
	}
	return info, security, nil
}

func ParseSDPSecurity(body []byte) (SDPSecurityInfo, error) {
	lines := sdpSecurityLines(body)
	var session SDPSecurityInfo
	var out SDPSecurityInfo
	beforeFirstMedia := true
	inAudio := false
	sawAudio := false
	for _, line := range lines {
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "m=") {
			if inAudio {
				break
			}
			beforeFirstMedia = false
			inAudio = false
			fields := strings.Fields(line)
			if len(fields) >= 1 && strings.EqualFold(fields[0], "m=audio") {
				if len(fields) < 3 {
					return SDPSecurityInfo{}, fmt.Errorf("%w: missing audio RTP profile", ErrInvalidSDPSecurity)
				}
				out.RTPProfile = fields[2]
				inAudio = true
				sawAudio = true
			}
			continue
		}
		switch {
		case beforeFirstMedia:
			if fingerprint, ok, err := parseSDPFingerprintLine(line); ok || err != nil {
				if err != nil {
					return SDPSecurityInfo{}, err
				}
				session.Fingerprints = append(session.Fingerprints, fingerprint)
				continue
			}
			if setup, ok, err := parseSDPSetupLine(line); ok || err != nil {
				if err != nil {
					return SDPSecurityInfo{}, err
				}
				session.Setup = setup
			}
		case inAudio:
			if crypto, ok, err := parseSDPCryptoLine(line); ok || err != nil {
				if err != nil {
					return SDPSecurityInfo{}, err
				}
				out.Crypto = append(out.Crypto, crypto)
				continue
			}
			if fingerprint, ok, err := parseSDPFingerprintLine(line); ok || err != nil {
				if err != nil {
					return SDPSecurityInfo{}, err
				}
				out.Fingerprints = append(out.Fingerprints, fingerprint)
				continue
			}
			if setup, ok, err := parseSDPSetupLine(line); ok || err != nil {
				if err != nil {
					return SDPSecurityInfo{}, err
				}
				out.Setup = setup
			}
		}
	}
	if !sawAudio {
		return SDPSecurityInfo{}, fmt.Errorf("%w: missing SDP audio media", ErrInvalidSDPSecurity)
	}
	if len(out.Fingerprints) == 0 {
		out.Fingerprints = session.Fingerprints
	}
	if strings.TrimSpace(out.Setup) == "" {
		out.Setup = session.Setup
	}
	return out, nil
}

func SelectSDPSecurityAnswer(offer SDPSecurityInfo, options SDPSecurityAnswerOptions) (SDPSecurityInfo, error) {
	profile, ok := selectSDPRTPProfile(offer.RTPProfile, options.RTPProfiles)
	if !ok {
		return SDPSecurityInfo{}, fmt.Errorf("%w: unsupported RTP profile %q", ErrSDPSecurityNegotiation, offer.RTPProfile)
	}
	if !options.PreferCrypto {
		if answer, ok, err := selectSDPFingerprintAnswer(offer, options, profile); ok || err != nil {
			return answer, err
		}
	}
	if answer, ok := selectSDPCryptoAnswer(offer, options, profile); ok {
		return answer, nil
	}
	if options.PreferCrypto {
		if answer, ok, err := selectSDPFingerprintAnswer(offer, options, profile); ok || err != nil {
			return answer, err
		}
	}
	if offer.HasSecurityAttributes() {
		return SDPSecurityInfo{}, fmt.Errorf("%w: no compatible SDP security attributes", ErrSDPSecurityNegotiation)
	}
	return SDPSecurityInfo{RTPProfile: profile}, nil
}

func BuildSDPAnswerWithSecurity(info SDPInfo, security SDPSecurityInfo) []byte {
	base := BuildSDPAnswer(info)
	if security.IsZero() {
		return base
	}
	return applySDPSecurity(base, security)
}

func (s SDPSecurityInfo) IsZero() bool {
	return strings.TrimSpace(s.RTPProfile) == "" &&
		len(s.Crypto) == 0 &&
		len(s.Fingerprints) == 0 &&
		strings.TrimSpace(s.Setup) == ""
}

func (s SDPSecurityInfo) HasSecurityAttributes() bool {
	return len(s.Crypto) > 0 || len(s.Fingerprints) > 0 || strings.TrimSpace(s.Setup) != ""
}

func (a SDPCryptoAttribute) SDPValue() string {
	parts := []string{strings.TrimSpace(a.Tag), strings.TrimSpace(a.Suite), strings.TrimSpace(a.KeyParams)}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return ""
	}
	value := strings.Join(parts, " ")
	if session := strings.TrimSpace(a.SessionParams); session != "" {
		value += " " + session
	}
	return value
}

func (a SDPFingerprintAttribute) SDPValue() string {
	hashFunc := strings.TrimSpace(a.HashFunc)
	fingerprint := strings.TrimSpace(a.Fingerprint)
	if hashFunc == "" || fingerprint == "" {
		return ""
	}
	return hashFunc + " " + fingerprint
}

func applySDPSecurity(body []byte, security SDPSecurityInfo) []byte {
	lines := sdpSecurityLines(body)
	attrs := security.sdpAttributeLines()
	profile := strings.TrimSpace(security.RTPProfile)
	out := make([]string, 0, len(lines)+len(attrs))
	inserted := false
	for _, line := range lines {
		if line == "" {
			continue
		}
		if !inserted && strings.HasPrefix(strings.ToLower(line), "m=audio ") {
			fields := strings.Fields(line)
			if profile != "" && len(fields) >= 3 {
				fields[2] = profile
				line = strings.Join(fields, " ")
			}
			out = append(out, line)
			out = append(out, attrs...)
			inserted = true
			continue
		}
		out = append(out, line)
	}
	if !inserted {
		out = append(out, attrs...)
	}
	return []byte(strings.Join(out, "\r\n") + "\r\n")
}

func (s SDPSecurityInfo) sdpAttributeLines() []string {
	out := make([]string, 0, len(s.Crypto)+len(s.Fingerprints)+1)
	for _, crypto := range s.Crypto {
		if value := crypto.SDPValue(); value != "" {
			out = append(out, "a=crypto:"+value)
		}
	}
	for _, fingerprint := range s.Fingerprints {
		if value := fingerprint.SDPValue(); value != "" {
			out = append(out, "a=fingerprint:"+value)
		}
	}
	if setup := strings.TrimSpace(s.Setup); setup != "" {
		out = append(out, "a=setup:"+setup)
	}
	return out
}

func parseSDPCryptoLine(line string) (SDPCryptoAttribute, bool, error) {
	value, ok := cutSDPAttributeValue(line, "a=crypto:")
	if !ok {
		return SDPCryptoAttribute{}, false, nil
	}
	tag, rest, ok := cutSDPField(value)
	if !ok {
		return SDPCryptoAttribute{}, true, fmt.Errorf("%w: malformed crypto attribute", ErrInvalidSDPSecurity)
	}
	suite, rest, ok := cutSDPField(rest)
	if !ok {
		return SDPCryptoAttribute{}, true, fmt.Errorf("%w: malformed crypto attribute", ErrInvalidSDPSecurity)
	}
	keyParams, sessionParams, ok := cutSDPField(rest)
	if !ok {
		return SDPCryptoAttribute{}, true, fmt.Errorf("%w: malformed crypto attribute", ErrInvalidSDPSecurity)
	}
	return SDPCryptoAttribute{
		Tag:           tag,
		Suite:         suite,
		KeyParams:     keyParams,
		SessionParams: strings.TrimSpace(sessionParams),
	}, true, nil
}

func parseSDPFingerprintLine(line string) (SDPFingerprintAttribute, bool, error) {
	value, ok := cutSDPAttributeValue(line, "a=fingerprint:")
	if !ok {
		return SDPFingerprintAttribute{}, false, nil
	}
	hashFunc, fingerprint, ok := cutSDPField(value)
	if !ok || strings.TrimSpace(fingerprint) == "" {
		return SDPFingerprintAttribute{}, true, fmt.Errorf("%w: malformed fingerprint attribute", ErrInvalidSDPSecurity)
	}
	return SDPFingerprintAttribute{HashFunc: hashFunc, Fingerprint: strings.TrimSpace(fingerprint)}, true, nil
}

func parseSDPSetupLine(line string) (string, bool, error) {
	value, ok := cutSDPAttributeValue(line, "a=setup:")
	if !ok {
		return "", false, nil
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", true, fmt.Errorf("%w: malformed setup attribute", ErrInvalidSDPSecurity)
	}
	return value, true, nil
}

func cutSDPAttributeValue(line, prefix string) (string, bool) {
	if len(line) < len(prefix) || !strings.EqualFold(line[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(line[len(prefix):]), true
}

func cutSDPField(value string) (string, string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", false
	}
	for i, r := range value {
		if r == ' ' || r == '\t' {
			return value[:i], strings.TrimSpace(value[i+1:]), true
		}
	}
	return value, "", true
}

func sdpSecurityLines(body []byte) []string {
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	raw := strings.Split(text, "\n")
	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		lines = append(lines, strings.TrimSpace(line))
	}
	return lines
}

func selectSDPRTPProfile(offerProfile string, allowed []string) (string, bool) {
	offerProfile = strings.TrimSpace(offerProfile)
	if offerProfile == "" {
		offerProfile = "RTP/AVP"
	}
	if len(allowed) == 0 {
		return offerProfile, true
	}
	for _, profile := range allowed {
		profile = strings.TrimSpace(profile)
		if profile == "" {
			continue
		}
		if strings.EqualFold(profile, offerProfile) {
			return offerProfile, true
		}
	}
	return "", false
}

func selectSDPFingerprintAnswer(offer SDPSecurityInfo, options SDPSecurityAnswerOptions, profile string) (SDPSecurityInfo, bool, error) {
	if len(offer.Fingerprints) == 0 || len(options.Fingerprints) == 0 {
		return SDPSecurityInfo{}, false, nil
	}
	for _, local := range options.Fingerprints {
		for _, remote := range offer.Fingerprints {
			if !strings.EqualFold(strings.TrimSpace(local.HashFunc), strings.TrimSpace(remote.HashFunc)) {
				continue
			}
			setup, err := SelectSDPSetupAnswer(offer.Setup, options.Setup)
			if err != nil {
				return SDPSecurityInfo{}, true, err
			}
			local.HashFunc = strings.TrimSpace(local.HashFunc)
			local.Fingerprint = strings.TrimSpace(local.Fingerprint)
			if local.SDPValue() == "" {
				continue
			}
			return SDPSecurityInfo{
				RTPProfile:   profile,
				Fingerprints: []SDPFingerprintAttribute{local},
				Setup:        setup,
			}, true, nil
		}
	}
	return SDPSecurityInfo{}, false, nil
}

func selectSDPCryptoAnswer(offer SDPSecurityInfo, options SDPSecurityAnswerOptions, profile string) (SDPSecurityInfo, bool) {
	if len(offer.Crypto) == 0 || len(options.Crypto) == 0 {
		return SDPSecurityInfo{}, false
	}
	for _, local := range options.Crypto {
		for _, remote := range offer.Crypto {
			if !strings.EqualFold(strings.TrimSpace(local.Suite), strings.TrimSpace(remote.Suite)) {
				continue
			}
			answer := local
			answer.Tag = strings.TrimSpace(remote.Tag)
			answer.Suite = strings.TrimSpace(local.Suite)
			answer.KeyParams = strings.TrimSpace(local.KeyParams)
			answer.SessionParams = strings.TrimSpace(local.SessionParams)
			if answer.SDPValue() == "" {
				continue
			}
			return SDPSecurityInfo{
				RTPProfile: profile,
				Crypto:     []SDPCryptoAttribute{answer},
			}, true
		}
	}
	return SDPSecurityInfo{}, false
}

func SelectSDPSetupAnswer(offerSetup, preferred string) (string, error) {
	offerSetup = strings.ToLower(strings.TrimSpace(offerSetup))
	preferred = strings.ToLower(strings.TrimSpace(preferred))
	if offerSetup == "" {
		offerSetup = "actpass"
	}
	switch offerSetup {
	case "actpass":
		if preferred == "" {
			return "active", nil
		}
		if preferred == "active" || preferred == "passive" {
			return preferred, nil
		}
	case "active":
		if preferred == "" || preferred == "passive" {
			return "passive", nil
		}
	case "passive":
		if preferred == "" || preferred == "active" {
			return "active", nil
		}
	case "holdconn":
		if preferred == "" || preferred == "holdconn" {
			return "holdconn", nil
		}
	default:
		return "", fmt.Errorf("%w: unsupported setup role %q", ErrSDPSecurityNegotiation, offerSetup)
	}
	return "", fmt.Errorf("%w: setup role %q cannot answer offer role %q", ErrSDPSecurityNegotiation, preferred, offerSetup)
}
