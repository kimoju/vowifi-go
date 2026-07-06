package carrier

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

type E911Config struct {
	Enabled             bool   `json:"enabled"`
	Provider            string `json:"provider"`
	Websheet            string `json:"websheet"`
	EntitlementEndpoint string `json:"entitlement_endpoint"`
}

type NetworkConfig struct {
	IMSRealm string `json:"ims_realm"`
	NAIRealm string `json:"nai_realm"`
	EPDGFQDN string `json:"epdg_fqdn"`
}

type SubscriberProfileInput struct {
	IMSI string
	MCC  string
	MNC  string
}

type SubscriberProfile struct {
	IMSI               string
	MCC                string
	MNC                string
	PresetID           string
	Network            NetworkConfig
	IMSPrivateIdentity string
	IMSPublicIdentity  string
	PermanentNAI       string
}

type EffectiveCarrierConfig struct {
	MCC      string        `json:"mcc"`
	MNC      string        `json:"mnc"`
	PresetID string        `json:"preset_id"`
	E911     E911Config    `json:"e911"`
	Network  NetworkConfig `json:"network"`
}

type EffectiveCarrierConfigInput struct {
	IMSI string
	MCC  string
	MNC  string
}

type LoadResult struct {
	Path    string
	Missing bool
	Count   int
}

var (
	overridesMu sync.RWMutex
	overrides   = map[string]EffectiveCarrierConfig{}
)

var builtinCarriers = map[string]EffectiveCarrierConfig{
	"310280": {
		MCC:      "310",
		MNC:      "280",
		PresetID: "310280",
		E911: E911Config{
			Enabled:             true,
			Provider:            "att-ts43",
			Websheet:            "https://www.att.com/acctmgmt/wireless/e911",
			EntitlementEndpoint: "https://sentitlement2.mobile.att.net/WFC",
		},
	},
	"310410": {
		MCC:      "310",
		MNC:      "410",
		PresetID: "310410",
		E911: E911Config{
			Enabled:             true,
			Provider:            "att-ts43",
			Websheet:            "https://www.att.com/acctmgmt/wireless/e911",
			EntitlementEndpoint: "https://sentitlement2.mobile.att.net/WFC",
		},
	},
}

func LoadCarrierOverrides(path string) (LoadResult, error) {
	path = strings.TrimSpace(path)
	result := LoadResult{Path: path, Missing: true}
	if path == "" {
		return result, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return result, nil
		}
		return result, err
	}
	var decoded map[string]EffectiveCarrierConfig
	if err := json.Unmarshal(raw, &decoded); err != nil {
		var list []EffectiveCarrierConfig
		if err2 := json.Unmarshal(raw, &list); err2 != nil {
			return result, err
		}
		decoded = make(map[string]EffectiveCarrierConfig, len(list))
		for _, cfg := range list {
			if key := presetKey(cfg.MCC, cfg.MNC); key != "" {
				decoded[key] = normalizeConfig(cfg)
			}
		}
	}
	next := make(map[string]EffectiveCarrierConfig, len(decoded))
	for key, cfg := range decoded {
		cfg = normalizeConfig(cfg)
		if cfg.MCC == "" || cfg.MNC == "" {
			cfg.MCC, cfg.MNC = splitPresetKey(key)
			cfg = normalizeConfig(cfg)
		}
		if cfg.PresetID != "" {
			key = cfg.PresetID
		}
		key = strings.TrimSpace(key)
		if key != "" {
			next[key] = cfg
		}
	}
	overridesMu.Lock()
	overrides = next
	overridesMu.Unlock()
	result.Missing = false
	result.Count = len(next)
	return result, nil
}

func ClearCarrierOverrides() {
	overridesMu.Lock()
	overrides = map[string]EffectiveCarrierConfig{}
	overridesMu.Unlock()
}

func ResolveEffectiveCarrierConfig(in EffectiveCarrierConfigInput) EffectiveCarrierConfig {
	profile := NormalizeSubscriberProfile(SubscriberProfileInput{
		IMSI: in.IMSI,
		MCC:  in.MCC,
		MNC:  in.MNC,
	})
	mcc := profile.MCC
	mnc := profile.MNC
	key := presetKey(mcc, mnc)
	overridesMu.RLock()
	if cfg, ok := overrides[key]; ok {
		overridesMu.RUnlock()
		return normalizeConfig(cfg)
	}
	overridesMu.RUnlock()
	if cfg, ok := builtinCarriers[key]; ok {
		return normalizeConfig(cfg)
	}
	return normalizeConfig(EffectiveCarrierConfig{
		MCC:      mcc,
		MNC:      mnc,
		PresetID: mcc + mnc,
		E911: E911Config{
			Enabled:  false,
			Provider: "",
		},
	})
}

func NormalizeSubscriberProfile(in SubscriberProfileInput) SubscriberProfile {
	imsi := strings.TrimSpace(in.IMSI)
	mcc := normalizeMCC(in.MCC)
	mnc := normalizeMNC(in.MNC)
	if mcc == "" && len(imsi) >= 3 {
		mcc = normalizeMCC(imsi[:3])
	}
	if mnc == "" {
		switch {
		case len(imsi) >= 6:
			mnc = normalizeMNC(imsi[3:6])
		case len(imsi) >= 5:
			mnc = normalizeMNC(imsi[3:5])
		}
	}
	network := normalizeNetworkConfig(mcc, mnc, NetworkConfig{})
	return SubscriberProfile{
		IMSI:               imsi,
		MCC:                mcc,
		MNC:                mnc,
		PresetID:           presetKey(mcc, mnc),
		Network:            network,
		IMSPrivateIdentity: DeriveIMSPrivateIdentity(imsi, mcc, mnc),
		IMSPublicIdentity:  DeriveIMSPublicIdentity(imsi, mcc, mnc),
		PermanentNAI:       DerivePermanentNAI(imsi, mcc, mnc),
	}
}

var blockedMCC = map[string]struct{}{
	"460": {},
}

func IsVoWiFiBlockedMCC(mcc string) bool {
	_, ok := blockedMCC[normalizeMCC(mcc)]
	return ok
}

type VoWiFiBlockedMCCError struct {
	MCC string
}

func (e VoWiFiBlockedMCCError) Error() string {
	return fmt.Sprintf("vowifi blocked by carrier policy for MCC %s", e.MCC)
}

func NewVoWiFiBlockedMCCError(mcc string) error {
	return VoWiFiBlockedMCCError{MCC: normalizeMCC(mcc)}
}

func IsVoWiFiPolicyBlockedError(err error) bool {
	var target VoWiFiBlockedMCCError
	return errors.As(err, &target)
}

func normalizeConfig(cfg EffectiveCarrierConfig) EffectiveCarrierConfig {
	cfg.MCC = normalizeMCC(cfg.MCC)
	cfg.MNC = normalizeMNC(cfg.MNC)
	if cfg.PresetID == "" {
		cfg.PresetID = presetKey(cfg.MCC, cfg.MNC)
	} else {
		cfg.PresetID = strings.TrimSpace(cfg.PresetID)
	}
	cfg.E911.Provider = strings.ToLower(strings.TrimSpace(cfg.E911.Provider))
	cfg.E911.Websheet = strings.TrimSpace(cfg.E911.Websheet)
	cfg.E911.EntitlementEndpoint = strings.TrimSpace(cfg.E911.EntitlementEndpoint)
	cfg.Network = normalizeNetworkConfig(cfg.MCC, cfg.MNC, cfg.Network)
	return cfg
}

func DefaultIMSRealm(mcc, mnc string) string {
	mcc = normalizeMCC(mcc)
	mnc = normalizeMNC(mnc)
	if mcc == "" || mnc == "" {
		return ""
	}
	return fmt.Sprintf("ims.mnc%s.mcc%s.3gppnetwork.org", mnc, mcc)
}

func DefaultNAIRealm(mcc, mnc string) string {
	mcc = normalizeMCC(mcc)
	mnc = normalizeMNC(mnc)
	if mcc == "" || mnc == "" {
		return ""
	}
	return fmt.Sprintf("nai.epc.mnc%s.mcc%s.3gppnetwork.org", mnc, mcc)
}

func DefaultEPDGFQDN(mcc, mnc string) string {
	mcc = normalizeMCC(mcc)
	mnc = normalizeMNC(mnc)
	if mcc == "" || mnc == "" {
		return ""
	}
	return fmt.Sprintf("epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org", mnc, mcc)
}

func DeriveIMSPrivateIdentity(imsi, mcc, mnc string) string {
	imsi = strings.TrimSpace(imsi)
	realm := DefaultIMSRealm(mcc, mnc)
	if imsi == "" || realm == "" {
		return ""
	}
	return imsi + "@" + realm
}

func DeriveIMSPublicIdentity(imsi, mcc, mnc string) string {
	imsi = strings.TrimSpace(imsi)
	realm := DefaultIMSRealm(mcc, mnc)
	if imsi == "" || realm == "" {
		return ""
	}
	return "sip:" + imsi + "@" + realm
}

func DerivePermanentNAI(imsi, mcc, mnc string) string {
	imsi = strings.TrimSpace(imsi)
	realm := DefaultNAIRealm(mcc, mnc)
	if imsi == "" || realm == "" {
		return ""
	}
	return "0" + imsi + "@" + realm
}

func normalizeNetworkConfig(mcc, mnc string, cfg NetworkConfig) NetworkConfig {
	cfg.IMSRealm = normalizeDomainName(cfg.IMSRealm)
	cfg.NAIRealm = normalizeDomainName(cfg.NAIRealm)
	cfg.EPDGFQDN = normalizeDomainName(cfg.EPDGFQDN)
	if mcc == "" || mnc == "" {
		return cfg
	}
	if cfg.IMSRealm == "" {
		cfg.IMSRealm = DefaultIMSRealm(mcc, mnc)
	}
	if cfg.NAIRealm == "" {
		cfg.NAIRealm = DefaultNAIRealm(mcc, mnc)
	}
	if cfg.EPDGFQDN == "" {
		cfg.EPDGFQDN = DefaultEPDGFQDN(mcc, mnc)
	}
	return cfg
}

func normalizeMCC(mcc string) string {
	return strings.TrimSpace(mcc)
}

func normalizeMNC(mnc string) string {
	mnc = strings.TrimSpace(mnc)
	if len(mnc) == 2 {
		return "0" + mnc
	}
	return mnc
}

func normalizeDomainName(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return strings.TrimSuffix(domain, ".")
}

func presetKey(mcc, mnc string) string {
	mcc = normalizeMCC(mcc)
	mnc = normalizeMNC(mnc)
	if mcc == "" || mnc == "" {
		return ""
	}
	return mcc + mnc
}

func splitPresetKey(key string) (string, string) {
	key = strings.TrimSpace(key)
	if len(key) < 5 {
		return "", ""
	}
	return key[:3], key[3:]
}
