package carrier

import (
	"errors"
	"fmt"
	"strings"
)

type E911Config struct {
	Enabled  bool
	Provider string
	Websheet string
}

type EffectiveCarrierConfig struct {
	MCC      string
	MNC      string
	PresetID string
	E911     E911Config
}

type EffectiveCarrierConfigInput struct {
	MCC string
	MNC string
}

type LoadResult struct {
	Path    string
	Missing bool
	Count   int
}

func LoadCarrierOverrides(path string) (LoadResult, error) {
	return LoadResult{Path: path, Missing: true}, nil
}

func ClearCarrierOverrides() {}

func ResolveEffectiveCarrierConfig(in EffectiveCarrierConfigInput) EffectiveCarrierConfig {
	mcc := strings.TrimSpace(in.MCC)
	mnc := strings.TrimSpace(in.MNC)
	return EffectiveCarrierConfig{
		MCC:      mcc,
		MNC:      mnc,
		PresetID: mcc + mnc,
		E911: E911Config{
			Enabled:  false,
			Provider: "",
		},
	}
}

var blockedMCC = map[string]struct{}{
	"460": {},
}

func IsVoWiFiBlockedMCC(mcc string) bool {
	_, ok := blockedMCC[strings.TrimSpace(mcc)]
	return ok
}

type VoWiFiBlockedMCCError struct {
	MCC string
}

func (e VoWiFiBlockedMCCError) Error() string {
	return fmt.Sprintf("vowifi blocked by carrier policy for MCC %s", e.MCC)
}

func NewVoWiFiBlockedMCCError(mcc string) error {
	return VoWiFiBlockedMCCError{MCC: strings.TrimSpace(mcc)}
}

func IsVoWiFiPolicyBlockedError(err error) bool {
	var target VoWiFiBlockedMCCError
	return errors.As(err, &target)
}
