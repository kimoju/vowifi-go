package carrier

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRound2Audit8B13PLMNTwoVsThreeDigitMNCAndReloadNoHijack(t *testing.T) {
	ClearCarrierOverrides()
	t.Cleanup(ClearCarrierOverrides)

	// 1. Colliding 2-digit ("310-26") and 3-digit ("310-026") overrides remain distinct and load deterministically.
	dir := t.TempDir()
	overridePath := filepath.Join(dir, "overrides.json")
	rawJSON := `{
		"310-026": {"mcc":"310","mnc":"026","mnc_digits":3,"network":{"ims_realm":"ims.mnc026-3.example"}},
		"310-26":  {"mcc":"310","mnc":"26","mnc_digits":2,"network":{"ims_realm":"ims.mnc26-2.example"}}
	}`
	if err := os.WriteFile(overridePath, []byte(rawJSON), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := LoadCarrierOverrides(overridePath); err != nil {
			t.Fatalf("LoadCarrierOverrides() iter %d error = %v", i, err)
		}
		two := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "310", MNC: "26"})
		three := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "310", MNC: "026"})
		if two.Network.IMSRealm != "ims.mnc26-2.example" {
			t.Fatalf("2-digit resolve = %+v", two)
		}
		if three.Network.IMSRealm != "ims.mnc026-3.example" {
			t.Fatalf("3-digit resolve = %+v", three)
		}
	}

	// 2. Saving and reloading an EffectiveCarrierConfig for a 2-digit PLMN (e.g. UK 234-15 normalized to MNC="015")
	// must NOT cause DerivePLMNFromIMSI("234015123456789") to hijack 2-digit PLMN 234-01 subscribers!
	ClearCarrierOverrides()
	vodafone := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "234", MNC: "15"})
	reloadMap := map[string]EffectiveCarrierConfig{"234-015": vodafone}
	reloadBytes, err := json.Marshal(reloadMap)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	reloadPath := filepath.Join(dir, "reload.json")
	if err := os.WriteFile(reloadPath, reloadBytes, 0o600); err != nil {
		t.Fatalf("WriteFile(reload) error = %v", err)
	}
	if _, err := LoadCarrierOverrides(reloadPath); err != nil {
		t.Fatalf("LoadCarrierOverrides(reload) error = %v", err)
	}
	mcc, mnc := DerivePLMNFromIMSI("234015123456789")
	if mcc != "234" || mnc != "01" {
		t.Fatalf("DerivePLMNFromIMSI(234015123456789) = (%q, %q), want (234, 01)", mcc, mnc)
	}

	// Test PLMN 001 continues to use 3-digit MNC behavior.
	mcc001, mnc001 := DerivePLMNFromIMSI("001010123456789")
	if mcc001 != "001" || mnc001 != "010" {
		t.Fatalf("DerivePLMNFromIMSI(001010123456789) = (%q, %q), want (001, 010)", mcc001, mnc001)
	}
}

func TestRound2Audit8B14TelURIContactAndVisitedNetworkIDQuoting(t *testing.T) {
	// 1. tel: IMPU must not produce sip:tel:+1...@host:port in Contact URI.
	gotUser := sipUserFromIdentity("tel:+12065550100;phone-context=ims.mnc260.mcc310.3gppnetwork.org")
	if gotUser != "+12065550100" {
		t.Fatalf("sipUserFromIdentity(tel:) = %q, want +12065550100", gotUser)
	}
	contact := imsContactURI(IMSAccessProfile{
		IMSPublicIdentity:  "tel:+12065550100;phone-context=ims.mnc260.mcc310.3gppnetwork.org",
		IMSPrivateIdentity: "310260123456789@ims.mnc260.mcc310.3gppnetwork.org",
	}, "10.0.0.2", 5060)
	if strings.Contains(contact, "sip:tel:") || contact != "sip:+12065550100@10.0.0.2:5060" {
		t.Fatalf("imsContactURI(tel:) = %q, want sip:+12065550100@10.0.0.2:5060", contact)
	}

	// 2. formatVisitedNetworkIDHeader must never pass a lone `"` through unclosed, and must quote list items with spaces/colons.
	if got := formatVisitedNetworkIDHeader(`"`); got != `"\""` {
		t.Fatalf("formatVisitedNetworkIDHeader(single quote) = %q, want %q", got, `"\""`)
	}
	list := formatVisitedNetworkIDHeader(`Visited Network One, ims.mnc260.mcc310.3gppnetwork.org`)
	if list != `"Visited Network One", "ims.mnc260.mcc310.3gppnetwork.org"` {
		t.Fatalf("formatVisitedNetworkIDHeader(list) = %q", list)
	}
}
