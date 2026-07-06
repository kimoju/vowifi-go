package carrier

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveEffectiveCarrierConfigEnablesATTNativeE911(t *testing.T) {
	ClearCarrierOverrides()
	cfg := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "310", MNC: "280"})
	if cfg.PresetID != "310280" {
		t.Fatalf("PresetID=%q, want 310280", cfg.PresetID)
	}
	if !cfg.E911.Enabled || cfg.E911.Provider != "att-ts43" || cfg.E911.Websheet == "" || cfg.E911.EntitlementEndpoint == "" {
		t.Fatalf("E911 config=%+v, want enabled ATT TS.43 preset", cfg.E911)
	}
}

func TestResolveEffectiveCarrierConfigNormalizesTwoDigitMNC(t *testing.T) {
	ClearCarrierOverrides()
	cfg := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "310", MNC: "28"})
	if cfg.PresetID != "310028" {
		t.Fatalf("PresetID=%q, want normalized 310028", cfg.PresetID)
	}
	if cfg.E911.Enabled {
		t.Fatalf("E911 enabled for unknown normalized preset: %+v", cfg.E911)
	}
	if cfg.Network.IMSRealm != "ims.mnc028.mcc310.3gppnetwork.org" ||
		cfg.Network.NAIRealm != "nai.epc.mnc028.mcc310.3gppnetwork.org" ||
		cfg.Network.EPDGFQDN != "epdg.epc.mnc028.mcc310.pub.3gppnetwork.org" {
		t.Fatalf("Network=%+v, want derived 3GPP defaults", cfg.Network)
	}
}

func TestLoadCarrierOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "carriers.json")
	if err := os.WriteFile(path, []byte(`{
		"001001": {
			"mcc": "001",
			"mnc": "001",
			"e911": {
				"enabled": true,
				"provider": "ts43",
				"websheet": "https://example.test/e911",
				"entitlement_endpoint": "https://example.test/entitlement"
			}
		}
	}`), 0600); err != nil {
		t.Fatal(err)
	}
	res, err := LoadCarrierOverrides(path)
	if err != nil {
		t.Fatalf("LoadCarrierOverrides() error = %v", err)
	}
	if res.Missing || res.Count != 1 {
		t.Fatalf("LoadResult=%+v, want one loaded override", res)
	}
	cfg := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "001", MNC: "001"})
	if !cfg.E911.Enabled || cfg.E911.Provider != "ts43" || cfg.E911.Websheet != "https://example.test/e911" {
		t.Fatalf("override config=%+v", cfg)
	}
	ClearCarrierOverrides()
}

func TestLoadCarrierOverridesNormalizesShortKeyAndNetworkPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "carriers.json")
	if err := os.WriteFile(path, []byte(`{
		"31028": {
			"network": {
				"ims_realm": " IMS.OVERRIDE.EXAMPLE. ",
				"epdg_fqdn": " EPDG.OVERRIDE.EXAMPLE. "
			}
		}
	}`), 0600); err != nil {
		t.Fatal(err)
	}
	res, err := LoadCarrierOverrides(path)
	if err != nil {
		t.Fatalf("LoadCarrierOverrides() error = %v", err)
	}
	if res.Missing || res.Count != 1 {
		t.Fatalf("LoadResult=%+v, want one loaded override", res)
	}
	cfg := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "310", MNC: "28"})
	if cfg.MCC != "310" || cfg.MNC != "028" || cfg.PresetID != "310028" {
		t.Fatalf("PLMN=(%q,%q) PresetID=%q, want normalized 310028", cfg.MCC, cfg.MNC, cfg.PresetID)
	}
	if cfg.Network.IMSRealm != "ims.override.example" ||
		cfg.Network.NAIRealm != "nai.epc.mnc028.mcc310.3gppnetwork.org" ||
		cfg.Network.EPDGFQDN != "epdg.override.example" {
		t.Fatalf("Network=%+v, want override plus fallback defaults", cfg.Network)
	}
	ClearCarrierOverrides()
}
