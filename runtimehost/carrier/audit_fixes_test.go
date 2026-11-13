package carrier

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDerivePLMNFromIMSIHandlesTwoAndThreeDigitMNC(t *testing.T) {
	ClearCarrierOverrides()
	t.Cleanup(ClearCarrierOverrides)

	// 2-digit European/Asian MCCs must not blindly slice 3 digits.
	mcc, mnc := DerivePLMNFromIMSI("234150123456789")
	if mcc != "234" || mnc != "15" {
		t.Fatalf("DerivePLMNFromIMSI(UK 234-15) = (%q,%q), want (234,15)", mcc, mnc)
	}
	profile := NormalizeSubscriberProfile(SubscriberProfileInput{IMSI: "234150123456789"})
	if profile.MCC != "234" || profile.MNC != "015" || profile.Network.IMSRealm != "ims.mnc015.mcc234.3gppnetwork.org" {
		t.Fatalf("NormalizeSubscriberProfile(234-15) = %+v", profile)
	}

	mcc, mnc = DerivePLMNFromIMSI("262011234567890")
	if mcc != "262" || mnc != "01" {
		t.Fatalf("DerivePLMNFromIMSI(DE 262-01) = (%q,%q), want (262,01)", mcc, mnc)
	}

	// North American 3-digit MCC.
	mcc, mnc = DerivePLMNFromIMSI("310280233621715")
	if mcc != "310" || mnc != "280" {
		t.Fatalf("DerivePLMNFromIMSI(US 310-280) = (%q,%q), want (310,280)", mcc, mnc)
	}

	// EF_AD overrides heuristic in both directions.
	mcc, mnc = DerivePLMNFromIMSIWithAD("310260123456789", []byte{0x00, 0x00, 0x00, 0x02})
	if mcc != "310" || mnc != "26" {
		t.Fatalf("DerivePLMNFromIMSIWithAD(EF_AD=2) = (%q,%q), want (310,26)", mcc, mnc)
	}
	mcc, mnc = DerivePLMNFromIMSIWithAD("234999123456789", []byte{0x00, 0x00, 0x00, 0x03})
	if mcc != "234" || mnc != "999" {
		t.Fatalf("DerivePLMNFromIMSIWithAD(EF_AD=3) = (%q,%q), want (234,999)", mcc, mnc)
	}
}

func TestDerivePLMNFromIMSIConsultsCarrierOverridesTable(t *testing.T) {
	ClearCarrierOverrides()
	t.Cleanup(ClearCarrierOverrides)

	path := filepath.Join(t.TempDir(), "carriers.json")
	if err := os.WriteFile(path, []byte(`{
		"234999": {
			"mcc": "234",
			"mnc": "999"
		},
		"31026": {
			"mcc": "310",
			"mnc": "26"
		}
	}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCarrierOverrides(path); err != nil {
		t.Fatalf("LoadCarrierOverrides() error = %v", err)
	}

	mcc, mnc := DerivePLMNFromIMSI("234999123456789")
	if mcc != "234" || mnc != "999" {
		t.Fatalf("DerivePLMNFromIMSI(3-digit override) = (%q,%q), want (234,999)", mcc, mnc)
	}

	mcc, mnc = DerivePLMNFromIMSI("310269123456789")
	if mcc != "310" || mnc != "26" {
		t.Fatalf("DerivePLMNFromIMSI(2-digit override) = (%q,%q), want (310,26)", mcc, mnc)
	}
}
