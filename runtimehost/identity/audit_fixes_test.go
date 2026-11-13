package identity

import (
	"encoding/hex"
	"testing"

	"github.com/kimoju/vowifi-go/runtimehost/simtransport"
)

type efadTestAccess struct {
	efAD []byte
}

func (a efadTestAccess) GetISIMIdentity() (Identity, error) { return Identity{}, nil }
func (a efadTestAccess) GetEFAD() ([]byte, error)           { return a.efAD, nil }

func TestPrepareStartDerivesTwoDigitMNCAndHonorsEFAD(t *testing.T) {
	prepared, err := PrepareStart(PrepareStartInput{
		Profile: Profile{IMSI: "234150123456789"},
	})
	if err != nil {
		t.Fatalf("PrepareStart(234-15) error = %v", err)
	}
	if prepared.Profile.MCC != "234" || prepared.Profile.MNC != "15" {
		t.Fatalf("Profile PLMN = (%q,%q), want (234,15)", prepared.Profile.MCC, prepared.Profile.MNC)
	}
	if prepared.EffectiveCarrier.MNC != "015" || prepared.IMSIdentity.Domain != "ims.mnc015.mcc234.3gppnetwork.org" {
		t.Fatalf("EffectiveCarrier=%+v Domain=%q, want mnc015", prepared.EffectiveCarrier, prepared.IMSIdentity.Domain)
	}

	// EF_AD via Access.GetEFAD() overrides North American 3-digit default when SIM is 2-digit MNC.
	preparedAD, err := PrepareStart(PrepareStartInput{
		Profile: Profile{IMSI: "310260123456789"},
		Access:  efadTestAccess{efAD: []byte{0x00, 0x00, 0x00, 0x02}},
	})
	if err != nil {
		t.Fatalf("PrepareStart(EF_AD=2) error = %v", err)
	}
	if preparedAD.Profile.MCC != "310" || preparedAD.Profile.MNC != "26" || preparedAD.EffectiveCarrier.MNC != "026" {
		t.Fatalf("PrepareStart(EF_AD=2) PLMN = (%q,%q) effective=%+v", preparedAD.Profile.MCC, preparedAD.Profile.MNC, preparedAD.EffectiveCarrier)
	}
}

func TestReadISIMIdentityCRSMAcceptsSW6282WithData(t *testing.T) {
	impiHex := hex.EncodeToString(isimTLVString("234150123456789@ims.mnc015.mcc234.3gppnetwork.org"))
	domainHex := hex.EncodeToString(isimTLVString("ims.mnc015.mcc234.3gppnetwork.org"))
	impuHex := hex.EncodeToString(padRecord(isimTLVString("sip:234150123456789@ims.mnc015.mcc234.3gppnetwork.org"), 64))

	ft := &crsmIdentityFake{
		binary: []simtransport.CRSMResult{
			{Data: impiHex, SW1: 0x62, SW2: 0x82},
			{Data: domainHex, SW1: 0x62, SW2: 0x82},
		},
		records: []simtransport.CRSMResult{
			{Data: impuHex, SW1: 0x90, SW2: 0x00},
			{SW1: 0x6A, SW2: 0x83},
		},
	}

	id, err := ReadISIMIdentityCRSM(ft, "7fff")
	if err != nil {
		t.Fatalf("ReadISIMIdentityCRSM(SW=6282) error = %v", err)
	}
	if id.IMPI != "234150123456789@ims.mnc015.mcc234.3gppnetwork.org" ||
		id.Domain != "ims.mnc015.mcc234.3gppnetwork.org" ||
		len(id.IMPU) != 1 {
		t.Fatalf("ReadISIMIdentityCRSM(SW=6282) = %+v", id)
	}
}
