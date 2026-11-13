package identity

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/kimoju/vowifi-go/runtimehost/carrier"
	"github.com/kimoju/vowifi-go/runtimehost/simtransport"
)

type crsmChunkFake struct {
	calls     []string
	responses []simtransport.CRSMResult
}

func (f *crsmChunkFake) ReadCRSMBinary(fileID uint16, offset, length int, pathID string) (simtransport.CRSMResult, error) {
	f.calls = append(f.calls, hex.EncodeToString([]byte{byte(offset >> 8), byte(offset), byte(length)}))
	if len(f.responses) == 0 {
		return simtransport.CRSMResult{SW1: 0x6B, SW2: 0x00}, nil
	}
	out := f.responses[0]
	f.responses = f.responses[1:]
	return out, nil
}

func TestRound2Audit8B02ReadCRSMTransparentEFMultiChunk(t *testing.T) {
	chunk1 := bytes.Repeat([]byte{0x41}, 256)
	chunk2 := bytes.Repeat([]byte{0x42}, 64)
	fake := &crsmChunkFake{
		responses: []simtransport.CRSMResult{
			{SW1: 0x90, SW2: 0x00, Data: strings.ToUpper(hex.EncodeToString(chunk1))},
			{SW1: 0x90, SW2: 0x00, Data: strings.ToUpper(hex.EncodeToString(chunk2))},
		},
	}
	got, _, err := readCRSMTransparentEF(fake, 0x6F02, "")
	if err != nil {
		t.Fatalf("readCRSMTransparentEF(320B) error = %v", err)
	}
	want := append(append([]byte(nil), chunk1...), chunk2...)
	if !bytes.Equal(got, want) || len(fake.calls) != 2 {
		t.Fatalf("readCRSMTransparentEF len=%d calls=%d, want 320 and 2 calls", len(got), len(fake.calls))
	}
}

func TestRound2Audit8B03DecodeISIMStringClearedTLVAndLongUntagged(t *testing.T) {
	if got := decodeISIMString([]byte{0x80, 0x00, 0xFF, 0xFF, 0xFF}); got != "" {
		t.Fatalf("decodeISIMString(80 00 FF FF FF) = %q, want empty", got)
	}
	untagged := "sip:310260123456789@ims.mnc260.mcc310.3gppnetwork.org"
	raw := append([]byte(untagged), 0xFF, 0xFF)
	if got := decodeISIMString(raw); got != untagged {
		t.Fatalf("decodeISIMString(untagged 53B) = %q, want %q", got, untagged)
	}
}

type simSwapAccessFake struct {
	ad []byte
}

func (f simSwapAccessFake) GetISIMIdentity() (Identity, error) {
	return Identity{}, errors.New("ISIM unavailable")
}

func (f simSwapAccessFake) ReadCRSMBinary(fileID uint16, offset, length int, pathID string) (simtransport.CRSMResult, error) {
	if fileID == 0x6FAD && len(f.ad) > 0 {
		return simtransport.CRSMResult{SW1: 0x90, SW2: 0x00, Data: strings.ToUpper(hex.EncodeToString(f.ad))}, nil
	}
	return simtransport.CRSMResult{SW1: 0x6A, SW2: 0x82}, nil
}

func TestRound2Audit8B07And8B13IMEIValidationIMSIRejectionAndStalePLMNReset(t *testing.T) {
	carrier.ClearCarrierOverrides()
	t.Cleanup(carrier.ClearCarrierOverrides)

	// 1. ExtractIMEI supports urn:gsma:imei (recomputing Luhn check digit), 16-digit IMEISV, and rejects ICCIDs/invalid Luhn.
	if got := ExtractIMEI("urn:gsma:imei:49015420-323751-0"); got != "490154203237518" {
		t.Fatalf("ExtractIMEI(urn:gsma:imei) = %q, want 490154203237518", got)
	}
	if got := ExtractIMEI("IMEISV=4901542032375101"); got != "490154203237518" {
		t.Fatalf("ExtractIMEI(IMEISV) = %q, want 490154203237518", got)
	}
	if got := ExtractIMEI("89014103211118510720"); got != "" {
		t.Fatalf("ExtractIMEI(ICCID) = %q, want empty", got)
	}
	if got := ExtractIMEI("490154203237510"); got != "" {
		t.Fatalf("ExtractIMEI(bad Luhn) = %q, want empty", got)
	}

	// 2. PrepareStart must NOT scrape DeviceID as IMEI when DeviceID contains the subscriber's IMSI!
	// Even when the 15-digit IMSI happens to satisfy Luhn ("490154203237518"), imei == IMSI must be rejected.
	luhnIMSI := "490154203237518"
	preparedIMSI, err := PrepareStart(PrepareStartInput{
		DeviceID: "sim-" + luhnIMSI,
		Profile:  Profile{IMSI: luhnIMSI},
		Access:   simSwapAccessFake{},
	})
	if err != nil {
		t.Fatalf("PrepareStart(DeviceID=IMSI) error = %v", err)
	}
	if preparedIMSI.Profile.IMEI != "" {
		t.Fatalf("PrepareStart leaked IMSI into Profile.IMEI = %q, want empty", preparedIMSI.Profile.IMEI)
	}

	// 3. Hyphenated Profile.IMEI is normalized to 15 digits, and stale Profile.MCC/MNC from a prior SIM
	// (310/260) is discarded and re-derived from new SIM IMSI (460001234567890 + EF_AD mncLen=2 -> 460/00).
	preparedSwap, err := PrepareStart(PrepareStartInput{
		DeviceID: "slot-1",
		Profile: Profile{
			IMSI: "460001234567890",
			MCC:  "310",
			MNC:  "260",
			IMEI: "49015420-323751-8",
		},
		Access: simSwapAccessFake{
			ad: []byte{0x00, 0x00, 0x00, 0x02},
		},
	})
	if err != nil {
		t.Fatalf("PrepareStart(SIM swap) error = %v", err)
	}
	if preparedSwap.Profile.IMEI != "490154203237518" {
		t.Fatalf("normalized Profile.IMEI = %q, want 490154203237518", preparedSwap.Profile.IMEI)
	}
	if preparedSwap.Profile.MCC != "460" || (preparedSwap.Profile.MNC != "00" && preparedSwap.Profile.MNC != "000") {
		t.Fatalf("SIM swap PLMN = (%q, %q), want (460, 00/000)", preparedSwap.Profile.MCC, preparedSwap.Profile.MNC)
	}
	if !strings.Contains(preparedSwap.CarrierPolicy.IMS.IMSPrivateIdentity, "mnc000.mcc460.3gppnetwork.org") {
		t.Fatalf("SIM swap IMSPrivateIdentity = %q, want mnc000.mcc460", preparedSwap.CarrierPolicy.IMS.IMSPrivateIdentity)
	}
}
