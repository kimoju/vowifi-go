package simtransport

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestRound2Audit8B01SecurityStatusWords(t *testing.T) {
	st9862 := DescribeAPDUStatus(0x98, 0x62)
	if st9862.Class != APDUStatusClassSecurityError || !strings.Contains(strings.ToLower(st9862.Meaning), "authentication error") {
		t.Fatalf("DescribeAPDUStatus(0x98, 0x62) = %+v, want security authentication error", st9862)
	}
	st9864 := DescribeAPDUStatus(0x98, 0x64)
	if st9864.Class != APDUStatusClassSecurityError {
		t.Fatalf("DescribeAPDUStatus(0x98, 0x64) = %+v, want security error", st9864)
	}
	st9850 := DescribeAPDUStatus(0x98, 0x50)
	if st9850.Class != APDUStatusClassSecurityError {
		t.Fatalf("DescribeAPDUStatus(0x98, 0x50) = %+v, want security error", st9850)
	}
	stGeneric := DescribeAPDUStatus(0x98, 0x04)
	if stGeneric.Class != APDUStatusClassSecurityError {
		t.Fatalf("DescribeAPDUStatus(0x98, 0x04) = %+v, want %q", stGeneric, APDUStatusClassSecurityError)
	}
}

func TestRound2Audit8B02CRSMRecoveryAndOffsetGuard(t *testing.T) {
	// 1. ReadCRSMBinary rejects offset > 0x7FFF (preventing SFI bit corruption) and recovers SW=6C04.
	atBinary := &fakeAT{responses: []string{
		"+CRSM: 108,4,\"\"\r\nOK\r\n",
		"+CRSM: 144,0,\"0002AABB\"\r\nOK\r\n",
	}}
	adapter := NewAdapter(atBinary)
	if _, err := adapter.ReadCRSMBinary(0x6F7E, 0x8000, 16, ""); err == nil {
		t.Fatal("ReadCRSMBinary(offset=0x8000) = nil, want invalid CRSM offset error")
	}
	res, err := adapter.ReadCRSMBinary(0x6F7E, 0x7FFF, 16, "")
	if err != nil {
		t.Fatalf("ReadCRSMBinary(6C04) error = %v", err)
	}
	if res.SW1 != 0x90 || res.SW2 != 0x00 || res.Data != "0002AABB" {
		t.Fatalf("ReadCRSMBinary(6C04) = %+v, want 9000 0002AABB", res)
	}
	wantBinaryCalls := []string{
		"AT+CRSM=176,28542,127,255,16",
		"AT+CRSM=176,28542,127,255,4",
	}
	if !reflect.DeepEqual(atBinary.calls, wantBinaryCalls) {
		t.Fatalf("ReadCRSMBinary calls = %#v, want %#v", atBinary.calls, wantBinaryCalls)
	}

	// 2. ReadCRSMRecord recovers SW=6106 via AT+CRSM=192 GET RESPONSE.
	atRecord := &fakeAT{responses: []string{
		"+CRSM: 97,6,\"\"\r\nOK\r\n",
		"+CRSM: 144,0,\"800474657374\"\r\nOK\r\n",
	}}
	resRec, err := NewAdapter(atRecord).ReadCRSMRecord(0x6F04, 1, 32, "")
	if err != nil {
		t.Fatalf("ReadCRSMRecord(6106) error = %v", err)
	}
	if resRec.SW1 != 0x90 || resRec.SW2 != 0x00 || resRec.Data != "800474657374" {
		t.Fatalf("ReadCRSMRecord(6106) = %+v, want 9000 800474657374", resRec)
	}
	wantRecCalls := []string{
		"AT+CRSM=178,28420,1,4,32",
		"AT+CRSM=192,28420,0,0,6",
	}
	if !reflect.DeepEqual(atRecord.calls, wantRecCalls) {
		t.Fatalf("ReadCRSMRecord calls = %#v, want %#v", atRecord.calls, wantRecCalls)
	}
}

func TestRound2Audit8B07IMEILuhnIMEISVAndICCIDRejection(t *testing.T) {
	check, ok := ComputeIMEILuhn("49015420323751")
	if !ok || check != '8' {
		t.Fatalf("ComputeIMEILuhn() = (%q, %v), want ('8', true)", check, ok)
	}
	if !ValidateIMEI("490154203237518") {
		t.Fatal("ValidateIMEI(490154203237518) = false, want true")
	}
	if ValidateIMEI("490154203237510") {
		t.Fatal("ValidateIMEI(invalid check digit) = true, want false")
	}

	// 16-digit IMEISV (TAC+SNR+SVN) derives 15-digit IMEI with Luhn check digit instead of SVN[0].
	atIMEISV := &fakeAT{responses: []string{"+CGSN: 4901542032375101\r\nOK\r\n"}}
	gotIMEI, err := NewAdapter(atIMEISV).ReadIMEI()
	if err != nil {
		t.Fatalf("ReadIMEI(IMEISV) error = %v", err)
	}
	if gotIMEI != "490154203237518" {
		t.Fatalf("ReadIMEI(IMEISV) = %q, want 490154203237518", gotIMEI)
	}

	// 19-20 digit ICCID echoed before IMEI must never be sliced to 15 digits.
	atICCIDThenIMEI := &fakeAT{responses: []string{"ICCID: 89014103211118510720\r\nIMEI: 49015420-323751-8\r\nOK\r\n"}}
	gotIMEI2, err := NewAdapter(atICCIDThenIMEI).ReadIMEI()
	if err != nil {
		t.Fatalf("ReadIMEI(ICCID+IMEI) error = %v", err)
	}
	if gotIMEI2 != "490154203237518" {
		t.Fatalf("ReadIMEI(ICCID+IMEI) = %q, want 490154203237518", gotIMEI2)
	}

	// Standalone 20-digit ICCID must fail rather than returning ICCID[:15].
	atOnlyICCID := &fakeAT{responses: []string{
		"89014103211118510720\r\nOK\r\n",
		"89014103211118510720\r\nOK\r\n",
		"89014103211118510720\r\nOK\r\n",
	}}
	if got, err := NewAdapter(atOnlyICCID).ReadIMEI(); err == nil {
		t.Fatalf("ReadIMEI(only ICCID) = %q, want error", got)
	}
}

func TestRound2Audit8B15GetResponseCLACMSErrorAndRecoveryClassification(t *testing.T) {
	// 1. Proprietary CLA=0x82 command receiving SW=6104 must send ISO CLA=0x02 GET RESPONSE (never 0x82),
	// while GSM SW=9F02 continues to use CLA=0xA0.
	at := &fakeAT{responses: []string{
		"+CGLA: 4,\"6104\"\r\nOK\r\n",
		"+CGLA: 12,\"DEADBEEF9000\"\r\nOK\r\n",
		"+CGLA: 4,\"9F02\"\r\nOK\r\n",
		"+CGLA: 8,\"CAFE9000\"\r\nOK\r\n",
	}}
	adapter := NewAdapter(at)
	resp, err := adapter.TransmitAPDU(2, "828800810401020304")
	if err != nil || resp != "DEADBEEF9000" {
		t.Fatalf("TransmitAPDU(CLA=0x82, SW=6104) = (%q, %v), want DEADBEEF9000", resp, err)
	}
	resp9F, err := adapter.TransmitAPDU(0, "A0A40000027F20")
	if err != nil || resp9F != "CAFE9000" {
		t.Fatalf("TransmitAPDU(CLA=0xA0, SW=9F02) = (%q, %v), want CAFE9000", resp9F, err)
	}
	wantCalls := []string{
		`AT+CGLA=2,18,"828800810401020304"`,
		`AT+CGLA=2,10,"02C0000004"`,
		`AT+CSIM=14,"A0A40000027F20"`,
		`AT+CSIM=10,"A0C0000002"`,
	}
	if !reflect.DeepEqual(at.calls, wantCalls) {
		t.Fatalf("GET RESPONSE calls = %#v, want %#v", at.calls, wantCalls)
	}

	// 2. +CMS ERROR: 314 (SIM busy) on ReadSMSC surfaces as AT error and classifies as RecoveryClassSIMBusy.
	atCMS := &fakeAT{responses: []string{"+CMS ERROR: 314\r\n"}}
	_, cmsErr := NewAdapter(atCMS).ReadSMSC()
	if cmsErr == nil {
		t.Fatal("ReadSMSC(+CMS ERROR: 314) = nil, want error")
	}
	if got := ClassifyError(cmsErr); got != RecoveryClassSIMBusy {
		t.Fatalf("ClassifyError(+CMS ERROR: 314) = %q, want %q (err=%v)", got, RecoveryClassSIMBusy, cmsErr)
	}
	if got := ClassifyError(errors.New("AT CMS ERROR: 313")); got != RecoveryClassATError {
		t.Fatalf("ClassifyError(AT CMS ERROR: 313) = %q, want %q", got, RecoveryClassATError)
	}

	// 3. context.Canceled must never classify as hung control port or trigger hardware reset actions.
	canceledErr := fmt.Errorf("read imsi: %w", context.Canceled)
	if got := ClassifyError(canceledErr); got != RecoveryClassNone {
		t.Fatalf("ClassifyError(context.Canceled) = %q, want %q", got, RecoveryClassNone)
	}
	decision := ClassifyControlPortRecovery(ControlPortRecoveryInput{
		PortType:  ControlPortTypeAT,
		Operation: "read_imsi",
		Err:       canceledErr,
	})
	if decision.Class != RecoveryClassNone || decision.RestartControlPort || len(decision.ATControlPlan) != 0 {
		t.Fatalf("ClassifyControlPortRecovery(context.Canceled) = %+v, want RecoveryClassNone with no reset plan", decision)
	}

	// 4. TCP port numbers like :6500 or :6100 in timeout errors must not match 4-hex APDU status words.
	for _, msg := range []string{
		"dial tcp 127.0.0.1:6500: i/o timeout",
		"port 6100: context deadline exceeded",
	} {
		if got := ClassifyError(errors.New(msg)); got != RecoveryClassControlPortHung {
			t.Fatalf("ClassifyError(%q) = %q, want %q", msg, got, RecoveryClassControlPortHung)
		}
	}
}
