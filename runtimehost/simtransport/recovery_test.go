package simtransport

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestClassifyRecoveryErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want RecoveryClass
	}{
		{name: "deadline", err: context.DeadlineExceeded, want: RecoveryClassControlPortHung},
		{name: "ccho parse", err: errors.New("open ISIM logical channel: parse CCHO channel from OK"), want: RecoveryClassControlPortHung},
		{name: "crsm file missing", err: errors.New("CRSM read EF_IMPI: READ BINARY 6F02 failed: SW=6A82"), want: RecoveryClassFileNotFound},
		{name: "bare 6a82", err: errors.New("6A82"), want: RecoveryClassFileNotFound},
		{name: "apdu busy status", err: errors.New("READ BINARY 6F02 failed: SW=9300"), want: RecoveryClassSIMBusy},
		{name: "invalidated status", err: errors.New("READ RECORD 6F04 #1 failed: status=6283"), want: RecoveryClassSIMBusy},
		{name: "technical problem status", err: errors.New("AUTHENTICATE failed: SW=6F00"), want: RecoveryClassSIMBusy},
		{name: "empty ef status", err: errors.New("READ BINARY 6F03 failed: SW=6282"), want: RecoveryClassEmptyEF},
		{name: "wrong length status", err: errors.New("AT+CSIM response status=6700"), want: RecoveryClassMalformedReply},
		{name: "numeric cme sim busy", err: errors.New("AT CME ERROR: 14"), want: RecoveryClassSIMBusy},
		{name: "sim busy", err: errors.New("AT CME ERROR: SIM busy"), want: RecoveryClassSIMBusy},
		{name: "empty ef", err: errors.New("ISIM identity data empty"), want: RecoveryClassEmptyEF},
		{name: "malformed apdu", err: errors.New("APDU response too short: 1"), want: RecoveryClassMalformedReply},
		{name: "unknown", err: errors.New("permanent profile error"), want: RecoveryClassNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyError(tt.err); got != tt.want {
				t.Fatalf("ClassifyError() = %q, want %q", got, tt.want)
			}
		})
	}
}

type statusErrorForTest struct {
	status uint16
}

func (e statusErrorForTest) Error() string {
	return "status-bearing error"
}

func (e statusErrorForTest) Status() uint16 {
	return e.status
}

type timeoutErrorForTest struct{}

func (e timeoutErrorForTest) Error() string {
	return "read failed"
}

func (e timeoutErrorForTest) Timeout() bool {
	return true
}

func TestClassifyRecoveryErrorFromStatusCarrier(t *testing.T) {
	err := errors.Join(errors.New("logical-channel ISIM identity"), statusErrorForTest{status: 0x6F00})
	if got := ClassifyError(err); got != RecoveryClassSIMBusy {
		t.Fatalf("ClassifyError(status carrier) = %q, want SIM busy", got)
	}
}

func TestClassifyRecoveryErrorFromTimeoutCarrier(t *testing.T) {
	if got := ClassifyError(timeoutErrorForTest{}); got != RecoveryClassControlPortHung {
		t.Fatalf("ClassifyError(timeout carrier) = %q, want control port hung", got)
	}
}

func TestStatusStringRecoveryClass(t *testing.T) {
	tests := []struct {
		status string
		want   RecoveryClass
	}{
		{status: "9000", want: RecoveryClassNone},
		{status: "6a82", want: RecoveryClassFileNotFound},
		{status: "0x6A83", want: RecoveryClassFileNotFound},
		{status: "9404", want: RecoveryClassFileNotFound},
		{status: "6282", want: RecoveryClassEmptyEF},
		{status: "9300", want: RecoveryClassSIMBusy},
		{status: "6283", want: RecoveryClassSIMBusy},
		{status: "6400", want: RecoveryClassSIMBusy},
		{status: "6F00", want: RecoveryClassSIMBusy},
		{status: "6102", want: RecoveryClassMalformedReply},
		{status: "9F02", want: RecoveryClassMalformedReply},
		{status: "6C10", want: RecoveryClassMalformedReply},
		{status: "6A86", want: RecoveryClassMalformedReply},
		{status: "not-status", want: RecoveryClassNone},
	}

	for _, tt := range tests {
		if got := StatusStringRecoveryClass(tt.status); got != tt.want {
			t.Fatalf("StatusStringRecoveryClass(%q) = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestResultRecoveryClass(t *testing.T) {
	if got := (CRSMResult{SW1: 0x6A, SW2: 0x82}).RecoveryClass(); got != RecoveryClassFileNotFound {
		t.Fatalf("CRSM 6A82 recovery class = %q, want file missing", got)
	}
	if got := (APDUResult{SW1: 0x93, SW2: 0x00}).RecoveryClass(); got != RecoveryClassSIMBusy {
		t.Fatalf("APDU 9300 recovery class = %q, want SIM busy", got)
	}
	if got := (CRSMResult{SW1: 0x90, SW2: 0x00}).RecoveryClass(); got != RecoveryClassNone {
		t.Fatalf("CRSM 9000 recovery class = %q, want none", got)
	}
}

func TestAPDUStatusRecoveryPlan(t *testing.T) {
	plan := PlanAPDUStatusRecovery(0x6C, 0x00)
	if plan.Action != APDURecoveryCorrectLe || plan.Le != 256 || !plan.Recoverable() {
		t.Fatalf("6C00 plan=%+v", plan)
	}
	leByte, err := plan.LeByte()
	if err != nil {
		t.Fatalf("LeByte() error = %v", err)
	}
	if leByte != 0x00 {
		t.Fatalf("LeByte() = 0x%02X, want 0", leByte)
	}

	plan = PlanAPDUStatusRecovery(0x61, 0x02)
	if plan.Action != APDURecoveryGetResponse || plan.Le != 2 {
		t.Fatalf("6102 plan=%+v", plan)
	}

	plan = PlanAPDUStatusRecovery(0x9F, 0x02)
	if plan.Action != APDURecoveryGetResponse || plan.Le != 2 {
		t.Fatalf("9F02 plan=%+v", plan)
	}

	plan = PlanAPDUStatusRecovery(0x90, 0x00)
	if plan.Recoverable() {
		t.Fatalf("9000 plan=%+v, want not recoverable", plan)
	}
}

func TestATControlRecoveryPlan(t *testing.T) {
	tests := []struct {
		name    string
		class   RecoveryClass
		attempt int
		want    []ATRecoveryStep
	}{
		{
			name:    "control port first attempt uses cfun cycle",
			class:   RecoveryClassControlPortHung,
			attempt: -1,
			want: []ATRecoveryStep{
				{Command: "AT+CFUN=0", Timeout: 5 * time.Second, DelayAfter: 2 * time.Second, ContinueOnError: true},
				{Command: "AT+CFUN=1", Timeout: 10 * time.Second, DelayAfter: 5 * time.Second},
			},
		},
		{
			name:    "at error second attempt restarts modem",
			class:   RecoveryClassATError,
			attempt: 1,
			want: []ATRecoveryStep{
				{Command: "AT+CFUN=1,1", Timeout: 10 * time.Second, DelayAfter: 20 * time.Second},
			},
		},
		{
			name:    "later attempts use vendor reset",
			class:   RecoveryClassControlPortHung,
			attempt: 2,
			want: []ATRecoveryStep{
				{Command: "AT!RESET", Timeout: 10 * time.Second, DelayAfter: 30 * time.Second, VendorSpecific: true},
			},
		},
		{
			name:    "non control class has no reset plan",
			class:   RecoveryClassFileNotFound,
			attempt: 0,
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PlanATControlRecovery(tt.class, tt.attempt)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("PlanATControlRecovery() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestAPDURecoveryCommands(t *testing.T) {
	apdu := []byte{0x00, 0xB0, 0x00, 0x00, 0x00}
	corrected, err := CorrectAPDULe(apdu, 3)
	if err != nil {
		t.Fatalf("CorrectAPDULe() error = %v", err)
	}
	if !reflect.DeepEqual(corrected, []byte{0x00, 0xB0, 0x00, 0x00, 0x03}) {
		t.Fatalf("corrected APDU=% X", corrected)
	}
	if apdu[4] != 0x00 {
		t.Fatalf("CorrectAPDULe mutated input: % X", apdu)
	}

	withLe, err := CorrectAPDULe([]byte{0x00, 0x84, 0x00, 0x00}, 256)
	if err != nil {
		t.Fatalf("CorrectAPDULe(no Le) error = %v", err)
	}
	if !reflect.DeepEqual(withLe, []byte{0x00, 0x84, 0x00, 0x00, 0x00}) {
		t.Fatalf("APDU with Le=% X", withLe)
	}

	dataOnly, err := CorrectAPDULe([]byte{0x00, 0x88, 0x00, 0x81, 0x02, 0xAA, 0xBB}, 3)
	if err != nil {
		t.Fatalf("CorrectAPDULe(data only) error = %v", err)
	}
	if !reflect.DeepEqual(dataOnly, []byte{0x00, 0x88, 0x00, 0x81, 0x02, 0xAA, 0xBB, 0x03}) {
		t.Fatalf("data-only APDU with Le=% X", dataOnly)
	}

	dataWithLe, err := CorrectAPDULe([]byte{0x00, 0x88, 0x00, 0x81, 0x02, 0xAA, 0xBB, 0x00}, 3)
	if err != nil {
		t.Fatalf("CorrectAPDULe(data with Le) error = %v", err)
	}
	if !reflect.DeepEqual(dataWithLe, []byte{0x00, 0x88, 0x00, 0x81, 0x02, 0xAA, 0xBB, 0x03}) {
		t.Fatalf("data APDU corrected Le=% X", dataWithLe)
	}

	extendedLeOnly, err := CorrectAPDULe([]byte{0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00}, 3)
	if err != nil {
		t.Fatalf("CorrectAPDULe(extended Le-only) error = %v", err)
	}
	if !reflect.DeepEqual(extendedLeOnly, []byte{0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x03}) {
		t.Fatalf("extended Le-only APDU=% X", extendedLeOnly)
	}

	extendedDataOnly, err := CorrectAPDULe([]byte{0x00, 0x88, 0x00, 0x81, 0x00, 0x00, 0x02, 0xAA, 0xBB}, 3)
	if err != nil {
		t.Fatalf("CorrectAPDULe(extended data only) error = %v", err)
	}
	if !reflect.DeepEqual(extendedDataOnly, []byte{0x00, 0x88, 0x00, 0x81, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0x00, 0x03}) {
		t.Fatalf("extended data-only APDU with Le=% X", extendedDataOnly)
	}

	extendedDataWithLe, err := CorrectAPDULe([]byte{0x00, 0x88, 0x00, 0x81, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0x00, 0x00}, 256)
	if err != nil {
		t.Fatalf("CorrectAPDULe(extended data with Le) error = %v", err)
	}
	if !reflect.DeepEqual(extendedDataWithLe, []byte{0x00, 0x88, 0x00, 0x81, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0x01, 0x00}) {
		t.Fatalf("extended data APDU corrected Le=% X", extendedDataWithLe)
	}

	getResponse, err := GetResponseAPDU(2)
	if err != nil {
		t.Fatalf("GetResponseAPDU() error = %v", err)
	}
	if !reflect.DeepEqual(getResponse, []byte{0x00, 0xC0, 0x00, 0x00, 0x02}) {
		t.Fatalf("GET RESPONSE APDU=% X", getResponse)
	}
	simGetResponse, err := GetResponseAPDUWithCLA(0xA0, 2)
	if err != nil {
		t.Fatalf("GetResponseAPDUWithCLA() error = %v", err)
	}
	if !reflect.DeepEqual(simGetResponse, []byte{0xA0, 0xC0, 0x00, 0x00, 0x02}) {
		t.Fatalf("SIM GET RESPONSE APDU=% X", simGetResponse)
	}
	if _, err := GetResponseAPDU(0); err == nil {
		t.Fatal("GetResponseAPDU(0) err=nil, want error")
	}
	if _, err := CorrectAPDULe([]byte{0x00, 0x88, 0x00, 0x81, 0x00, 0xAA}, 1); err == nil {
		t.Fatal("CorrectAPDULe(malformed extended APDU) err=nil, want error")
	}
}
