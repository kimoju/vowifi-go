package simtransport

import (
	"context"
	"errors"
	"testing"
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

func TestClassifyRecoveryErrorFromStatusCarrier(t *testing.T) {
	err := errors.Join(errors.New("logical-channel ISIM identity"), statusErrorForTest{status: 0x6F00})
	if got := ClassifyError(err); got != RecoveryClassSIMBusy {
		t.Fatalf("ClassifyError(status carrier) = %q, want SIM busy", got)
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
