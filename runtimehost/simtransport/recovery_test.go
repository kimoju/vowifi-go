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
