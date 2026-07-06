package simtransport

import (
	"context"
	"errors"
	"strings"
)

type RecoveryClass string

const (
	RecoveryClassNone            RecoveryClass = ""
	RecoveryClassControlPortHung RecoveryClass = "control_port_hung"
	RecoveryClassSIMBusy         RecoveryClass = "sim_busy"
	RecoveryClassFileNotFound    RecoveryClass = "file_not_found"
	RecoveryClassEmptyEF         RecoveryClass = "empty_ef"
	RecoveryClassMalformedReply  RecoveryClass = "malformed_reply"
	RecoveryClassATError         RecoveryClass = "at_error"
)

type recoveryClassifier interface {
	RecoveryClass() RecoveryClass
}

func (c RecoveryClass) Recoverable() bool {
	return c != RecoveryClassNone
}

func ClassifyError(err error) RecoveryClass {
	if err == nil {
		return RecoveryClassNone
	}
	var classifier recoveryClassifier
	if errors.As(err, &classifier) {
		if class := classifier.RecoveryClass(); class != RecoveryClassNone {
			return class
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return RecoveryClassControlPortHung
	}
	return classifyErrorText(err.Error())
}

func StatusRecoveryClass(sw1, sw2 byte) RecoveryClass {
	switch {
	case sw1 == 0x90 && sw2 == 0x00:
		return RecoveryClassNone
	case sw1 == 0x6A && (sw2 == 0x82 || sw2 == 0x83):
		return RecoveryClassFileNotFound
	case sw1 == 0x93 || (sw1 == 0x62 && sw2 == 0x83):
		return RecoveryClassSIMBusy
	default:
		return RecoveryClassNone
	}
}

func (r APDUResult) RecoveryClass() RecoveryClass {
	return StatusRecoveryClass(r.SW1, r.SW2)
}

func (r CRSMResult) RecoveryClass() RecoveryClass {
	return StatusRecoveryClass(r.SW1, r.SW2)
}

func classifyErrorText(text string) RecoveryClass {
	s := strings.ToLower(strings.TrimSpace(text))
	switch {
	case s == "":
		return RecoveryClassNone
	case strings.Contains(s, "isim identity data empty") ||
		strings.Contains(s, "empty ef") ||
		strings.Contains(s, "ef data empty"):
		return RecoveryClassEmptyEF
	case s == "6a82" ||
		s == "6a83" ||
		strings.Contains(s, "sw=6a82") ||
		strings.Contains(s, "sw=6a83") ||
		strings.Contains(s, "status=6a82") ||
		strings.Contains(s, "status=6a83") ||
		strings.Contains(s, " 6a82") ||
		strings.Contains(s, " 6a83"):
		return RecoveryClassFileNotFound
	case strings.Contains(s, "sim busy") ||
		strings.Contains(s, "apdu busy") ||
		strings.Contains(s, "sim is busy") ||
		strings.Contains(s, "resource busy"):
		return RecoveryClassSIMBusy
	case strings.Contains(s, "context deadline exceeded") ||
		strings.Contains(s, "timeout") ||
		strings.Contains(s, "timed out") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "no response") ||
		strings.Contains(s, "hang") ||
		strings.Contains(s, "hung") ||
		strings.Contains(s, "control port") ||
		strings.Contains(s, "parse ccho channel") ||
		strings.Contains(s, "parse crsm result") ||
		strings.Contains(s, "parse apdu response hex"):
		return RecoveryClassControlPortHung
	case strings.Contains(s, "invalid crsm data") ||
		strings.Contains(s, "invalid apdu response") ||
		strings.Contains(s, "apdu response too short"):
		return RecoveryClassMalformedReply
	case strings.Contains(s, "at cme error") ||
		strings.Contains(s, "at error"):
		return RecoveryClassATError
	default:
		return RecoveryClassNone
	}
}
