package simtransport

import (
	"context"
	"errors"
	"strconv"
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

type statusCarrier interface {
	Status() uint16
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
	var status statusCarrier
	if errors.As(err, &status) {
		if class := StatusUint16RecoveryClass(status.Status()); class != RecoveryClassNone {
			return class
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return RecoveryClassControlPortHung
	}
	return classifyErrorText(err.Error())
}

func StatusUint16RecoveryClass(status uint16) RecoveryClass {
	return StatusRecoveryClass(byte(status>>8), byte(status))
}

func StatusRecoveryClass(sw1, sw2 byte) RecoveryClass {
	switch {
	case sw1 == 0x90 && sw2 == 0x00:
		return RecoveryClassNone
	case isFileNotFoundStatus(sw1, sw2):
		return RecoveryClassFileNotFound
	case sw1 == 0x62 && sw2 == 0x82:
		return RecoveryClassEmptyEF
	case isSIMBusyStatus(sw1, sw2):
		return RecoveryClassSIMBusy
	case isMalformedAPDUStatus(sw1, sw2):
		return RecoveryClassMalformedReply
	default:
		return RecoveryClassNone
	}
}

func StatusStringRecoveryClass(status string) RecoveryClass {
	s := strings.TrimSpace(status)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(s) != 4 || !looksHex(s) {
		return RecoveryClassNone
	}
	n, err := strconv.ParseUint(s, 16, 16)
	if err != nil {
		return RecoveryClassNone
	}
	return StatusRecoveryClass(byte(n>>8), byte(n))
}

func (r APDUResult) RecoveryClass() RecoveryClass {
	return StatusRecoveryClass(r.SW1, r.SW2)
}

func (r CRSMResult) RecoveryClass() RecoveryClass {
	return StatusRecoveryClass(r.SW1, r.SW2)
}

func classifyErrorText(text string) RecoveryClass {
	s := strings.ToLower(strings.TrimSpace(text))
	statusClass := statusTextRecoveryClass(s)
	cmeClass := cmeErrorRecoveryClass(s)
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
	case statusClass != RecoveryClassNone:
		return statusClass
	case cmeClass != RecoveryClassNone:
		return cmeClass
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

func isFileNotFoundStatus(sw1, sw2 byte) bool {
	return (sw1 == 0x6A && (sw2 == 0x82 || sw2 == 0x83)) ||
		(sw2 == 0x6A && (sw1 == 0x82 || sw1 == 0x83)) ||
		(sw1 == 0x94 && (sw2 == 0x04 || sw2 == 0x08))
}

func isSIMBusyStatus(sw1, sw2 byte) bool {
	return sw1 == 0x93 ||
		(sw1 == 0x62 && sw2 == 0x83) ||
		(sw1 == 0x64 && sw2 == 0x00) ||
		sw1 == 0x65 ||
		(sw1 == 0x6F && sw2 == 0x00)
}

func isMalformedAPDUStatus(sw1, sw2 byte) bool {
	return sw1 == 0x67 ||
		sw1 == 0x6B ||
		sw1 == 0x6C ||
		sw1 == 0x6D ||
		sw1 == 0x6E ||
		(sw1 == 0x6A && sw2 == 0x86)
}

func cmeErrorRecoveryClass(text string) RecoveryClass {
	i := strings.Index(text, "at cme error:")
	if i < 0 {
		return RecoveryClassNone
	}
	detail := strings.TrimSpace(text[i+len("at cme error:"):])
	if detail == "" {
		return RecoveryClassATError
	}
	switch {
	case detail == "14" ||
		strings.Contains(detail, "sim busy") ||
		strings.Contains(detail, "busy") ||
		strings.Contains(detail, "temporarily not allowed"):
		return RecoveryClassSIMBusy
	default:
		return RecoveryClassATError
	}
}

func statusTextRecoveryClass(text string) RecoveryClass {
	for _, token := range strings.FieldsFunc(text, func(r rune) bool {
		return !('0' <= r && r <= '9' || 'a' <= r && r <= 'f' || 'A' <= r && r <= 'F')
	}) {
		if class := StatusStringRecoveryClass(token); class != RecoveryClassNone {
			return class
		}
	}
	return RecoveryClassNone
}
