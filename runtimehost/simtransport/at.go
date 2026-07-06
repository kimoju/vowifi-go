package simtransport

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const defaultTimeout = 10 * time.Second

var (
	hexTokenRE = regexp.MustCompile(`(?i)"([0-9a-f]+)"`)
	cmeErrorRE = regexp.MustCompile(`(?i)\+CME ERROR:\s*([^\r\n]+)`)
	cchoLineRE = regexp.MustCompile(`(?im)^\s*\+CCHO:\s*(\d+)\s*$`)
	intTokenRE = regexp.MustCompile(`[-+]?\d+`)
)

type ATCommander interface {
	ExecuteATSilent(cmd string, timeout time.Duration) (string, error)
}

type Adapter struct {
	Control ATCommander
	Timeout time.Duration
}

type APDUResult struct {
	Hex  string
	Body string
	SW1  byte
	SW2  byte
}

func (r APDUResult) Status() uint16 {
	return uint16(r.SW1)<<8 | uint16(r.SW2)
}

func (r APDUResult) StatusString() string {
	return fmt.Sprintf("%02X%02X", r.SW1, r.SW2)
}

func (r APDUResult) Success() bool {
	return r.SW1 == 0x90 && r.SW2 == 0x00
}

func NewAdapter(control ATCommander) *Adapter {
	return &Adapter{Control: control, Timeout: defaultTimeout}
}

func (a *Adapter) ExecuteATSilent(cmd string, timeout time.Duration) (string, error) {
	if a == nil || a.Control == nil {
		return "", errors.New("nil AT control")
	}
	return a.Control.ExecuteATSilent(cmd, timeout)
}

func (a *Adapter) OpenLogicalChannel(aid string) (int, error) {
	if a == nil || a.Control == nil {
		return 0, errors.New("nil AT control")
	}
	aid, err := normalizeHex(aid)
	if err != nil {
		return 0, fmt.Errorf("invalid AID: %w", err)
	}
	out, err := a.Control.ExecuteATSilent(`AT+CCHO="`+aid+`"`, a.timeout())
	if err != nil {
		return 0, err
	}
	if err := parseATError(out); err != nil {
		return 0, err
	}
	channel, ok := parseCCHOChannel(out)
	if !ok || channel < 0 {
		return 0, fmt.Errorf("parse CCHO channel from %q", compactAT(out))
	}
	return channel, nil
}

func (a *Adapter) CloseLogicalChannel(channel int) error {
	if a == nil || a.Control == nil {
		return errors.New("nil AT control")
	}
	if channel < 0 {
		return fmt.Errorf("invalid logical channel: %d", channel)
	}
	out, err := a.Control.ExecuteATSilent(fmt.Sprintf("AT+CCHC=%d", channel), a.timeout())
	if err != nil {
		return err
	}
	return parseATError(out)
}

func (a *Adapter) TransmitAPDU(channel int, hexAPDU string) (string, error) {
	if a == nil || a.Control == nil {
		return "", errors.New("nil AT control")
	}
	apdu, err := normalizeHex(hexAPDU)
	if err != nil {
		return "", fmt.Errorf("invalid APDU: %w", err)
	}
	var cmd string
	if channel > 0 {
		cmd = fmt.Sprintf(`AT+CGLA=%d,%d,"%s"`, channel, len(apdu), apdu)
	} else {
		cmd = fmt.Sprintf(`AT+CSIM=%d,"%s"`, len(apdu), apdu)
	}
	out, err := a.Control.ExecuteATSilent(cmd, a.timeout())
	if err != nil {
		return "", err
	}
	resp, err := ParseAPDUResult(out)
	if err != nil {
		return "", err
	}
	return resp.Hex, nil
}

func ParseAPDUResult(out string) (APDUResult, error) {
	if err := parseATError(out); err != nil {
		return APDUResult{}, err
	}
	hexOut, ok := extractResponseHex(out)
	if !ok {
		return APDUResult{}, fmt.Errorf("parse APDU response hex from %q", compactAT(out))
	}
	hexOut, err := normalizeHex(hexOut)
	if err != nil {
		return APDUResult{}, fmt.Errorf("invalid APDU response: %w", err)
	}
	if len(hexOut) < 4 {
		return APDUResult{}, fmt.Errorf("APDU response too short: %d hex chars", len(hexOut))
	}
	sw1, _ := strconv.ParseUint(hexOut[len(hexOut)-4:len(hexOut)-2], 16, 8)
	sw2, _ := strconv.ParseUint(hexOut[len(hexOut)-2:], 16, 8)
	return APDUResult{
		Hex:  hexOut,
		Body: hexOut[:len(hexOut)-4],
		SW1:  byte(sw1),
		SW2:  byte(sw2),
	}, nil
}

func (a *Adapter) timeout() time.Duration {
	if a.Timeout > 0 {
		return a.Timeout
	}
	return defaultTimeout
}

func parseATError(out string) error {
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return nil
	}
	if m := cmeErrorRE.FindStringSubmatch(trimmed); len(m) == 2 {
		return fmt.Errorf("AT CME ERROR: %s", strings.TrimSpace(m[1]))
	}
	for _, line := range strings.FieldsFunc(trimmed, func(r rune) bool { return r == '\r' || r == '\n' }) {
		if strings.EqualFold(strings.TrimSpace(line), "ERROR") {
			return errors.New("AT ERROR")
		}
	}
	return nil
}

func parseCCHOChannel(out string) (int, bool) {
	if m := cchoLineRE.FindStringSubmatch(out); len(m) == 2 {
		n, err := strconv.Atoi(m[1])
		return n, err == nil
	}
	return parseFirstInt(out)
}

func extractResponseHex(out string) (string, bool) {
	if m := hexTokenRE.FindAllStringSubmatch(out, -1); len(m) > 0 {
		return m[len(m)-1][1], true
	}
	for _, field := range strings.FieldsFunc(out, func(r rune) bool {
		return r == '\r' || r == '\n' || r == ',' || r == ':' || r == ' ' || r == '\t'
	}) {
		if looksHex(field) && len(field) >= 4 {
			return field, true
		}
	}
	return "", false
}

func parseFirstInt(out string) (int, bool) {
	token := intTokenRE.FindString(out)
	if token == "" {
		return 0, false
	}
	n, err := strconv.Atoi(token)
	return n, err == nil
}

func normalizeHex(in string) (string, error) {
	out := strings.ToUpper(strings.TrimSpace(in))
	if out == "" {
		return "", errors.New("empty hex")
	}
	if len(out)%2 != 0 {
		return "", errors.New("odd hex length")
	}
	if !looksHex(out) {
		return "", errors.New("non-hex character")
	}
	return out, nil
}

func looksHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' {
			continue
		}
		return false
	}
	return true
}

func compactAT(out string) string {
	return strings.Join(strings.Fields(out), " ")
}
