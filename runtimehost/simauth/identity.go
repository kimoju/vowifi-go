package simauth

import (
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/kimoju/vowifi-go/runtimehost/carrier"
)

const (
	// EAPAKAPermanentIdentityPrefix is the permanent username prefix for EAP-AKA.
	EAPAKAPermanentIdentityPrefix byte = '0'
	// EAPAKAPrimePermanentIdentityPrefix is the permanent username prefix for EAP-AKA'.
	EAPAKAPrimePermanentIdentityPrefix byte = '6'
)

// EAPAKAPermanentIdentity contains the parsed permanent EAP-AKA NAI fields.
type EAPAKAPermanentIdentity struct {
	Prefix byte
	IMSI   string
	MCC    string
	MNC    string
	Realm  string
}

// FormatEAPAKAPermanentIdentity formats an EAP-AKA permanent NAI.
func FormatEAPAKAPermanentIdentity(imsi, mcc, mnc string) (string, error) {
	return formatEAPAKAPermanentIdentity(EAPAKAPermanentIdentityPrefix, imsi, mcc, mnc, nil)
}

// FormatEAPAKAPermanentIdentityWithAD formats an EAP-AKA permanent NAI using EF_AD when MNC is omitted.
func FormatEAPAKAPermanentIdentityWithAD(imsi, mcc, mnc string, efAD []byte) (string, error) {
	return formatEAPAKAPermanentIdentity(EAPAKAPermanentIdentityPrefix, imsi, mcc, mnc, efAD)
}

// FormatEAPAKAPrimePermanentIdentity formats an EAP-AKA' permanent NAI.
func FormatEAPAKAPrimePermanentIdentity(imsi, mcc, mnc string) (string, error) {
	return formatEAPAKAPermanentIdentity(EAPAKAPrimePermanentIdentityPrefix, imsi, mcc, mnc, nil)
}

// FormatEAPAKAPrimePermanentIdentityWithAD formats an EAP-AKA' permanent NAI using EF_AD when MNC is omitted.
func FormatEAPAKAPrimePermanentIdentityWithAD(imsi, mcc, mnc string, efAD []byte) (string, error) {
	return formatEAPAKAPermanentIdentity(EAPAKAPrimePermanentIdentityPrefix, imsi, mcc, mnc, efAD)
}

// ParseEAPAKAPermanentIdentity parses an EAP-AKA or EAP-AKA' permanent NAI.
func ParseEAPAKAPermanentIdentity(identity string) (EAPAKAPermanentIdentity, error) {
	identity = strings.TrimSpace(identity)
	user, realm, ok := strings.Cut(identity, "@")
	if !ok || user == "" || realm == "" {
		return EAPAKAPermanentIdentity{}, fmt.Errorf("EAP-AKA identity must be user@realm")
	}
	if len(user) < 2 {
		return EAPAKAPermanentIdentity{}, fmt.Errorf("EAP-AKA identity user is too short")
	}
	prefix := user[0]
	if prefix != EAPAKAPermanentIdentityPrefix && prefix != EAPAKAPrimePermanentIdentityPrefix {
		return EAPAKAPermanentIdentity{}, fmt.Errorf("unsupported EAP-AKA identity prefix %q", prefix)
	}
	imsi := user[1:]
	if err := validateDecimalDigits("IMSI", imsi, 5, 15); err != nil {
		return EAPAKAPermanentIdentity{}, err
	}
	mcc, realmMNC, normalizedRealm, err := parseEAPAKARealm(realm)
	if err != nil {
		return EAPAKAPermanentIdentity{}, err
	}
	mnc, err := inferNAIMNCFromIMSI(imsi, mcc, realmMNC)
	if err != nil {
		return EAPAKAPermanentIdentity{}, err
	}
	return EAPAKAPermanentIdentity{
		Prefix: prefix,
		IMSI:   imsi,
		MCC:    mcc,
		MNC:    mnc,
		Realm:  normalizedRealm,
	}, nil
}

// DecodeISIMIdentityString decodes EF_IMPI, EF_IMPU, and EF_DOMAIN string data.
func DecodeISIMIdentityString(raw []byte) string {
	data := trimTLVPadding(raw)
	if len(data) == 0 {
		return ""
	}
	if data[0] == 0x80 {
		v, ok := decodeISIMDataObject(data[1:])
		if !ok {
			return ""
		}
		return decodeISIMTextValue(v)
	}
	if v, ok := FindTLV(data, 0x80); ok {
		return decodeISIMTextValue(v)
	}
	return decodeISIMStringValue(data)
}

// EncodeISIMIdentityString encodes EF_IMPI, EF_IMPU, and EF_DOMAIN text as
// the tag 0x80 data object used by ISIM identity elementary files.
func EncodeISIMIdentityString(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("ISIM identity string is empty")
	}
	return EncodeTLV(0x80, []byte(value))
}

// PadISIMIdentityRecord pads an encoded ISIM identity data object for an
// EF_IMPU-style linear fixed record.
func PadISIMIdentityRecord(encoded []byte, recordLength int) ([]byte, error) {
	if recordLength <= 0 {
		return nil, fmt.Errorf("ISIM record length must be positive: %d", recordLength)
	}
	if len(encoded) > recordLength {
		return nil, fmt.Errorf("ISIM record length %d is too small for %d encoded byte(s)", recordLength, len(encoded))
	}
	out := make([]byte, recordLength)
	copy(out, encoded)
	for i := len(encoded); i < len(out); i++ {
		out[i] = 0xFF
	}
	return out, nil
}

// DecodeUSIMIMSI decodes the transparent EF_IMSI mobile-identity payload.
func DecodeUSIMIMSI(raw []byte) (string, error) {
	if len(trimEFPadding(raw)) == 0 {
		return "", fmt.Errorf("EF_IMSI data empty")
	}
	data := trimTrailingFF(raw)
	length := int(data[0])
	if length <= 0 {
		return "", fmt.Errorf("EF_IMSI length is zero")
	}
	if len(data)-1 < length {
		return "", fmt.Errorf("EF_IMSI length %d exceeds remaining %d", length, len(data)-1)
	}
	mobileID := data[1 : 1+length]
	if len(mobileID) == 0 {
		return "", fmt.Errorf("EF_IMSI mobile identity empty")
	}
	if mobileID[0]&0x07 != 0x01 {
		return "", fmt.Errorf("EF_IMSI mobile identity type is 0x%X, want IMSI", mobileID[0]&0x07)
	}
	oddDigits := mobileID[0]&0x08 != 0
	digits := make([]byte, 0, 1+2*(len(mobileID)-1))
	if !appendBCDDigit(&digits, mobileID[0]>>4) {
		return "", fmt.Errorf("EF_IMSI digit 1 is not BCD")
	}
	for i, b := range mobileID[1:] {
		if !appendBCDDigit(&digits, b&0x0F) {
			return "", fmt.Errorf("EF_IMSI digit %d is not BCD", len(digits)+1)
		}
		hi := b >> 4
		last := i == len(mobileID[1:])-1
		if last && !oddDigits {
			if hi != 0x0F {
				return "", fmt.Errorf("EF_IMSI even-length filler is 0x%X, want 0xF", hi)
			}
			continue
		}
		if !appendBCDDigit(&digits, hi) {
			return "", fmt.Errorf("EF_IMSI digit %d is not BCD", len(digits)+1)
		}
	}
	if oddDigits && len(digits)%2 == 0 {
		return "", fmt.Errorf("EF_IMSI odd/even indicator does not match %d digits", len(digits))
	}
	if !oddDigits && len(digits)%2 != 0 {
		return "", fmt.Errorf("EF_IMSI odd/even indicator does not match %d digits", len(digits))
	}
	return string(digits), nil
}

// EncodeUSIMIMSI encodes an IMSI for the transparent EF_IMSI mobile-identity
// payload.
func EncodeUSIMIMSI(imsi string) ([]byte, error) {
	imsi = strings.TrimSpace(imsi)
	if err := validateDecimalDigits("IMSI", imsi, 5, 15); err != nil {
		return nil, err
	}

	mobileIdentityLength := 1 + len(imsi)/2
	out := make([]byte, 1+mobileIdentityLength)
	out[0] = byte(mobileIdentityLength)
	out[1] = ((imsi[0] - '0') << 4) | 0x01
	if len(imsi)%2 != 0 {
		out[1] |= 0x08
	}

	offset := 2
	for i := 1; i < len(imsi); i += 2 {
		lo := imsi[i] - '0'
		hi := byte(0x0F)
		if i+1 < len(imsi) {
			hi = imsi[i+1] - '0'
		}
		out[offset] = lo | (hi << 4)
		offset++
	}
	return out, nil
}

// MNCLengthFromAD returns the MNC length advertised in USIM EF_AD byte 4.
func MNCLengthFromAD(ad []byte) (int, bool) {
	if len(ad) < 4 {
		return 0, false
	}
	mncLen := int(ad[3] & 0x0F)
	if mncLen != 2 && mncLen != 3 {
		return 0, false
	}
	return mncLen, true
}

func formatEAPAKAPermanentIdentity(prefix byte, imsi, mcc, mnc string, efAD []byte) (string, error) {
	imsi, mcc, mnc, realm, err := normalizeEAPAKAIdentityParts(imsi, mcc, mnc, efAD)
	if err != nil {
		return "", err
	}
	return string([]byte{prefix}) + imsi + "@" + realm, nil
}

func normalizeEAPAKAIdentityParts(imsi, mcc, mnc string, efAD []byte) (string, string, string, string, error) {
	imsi = strings.TrimSpace(imsi)
	mcc = strings.TrimSpace(mcc)
	mnc = strings.TrimSpace(mnc)
	if err := validateDecimalDigits("IMSI", imsi, 5, 15); err != nil {
		return "", "", "", "", err
	}
	if mcc == "" || mnc == "" {
		derivedMCC, derivedMNC := carrier.DerivePLMNFromIMSIWithAD(imsi, efAD)
		if mcc == "" {
			mcc = derivedMCC
		}
		if mnc == "" {
			mnc = derivedMNC
		}
	}
	if err := validateDecimalDigits("MCC", mcc, 3, 3); err != nil {
		return "", "", "", "", err
	}
	if err := validateDecimalDigits("MNC", mnc, 2, 3); err != nil {
		return "", "", "", "", err
	}
	if err := validateIMSIPLMN(imsi, mcc, mnc); err != nil {
		return "", "", "", "", err
	}
	return imsi, mcc, mnc, eapAKARealm(mcc, mnc), nil
}

func parseEAPAKARealm(realm string) (string, string, string, error) {
	normalized := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(realm)), ".")
	parts := strings.Split(normalized, ".")
	if len(parts) != 5 ||
		parts[0] != "wlan" ||
		!strings.HasPrefix(parts[1], "mnc") ||
		!strings.HasPrefix(parts[2], "mcc") ||
		parts[3] != "3gppnetwork" ||
		parts[4] != "org" {
		return "", "", "", fmt.Errorf("EAP-AKA realm must be wlan.mncXXX.mccXXX.3gppnetwork.org")
	}
	mnc := strings.TrimPrefix(parts[1], "mnc")
	mcc := strings.TrimPrefix(parts[2], "mcc")
	if err := validateDecimalDigits("MCC", mcc, 3, 3); err != nil {
		return "", "", "", err
	}
	if err := validateDecimalDigits("realm MNC", mnc, 3, 3); err != nil {
		return "", "", "", err
	}
	return mcc, mnc, normalized, nil
}

func inferNAIMNCFromIMSI(imsi, mcc, realmMNC string) (string, error) {
	if !strings.HasPrefix(imsi, mcc) {
		return "", fmt.Errorf("IMSI does not match MCC %s", mcc)
	}
	rest := imsi[len(mcc):]
	if strings.HasPrefix(rest, realmMNC) {
		return realmMNC, nil
	}
	if strings.HasPrefix(realmMNC, "0") && strings.HasPrefix(rest, realmMNC[1:]) {
		return realmMNC[1:], nil
	}
	return "", fmt.Errorf("IMSI does not match MNC %s", realmMNC)
}

func validateIMSIPLMN(imsi, mcc, mnc string) error {
	if !strings.HasPrefix(imsi, mcc) {
		return fmt.Errorf("IMSI does not match MCC %s", mcc)
	}
	rest := imsi[len(mcc):]
	if !strings.HasPrefix(rest, mnc) {
		return fmt.Errorf("IMSI does not match MNC %s", mnc)
	}
	return nil
}

func eapAKARealm(mcc, mnc string) string {
	if len(mnc) == 2 {
		mnc = "0" + mnc
	}
	return fmt.Sprintf("wlan.mnc%s.mcc%s.3gppnetwork.org", mnc, mcc)
}

func validateDecimalDigits(name, value string, minLen, maxLen int) error {
	if len(value) < minLen || len(value) > maxLen {
		return fmt.Errorf("%s length must be %d..%d digits: %d", name, minLen, maxLen, len(value))
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return fmt.Errorf("%s contains non-decimal digit", name)
		}
	}
	return nil
}

func decodeISIMDataObject(data []byte) ([]byte, bool) {
	l, rest, ok := readSIMStringLength(data)
	if !ok || len(rest) < l {
		return nil, false
	}
	return rest[:l], true
}

func decodeISIMStringValue(data []byte) string {
	data = trimTLVPadding(data)
	if len(data) == 0 {
		return ""
	}
	if l, rest, ok := readSIMStringLength(data); ok && l > 0 && len(rest) >= l && len(trimEFPadding(rest[l:])) == 0 {
		if isLikelyISIMLengthPrefix(data[0], rest[:l]) {
			if s := decodeISIMTextValue(rest[:l]); s != "" {
				return s
			}
		}
	}
	return decodeISIMTextValue(data)
}

func isLikelyISIMLengthPrefix(first byte, payload []byte) bool {
	if first < 0x20 || first > 0x7E {
		return true
	}
	lower := strings.ToLower(string(payload))
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") || strings.HasPrefix(lower, "tel:") || strings.HasPrefix(lower, "urn:") {
		return true
	}
	isIdentStart := (first >= '0' && first <= '9') ||
		(first >= 'A' && first <= 'Z') ||
		(first >= 'a' && first <= 'z') ||
		first == '+'
	return !isIdentStart
}

func decodeISIMTextValue(data []byte) string {
	data = trimEFPadding(data)
	if len(data) == 0 || !utf8.Valid(data) {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readSIMStringLength(data []byte) (int, []byte, bool) {
	if len(data) == 0 {
		return 0, nil, false
	}
	first := data[0]
	data = data[1:]
	if first&0x80 == 0 {
		return int(first), data, true
	}
	n := int(first & 0x7F)
	if n == 0 || n > 4 || len(data) < n {
		return 0, nil, false
	}
	length := 0
	for _, part := range data[:n] {
		if length > (math.MaxInt-int(part))/256 {
			return 0, nil, false
		}
		length = (length << 8) | int(part)
	}
	return length, data[n:], true
}

func trimEFPadding(data []byte) []byte {
	start := 0
	for start < len(data) && (data[start] == 0x00 || data[start] == 0xFF) {
		start++
	}
	end := len(data)
	for end > start && (data[end-1] == 0x00 || data[end-1] == 0xFF) {
		end--
	}
	return data[start:end]
}

func trimTrailingFF(data []byte) []byte {
	end := len(data)
	for end > 0 && data[end-1] == 0xFF {
		end--
	}
	return data[:end]
}

func appendBCDDigit(out *[]byte, nibble byte) bool {
	if nibble > 9 {
		return false
	}
	*out = append(*out, '0'+nibble)
	return true
}

// DecodeUSIMSMSP decodes the TS-Service Centre Address (SMSC) from a USIM
// EF_SMSP (0x6F42, 3GPP TS 31.102 §4.2.25) linear-fixed record.
func DecodeUSIMSMSP(raw []byte) (string, error) {
	if len(raw) < 28 {
		return "", fmt.Errorf("EF_SMSP record too short: %d bytes", len(raw))
	}
	params := raw[len(raw)-28:]
	// Bit 1 (0x02) == 0 means TS-Service Centre Address is present.
	if params[0]&0x02 != 0 {
		return "", fmt.Errorf("EF_SMSP service centre address marked absent")
	}
	sca := params[13:25]
	addrLen := int(sca[0])
	if addrLen <= 1 || addrLen > 11 || addrLen == 0xFF {
		return "", fmt.Errorf("EF_SMSP service centre address length invalid: %d", addrLen)
	}
	toa := sca[1]
	bcd := sca[2 : 1+addrLen]
	var out strings.Builder
	if toa&0x70 == 0x10 {
		out.WriteByte('+')
	}
	digits := 0
	for _, octet := range bcd {
		for _, nibble := range []byte{octet & 0x0F, (octet >> 4) & 0x0F} {
			if nibble == 0x0F {
				if digits == 0 {
					return "", fmt.Errorf("EF_SMSP service centre address has no digits")
				}
				return out.String(), nil
			}
			d, ok := decodeSMSPBCDDigit(nibble)
			if !ok {
				return "", fmt.Errorf("EF_SMSP invalid BCD nibble 0x%X", nibble)
			}
			out.WriteByte(d)
			digits++
		}
	}
	if digits == 0 {
		return "", fmt.Errorf("EF_SMSP service centre address has no digits")
	}
	return out.String(), nil
}

func decodeSMSPBCDDigit(nibble byte) (byte, bool) {
	switch {
	case nibble <= 9:
		return '0' + nibble, true
	case nibble == 0x0A:
		return '*', true
	case nibble == 0x0B:
		return '#', true
	case nibble == 0x0C:
		return 'a', true
	case nibble == 0x0D:
		return 'b', true
	case nibble == 0x0E:
		return 'c', true
	default:
		return 0, false
	}
}
