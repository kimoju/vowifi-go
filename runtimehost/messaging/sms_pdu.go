package messaging

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

const IMS3GPPSMSContentType = "application/vnd.3gpp.sms"

func BuildSMSSubmitTPDU(to string, part SMSPart, mr byte) ([]byte, error) {
	number := normalizeSMSNumber(to)
	if number == "" {
		return nil, errors.New("sms destination address is empty")
	}
	digits, toa, bcd, err := encodeSMSAddress(number)
	if err != nil {
		return nil, err
	}
	encoding := normalizeEncoding(part.Text, part.Encoding)
	udh := append([]byte(nil), part.UDH...)
	firstOctet := byte(0x01)
	if len(udh) > 0 {
		firstOctet |= 0x40
	}
	userData, udl, dcs, err := encodeSMSUserData(part.Text, encoding, udh)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 7+len(bcd)+len(userData))
	out = append(out, firstOctet, mr, byte(digits), toa)
	out = append(out, bcd...)
	out = append(out, 0x00, dcs, byte(udl))
	out = append(out, userData...)
	return out, nil
}

func BuildSMSRPData(rpMR byte, smsc string, tpdu []byte) ([]byte, error) {
	if len(tpdu) > 255 {
		return nil, fmt.Errorf("SMS TPDU too long: %d", len(tpdu))
	}
	rpDA, err := encodeRPAddress(smsc)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 4+len(rpDA)+len(tpdu))
	out = append(out, 0x00, rpMR, 0x00)
	out = append(out, rpDA...)
	out = append(out, byte(len(tpdu)))
	out = append(out, tpdu...)
	return out, nil
}

func ParseSMSRPData(body []byte) (rpMR byte, tpdu []byte, err error) {
	if len(body) < 5 {
		return 0, nil, errors.New("RP-DATA too short")
	}
	if body[0] != 0x00 && body[0] != 0x01 {
		return 0, nil, fmt.Errorf("not RP-DATA: 0x%02x", body[0])
	}
	i := 1
	rpMR = body[i]
	i++
	if i >= len(body) {
		return 0, nil, errors.New("RP originator address missing")
	}
	oaLen := int(body[i])
	i++
	if i+oaLen > len(body) {
		return 0, nil, errors.New("RP originator address truncated")
	}
	i += oaLen
	if i >= len(body) {
		return 0, nil, errors.New("RP destination address missing")
	}
	daLen := int(body[i])
	i++
	if i+daLen > len(body) {
		return 0, nil, errors.New("RP destination address truncated")
	}
	i += daLen
	if i >= len(body) {
		return 0, nil, errors.New("RP user data missing")
	}
	udLen := int(body[i])
	i++
	if i+udLen > len(body) {
		return 0, nil, errors.New("RP user data truncated")
	}
	return rpMR, append([]byte(nil), body[i:i+udLen]...), nil
}

func encodeSMSUserData(text, encoding string, udh []byte) ([]byte, int, byte, error) {
	switch encoding {
	case "gsm7":
		septets, err := encodeGSM7(text)
		if err != nil {
			return nil, 0, 0, err
		}
		userData := append([]byte(nil), udh...)
		fillBits := 0
		if len(udh) > 0 {
			fillBits = (7 - ((len(udh) * 8) % 7)) % 7
		}
		userData = append(userData, packSeptets(septets, fillBits)...)
		udl := len(septets)
		if len(udh) > 0 {
			udl += (len(udh)*8 + 6) / 7
		}
		return userData, udl, 0x00, nil
	case "utf8":
		userData := append([]byte(nil), udh...)
		userData = append(userData, []byte(text)...)
		return userData, len(userData), 0x04, nil
	default:
		userData := append([]byte(nil), udh...)
		for _, unit := range utf16.Encode([]rune(text)) {
			userData = append(userData, byte(unit>>8), byte(unit))
		}
		return userData, len(userData), 0x08, nil
	}
}

func encodeGSM7(text string) ([]byte, error) {
	out := make([]byte, 0, len(text))
	for _, r := range text {
		idx := gsm7Code(r)
		if idx < 0 {
			return nil, fmt.Errorf("character %q is not in GSM 7-bit alphabet", r)
		}
		out = append(out, byte(idx))
	}
	return out, nil
}

func gsm7Code(r rune) int {
	for i, candidate := range gsm7BasicAlphabet {
		if candidate == r {
			return i
		}
	}
	return -1
}

var gsm7BasicAlphabet = []rune{
	'@', '£', '$', '¥', 'è', 'é', 'ù', 'ì',
	'ò', 'Ç', '\n', 'Ø', 'ø', '\r', 'Å', 'å',
	'Δ', '_', 'Φ', 'Γ', 'Λ', 'Ω', 'Π', 'Ψ',
	'Σ', 'Θ', 'Ξ', '\x1b', 'Æ', 'æ', 'ß', 'É',
	' ', '!', '"', '#', '¤', '%', '&', '\'',
	'(', ')', '*', '+', ',', '-', '.', '/',
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', ':', ';', '<', '=', '>', '?',
	'¡', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
	'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
	'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
	'X', 'Y', 'Z', 'Ä', 'Ö', 'Ñ', 'Ü', '§',
	'¿', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
	'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
	'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
	'x', 'y', 'z', 'ä', 'ö', 'ñ', 'ü', 'à',
}

func packSeptets(septets []byte, bitOffset int) []byte {
	if len(septets) == 0 {
		return nil
	}
	totalBits := bitOffset + len(septets)*7
	out := make([]byte, (totalBits+7)/8)
	for i, septet := range septets {
		bitPos := bitOffset + i*7
		bytePos := bitPos / 8
		shift := bitPos % 8
		out[bytePos] |= (septet & 0x7f) << shift
		if shift > 1 && bytePos+1 < len(out) {
			out[bytePos+1] |= (septet & 0x7f) >> (8 - shift)
		}
	}
	return out
}

func encodeRPAddress(number string) ([]byte, error) {
	number = normalizeSMSNumber(number)
	if number == "" {
		return []byte{0x00}, nil
	}
	_, toa, bcd, err := encodeSMSAddress(number)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 2+len(bcd))
	out = append(out, byte(1+len(bcd)), toa)
	out = append(out, bcd...)
	return out, nil
}

func encodeSMSAddress(number string) (digits int, toa byte, bcd []byte, err error) {
	number = normalizeSMSNumber(number)
	if number == "" {
		return 0, 0, nil, errors.New("sms address is empty")
	}
	toa = 0x81
	if strings.HasPrefix(number, "+") {
		toa = 0x91
		number = strings.TrimPrefix(number, "+")
	}
	if number == "" {
		return 0, 0, nil, errors.New("sms address has no digits")
	}
	for _, r := range number {
		if r < '0' || r > '9' {
			return 0, 0, nil, fmt.Errorf("sms address contains non-digit %q", r)
		}
	}
	digits = len(number)
	bcd = make([]byte, (digits+1)/2)
	for i := 0; i < digits; i++ {
		d := number[i] - '0'
		if i%2 == 0 {
			bcd[i/2] |= d
		} else {
			bcd[i/2] |= d << 4
		}
	}
	if digits%2 != 0 {
		bcd[digits/2] |= 0xf0
	}
	return digits, toa, bcd, nil
}

func normalizeSMSNumber(value string) string {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") {
		if _, rest, ok := strings.Cut(value, ":"); ok {
			value = rest
		}
		if user, _, ok := strings.Cut(value, "@"); ok {
			value = user
		}
	}
	if strings.HasPrefix(strings.ToLower(value), "tel:") {
		value = strings.TrimSpace(value[4:])
	}
	if semi := strings.IndexByte(value, ';'); semi >= 0 {
		value = value[:semi]
	}
	value = strings.Trim(value, "<>")
	var b strings.Builder
	for i, r := range value {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '+' && i == 0:
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '(' || r == ')':
			continue
		default:
			return strings.TrimSpace(value)
		}
	}
	return b.String()
}
