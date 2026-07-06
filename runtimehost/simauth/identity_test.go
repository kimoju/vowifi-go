package simauth

import (
	"reflect"
	"strings"
	"testing"
)

func TestDecodeISIMIdentityString(t *testing.T) {
	short := []byte{0x00, 0x80, 0x14}
	short = append(short, []byte("sip:user@ims.example")...)
	short = append(short, 0xFF)
	if got := DecodeISIMIdentityString(short); got != "sip:user@ims.example" {
		t.Fatalf("DecodeISIMIdentityString(short TLV) = %q", got)
	}

	longValue := strings.Repeat("a", 130) + "@private.example.test"
	longDO := append([]byte{0x80, 0x81, byte(len(longValue))}, []byte(longValue)...)
	wrapped := append([]byte{0xA0, 0x81, byte(len(longDO))}, longDO...)
	if got := DecodeISIMIdentityString(wrapped); got != longValue {
		t.Fatalf("DecodeISIMIdentityString(wrapped long TLV) length=%d, want %d", len(got), len(longValue))
	}

	plain := append([]byte{0x05}, []byte("hello")...)
	plain = append(plain, 0x00, 0xFF)
	if got := DecodeISIMIdentityString(plain); got != "hello" {
		t.Fatalf("DecodeISIMIdentityString(plain length) = %q", got)
	}
}

func TestDecodeUSIMIMSI(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{
			name: "odd digit count",
			raw:  []byte{0x08, 0x39, 0x01, 0x62, 0x10, 0x32, 0x54, 0x76, 0x98, 0xFF},
			want: "310260123456789",
		},
		{
			name: "significant trailing zero octet",
			raw:  []byte{0x08, 0x39, 0x01, 0x62, 0x10, 0x32, 0x54, 0x76, 0x00, 0xFF},
			want: "310260123456700",
		},
		{
			name: "even digit count",
			raw:  []byte{0x08, 0x01, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0xF8},
			want: "00101012345678",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeUSIMIMSI(tt.raw)
			if err != nil {
				t.Fatalf("DecodeUSIMIMSI() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("DecodeUSIMIMSI() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeUSIMIMSIRejectsMalformedEF(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "empty", raw: nil},
		{name: "length exceeds data", raw: []byte{0x09, 0x39, 0x01, 0x62, 0x10, 0x32, 0x54, 0x76, 0x98}},
		{name: "wrong identity type", raw: []byte{0x01, 0x38}},
		{name: "bad bcd digit", raw: []byte{0x02, 0x39, 0xFA}},
		{name: "bad even filler", raw: []byte{0x02, 0x31, 0x98}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := DecodeUSIMIMSI(tt.raw); err == nil {
				t.Fatalf("DecodeUSIMIMSI() = %q nil error, want error", got)
			}
		})
	}
}

func TestMNCLengthFromAD(t *testing.T) {
	if got, ok := MNCLengthFromAD([]byte{0x00, 0x00, 0x00, 0x03}); !ok || got != 3 {
		t.Fatalf("MNCLengthFromAD(3-digit) = %d/%v, want 3/true", got, ok)
	}
	if got, ok := MNCLengthFromAD([]byte{0x01, 0x02, 0x03, 0xF2}); !ok || got != 2 {
		t.Fatalf("MNCLengthFromAD(2-digit) = %d/%v, want 2/true", got, ok)
	}
	if got, ok := MNCLengthFromAD([]byte{0x00, 0x00, 0x00, 0x04}); ok || got != 0 {
		t.Fatalf("MNCLengthFromAD(invalid) = %d/%v, want 0/false", got, ok)
	}
	if got, ok := MNCLengthFromAD([]byte{0x00, 0x00, 0x00}); ok || got != 0 {
		t.Fatalf("MNCLengthFromAD(short) = %d/%v, want 0/false", got, ok)
	}
}

func TestFormatEAPAKAPermanentIdentity(t *testing.T) {
	tests := []struct {
		name   string
		format func(string, string, string) (string, error)
		imsi   string
		mcc    string
		mnc    string
		want   string
	}{
		{
			name:   "aka with three digit mnc",
			format: FormatEAPAKAPermanentIdentity,
			imsi:   "001010123456789",
			mcc:    "001",
			mnc:    "010",
			want:   "0001010123456789@wlan.mnc010.mcc001.3gppnetwork.org",
		},
		{
			name:   "aka prime with two digit mnc",
			format: FormatEAPAKAPrimePermanentIdentity,
			imsi:   "310260123456789",
			mcc:    "310",
			mnc:    "26",
			want:   "6310260123456789@wlan.mnc026.mcc310.3gppnetwork.org",
		},
		{
			name:   "derive plmn from imsi",
			format: FormatEAPAKAPermanentIdentity,
			imsi:   "001010123456789",
			want:   "0001010123456789@wlan.mnc010.mcc001.3gppnetwork.org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.format(tt.imsi, tt.mcc, tt.mnc)
			if err != nil {
				t.Fatalf("format() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("format() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseEAPAKAPermanentIdentity(t *testing.T) {
	tests := []struct {
		name string
		nai  string
		want EAPAKAPermanentIdentity
	}{
		{
			name: "aka",
			nai:  "0001010123456789@wlan.mnc010.mcc001.3gppnetwork.org",
			want: EAPAKAPermanentIdentity{
				Prefix: EAPAKAPermanentIdentityPrefix,
				IMSI:   "001010123456789",
				MCC:    "001",
				MNC:    "010",
				Realm:  "wlan.mnc010.mcc001.3gppnetwork.org",
			},
		},
		{
			name: "aka prime with two digit mnc",
			nai:  "6310260123456789@WLAN.MNC026.MCC310.3GPPNETWORK.ORG.",
			want: EAPAKAPermanentIdentity{
				Prefix: EAPAKAPrimePermanentIdentityPrefix,
				IMSI:   "310260123456789",
				MCC:    "310",
				MNC:    "26",
				Realm:  "wlan.mnc026.mcc310.3gppnetwork.org",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEAPAKAPermanentIdentity(tt.nai)
			if err != nil {
				t.Fatalf("ParseEAPAKAPermanentIdentity() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseEAPAKAPermanentIdentity() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestEAPAKAPermanentIdentityRejectsMalformedInput(t *testing.T) {
	badFormats := []struct {
		name string
		imsi string
		mcc  string
		mnc  string
	}{
		{name: "non digit imsi", imsi: "00101A123456789", mcc: "001", mnc: "010"},
		{name: "mcc mismatch", imsi: "001010123456789", mcc: "999", mnc: "010"},
		{name: "mnc mismatch", imsi: "001010123456789", mcc: "001", mnc: "011"},
		{name: "bad mnc length", imsi: "001010123456789", mcc: "001", mnc: "1"},
	}
	for _, tt := range badFormats {
		t.Run("format "+tt.name, func(t *testing.T) {
			if got, err := FormatEAPAKAPermanentIdentity(tt.imsi, tt.mcc, tt.mnc); err == nil {
				t.Fatalf("FormatEAPAKAPermanentIdentity() = %q nil error, want error", got)
			}
		})
	}

	badParses := []string{
		"001010123456789",
		"2001010123456789@wlan.mnc010.mcc001.3gppnetwork.org",
		"0001010123456789@ims.mnc010.mcc001.3gppnetwork.org",
		"0001010123456789@wlan.mnc011.mcc001.3gppnetwork.org",
		"0001010123456789@wlan.mnc01a.mcc001.3gppnetwork.org",
	}
	for _, nai := range badParses {
		t.Run("parse "+nai, func(t *testing.T) {
			if got, err := ParseEAPAKAPermanentIdentity(nai); err == nil {
				t.Fatalf("ParseEAPAKAPermanentIdentity() = %+v nil error, want error", got)
			}
		})
	}
}
