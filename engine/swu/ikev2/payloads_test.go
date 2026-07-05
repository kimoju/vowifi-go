package ikev2

import (
	"encoding/hex"
	"errors"
	"net"
	"testing"
)

func TestNotifyPayloadMarshalParse(t *testing.T) {
	body, err := (Notify{
		ProtocolID:       ProtocolIKE,
		NotifyType:       NotifyMOBIKESupported,
		NotificationData: []byte{0xaa, 0xbb},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	if got, want := hex.EncodeToString(body), "0100400caabb"; got != want {
		t.Fatalf("notify body=%s, want %s", got, want)
	}
	parsed, err := ParseNotify(body)
	if err != nil {
		t.Fatalf("ParseNotify() error = %v", err)
	}
	if parsed.ProtocolID != ProtocolIKE || parsed.NotifyType != NotifyMOBIKESupported || hex.EncodeToString(parsed.NotificationData) != "aabb" {
		t.Fatalf("parsed=%+v", parsed)
	}
}

func TestDeletePayloadMarshalParseESP(t *testing.T) {
	payload, err := ESPDeletePayload(mustHex("01020304"), mustHex("aabbccdd"))
	if err != nil {
		t.Fatalf("ESPDeletePayload() error = %v", err)
	}
	if payload.Type != PayloadDelete {
		t.Fatalf("payload.Type=%d, want PayloadDelete", payload.Type)
	}
	if got, want := hex.EncodeToString(payload.Body), "0304000201020304aabbccdd"; got != want {
		t.Fatalf("delete body=%s, want %s", got, want)
	}
	parsed, err := ParseDelete(payload.Body)
	if err != nil {
		t.Fatalf("ParseDelete() error = %v", err)
	}
	if parsed.ProtocolID != ProtocolESP || len(parsed.SPIs) != 2 ||
		hex.EncodeToString(parsed.SPIs[0]) != "01020304" ||
		hex.EncodeToString(parsed.SPIs[1]) != "aabbccdd" {
		t.Fatalf("parsed=%+v", parsed)
	}
}

func TestDeletePayloadMarshalParseIKE(t *testing.T) {
	payload := IKEDeletePayload()
	if got, want := hex.EncodeToString(payload.Body), "01000000"; got != want {
		t.Fatalf("delete body=%s, want %s", got, want)
	}
	parsed, err := ParseDelete(payload.Body)
	if err != nil {
		t.Fatalf("ParseDelete() error = %v", err)
	}
	if parsed.ProtocolID != ProtocolIKE || len(parsed.SPIs) != 0 {
		t.Fatalf("parsed=%+v", parsed)
	}
}

func TestDeletePayloadRejectsInvalid(t *testing.T) {
	cases := [][]byte{
		{},
		{ProtocolESP, 4, 0, 2, 1, 2, 3, 4},
		{ProtocolIKE, 4, 0, 1, 1, 2, 3, 4},
		{99, 0, 0, 0},
	}
	for _, tc := range cases {
		if _, err := ParseDelete(tc); !errors.Is(err, ErrInvalidDelete) {
			t.Fatalf("ParseDelete(%x) err=%v, want ErrInvalidDelete", tc, err)
		}
	}
	if _, err := ESPDeletePayload(); !errors.Is(err, ErrInvalidDelete) {
		t.Fatalf("ESPDeletePayload() err=%v, want ErrInvalidDelete", err)
	}
	if _, err := DeletePayload(Delete{ProtocolID: ProtocolESP, SPIs: [][]byte{{1, 2, 3, 4}, {5}}}); !errors.Is(err, ErrInvalidDelete) {
		t.Fatalf("DeletePayload() err=%v, want ErrInvalidDelete", err)
	}
}

func TestKeyExchangePayload(t *testing.T) {
	payload := KeyExchangePayload(DHGroupCurve25519, []byte{1, 2, 3})
	if payload.Type != PayloadKE || hex.EncodeToString(payload.Body) != "001f0000010203" {
		t.Fatalf("payload=%+v body=%x", payload, payload.Body)
	}
	parsed, err := ParseKeyExchange(payload.Body)
	if err != nil {
		t.Fatalf("ParseKeyExchange() error = %v", err)
	}
	if parsed.DHGroup != DHGroupCurve25519 || hex.EncodeToString(parsed.KeyData) != "010203" {
		t.Fatalf("parsed=%+v", parsed)
	}
}

func TestNATDetectionHash(t *testing.T) {
	hash, err := NATDetectionHash(0x0102030405060708, 0x1112131415161718, net.ParseIP("192.0.2.10"), 4500)
	if err != nil {
		t.Fatalf("NATDetectionHash(v4) error = %v", err)
	}
	if got, want := hex.EncodeToString(hash), "4241cad1dadc1360129f8fc22ffa37c931af3125"; got != want {
		t.Fatalf("v4 hash=%s, want %s", got, want)
	}
	hash, err = NATDetectionHash(0x0102030405060708, 0x1112131415161718, net.ParseIP("2001:db8::1"), 4500)
	if err != nil {
		t.Fatalf("NATDetectionHash(v6) error = %v", err)
	}
	if got, want := hex.EncodeToString(hash), "1ee24423bf8f59515e0265c6d0f08be3d038f7e5"; got != want {
		t.Fatalf("v6 hash=%s, want %s", got, want)
	}
}

func TestNATDetectionNotify(t *testing.T) {
	payload, err := NATDetectionNotify(NotifyNATDetectionSourceIP, 0x0102030405060708, 0x1112131415161718, net.ParseIP("192.0.2.10"), 4500)
	if err != nil {
		t.Fatalf("NATDetectionNotify() error = %v", err)
	}
	notify, err := ParseNotify(payload.Body)
	if err != nil {
		t.Fatalf("ParseNotify() error = %v", err)
	}
	if payload.Type != PayloadNotify || notify.NotifyType != NotifyNATDetectionSourceIP || len(notify.NotificationData) != 20 {
		t.Fatalf("payload=%+v notify=%+v", payload, notify)
	}
	if _, err := NATDetectionNotify(NotifyMOBIKESupported, 1, 2, net.ParseIP("192.0.2.10"), 4500); !errors.Is(err, ErrInvalidNotify) {
		t.Fatalf("NATDetectionNotify() err=%v, want ErrInvalidNotify", err)
	}
}
