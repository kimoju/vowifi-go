package ikev2

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestInformationalEmptyDPDRoundTrip(t *testing.T) {
	init, keys := informationalFixture(t)
	iv := bytes.Repeat([]byte{0x71}, keys.Profile.EncryptionBlockSize)
	msg, raw, err := BuildInformationalRequest(init, keys, 9, nil, iv)
	if err != nil {
		t.Fatalf("BuildInformationalRequest() error = %v", err)
	}
	if msg.Header.ExchangeType != ExchangeINFORMATIONAL || msg.Header.Flags != FlagInitiator {
		t.Fatalf("msg.Header=%+v", msg.Header)
	}
	if raw[16] != PayloadSK || raw[18] != ExchangeINFORMATIONAL || raw[28] != PayloadNoNext {
		t.Fatalf("raw header next=%d exchange=%d SK next=%d", raw[16], raw[18], raw[28])
	}
	parsed, inner, err := ParseInformationalRequest(raw, init, keys, 9)
	if err != nil {
		t.Fatalf("ParseInformationalRequest() error = %v", err)
	}
	if parsed.Header.MessageID != 9 || len(inner) != 0 {
		t.Fatalf("parsed=%+v inner=%+v", parsed, inner)
	}

	_, responseRaw, err := BuildInformationalResponse(init, keys, 9, nil, bytes.Repeat([]byte{0x72}, keys.Profile.EncryptionBlockSize))
	if err != nil {
		t.Fatalf("BuildInformationalResponse() error = %v", err)
	}
	response, inner, err := ParseInformationalResponse(responseRaw, init, keys, 9)
	if err != nil {
		t.Fatalf("ParseInformationalResponse() error = %v", err)
	}
	if response.Header.Flags != FlagResponse || len(inner) != 0 {
		t.Fatalf("response=%+v inner=%+v", response, inner)
	}
}

func TestInformationalESPDeleteRoundTrip(t *testing.T) {
	init, keys := informationalFixture(t)
	deletePayload, err := ESPDeletePayload(mustHex("01020304"))
	if err != nil {
		t.Fatalf("ESPDeletePayload() error = %v", err)
	}
	_, raw, err := BuildInformationalRequest(init, keys, 10, []Payload{deletePayload}, bytes.Repeat([]byte{0x73}, keys.Profile.EncryptionBlockSize))
	if err != nil {
		t.Fatalf("BuildInformationalRequest() error = %v", err)
	}
	_, inner, err := ParseInformationalRequest(raw, init, keys, 10)
	if err != nil {
		t.Fatalf("ParseInformationalRequest() error = %v", err)
	}
	if len(inner) != 1 || inner[0].Type != PayloadDelete {
		t.Fatalf("inner=%+v", inner)
	}
	deletePayloadBody, err := ParseDelete(inner[0].Body)
	if err != nil {
		t.Fatalf("ParseDelete() error = %v", err)
	}
	if deletePayloadBody.ProtocolID != ProtocolESP || len(deletePayloadBody.SPIs) != 1 ||
		hex.EncodeToString(deletePayloadBody.SPIs[0]) != "01020304" {
		t.Fatalf("delete=%+v", deletePayloadBody)
	}
}

func TestInformationalResponderOriginatedDPDRoundTrip(t *testing.T) {
	init, keys := informationalFixture(t)
	_, requestRaw, err := BuildInformationalRequestFrom(init, keys, 12, false, nil, bytes.Repeat([]byte{0x75}, keys.Profile.EncryptionBlockSize))
	if err != nil {
		t.Fatalf("BuildInformationalRequestFrom() error = %v", err)
	}
	request, inner, err := ParseInformationalRequestFrom(requestRaw, init, keys, 12, false)
	if err != nil {
		t.Fatalf("ParseInformationalRequestFrom() error = %v", err)
	}
	if request.Header.Flags&(FlagInitiator|FlagResponse) != 0 || len(inner) != 0 {
		t.Fatalf("request=%+v inner=%+v", request, inner)
	}

	_, responseRaw, err := BuildInformationalResponseFrom(init, keys, 12, true, nil, bytes.Repeat([]byte{0x76}, keys.Profile.EncryptionBlockSize))
	if err != nil {
		t.Fatalf("BuildInformationalResponseFrom() error = %v", err)
	}
	response, inner, err := ParseInformationalResponseFrom(responseRaw, init, keys, 12, true)
	if err != nil {
		t.Fatalf("ParseInformationalResponseFrom() error = %v", err)
	}
	if response.Header.Flags&(FlagInitiator|FlagResponse) != FlagInitiator|FlagResponse || len(inner) != 0 {
		t.Fatalf("response=%+v inner=%+v", response, inner)
	}
}

func TestInformationalRejectsUnexpectedHeader(t *testing.T) {
	init, keys := informationalFixture(t)
	_, raw, err := BuildInformationalResponse(init, keys, 11, nil, bytes.Repeat([]byte{0x74}, keys.Profile.EncryptionBlockSize))
	if err != nil {
		t.Fatalf("BuildInformationalResponse() error = %v", err)
	}
	if _, _, err := ParseInformationalResponse(raw, init, keys, 12); !errors.Is(err, ErrInvalidInformational) {
		t.Fatalf("ParseInformationalResponse() err=%v, want ErrInvalidInformational", err)
	}
	if _, _, err := ParseInformationalRequest(raw, init, keys, 11); !errors.Is(err, ErrInvalidSKPayload) {
		t.Fatalf("ParseInformationalRequest() err=%v, want ErrInvalidSKPayload", err)
	}
}

func informationalFixture(t *testing.T) (InitResult, IKEKeys) {
	t.Helper()
	profile, err := KeyMaterialProfileFromSA(DefaultIKEProposal())
	if err != nil {
		t.Fatalf("KeyMaterialProfileFromSA() error = %v", err)
	}
	keys, err := SplitIKEKeys(profile, incrementalBytes(profile.RequiredLength()))
	if err != nil {
		t.Fatalf("SplitIKEKeys() error = %v", err)
	}
	return InitResult{
		InitiatorSPI: 0x0102030405060708,
		ResponderSPI: 0x1112131415161718,
		Keys:         keys,
	}, keys
}
