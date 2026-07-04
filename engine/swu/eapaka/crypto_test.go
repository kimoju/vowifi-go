package eapaka

import (
	"bytes"
	"errors"
	"testing"

	"github.com/iniwex5/vowifi-go/engine/sim"
)

func TestDeriveKeysAndBuildChallengeResponse(t *testing.T) {
	identity := "310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	req := signedChallengeRequest(t, identity, aka)
	resp, keys, err := BuildChallengeResponse(identity, req, aka)
	if err != nil {
		t.Fatalf("BuildChallengeResponse() error = %v", err)
	}
	if len(keys.KEncr) != KeyLengthKEncr || len(keys.KAut) != KeyLengthKAut || len(keys.MSK) != KeyLengthMSK || len(keys.EMSK) != KeyLengthEMSK {
		t.Fatalf("key lengths KEncr=%d KAut=%d MSK=%d EMSK=%d", len(keys.KEncr), len(keys.KAut), len(keys.MSK), len(keys.EMSK))
	}
	if resp.Code != CodeResponse || resp.Identifier != req.Identifier || resp.Subtype != SubtypeChallenge {
		t.Fatalf("response=%+v", resp)
	}
	resAttr, ok := FindAttribute(resp.Attributes, AttributeRES)
	if !ok {
		t.Fatal("missing AT_RES")
	}
	res, bits, err := resAttr.RESValue()
	if err != nil {
		t.Fatalf("RESValue() error = %v", err)
	}
	if bits != 32 || !bytes.Equal(res, aka.RES) {
		t.Fatalf("RES bits=%d value=%x", bits, res)
	}
	raw, err := resp.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	if err := VerifyMAC(keys.KAut, raw, nil); err != nil {
		t.Fatalf("VerifyMAC(response) error = %v", err)
	}
}

func TestBuildChallengeResponseRejectsBadRequestMAC(t *testing.T) {
	identity := "user@example.com"
	aka := sim.AKAResult{RES: []byte{1}, CK: bytes.Repeat([]byte{2}, 16), IK: bytes.Repeat([]byte{3}, 16)}
	req := signedChallengeRequest(t, identity, aka)
	req.Attributes[len(req.Attributes)-1] = MACAttribute(bytes.Repeat([]byte{0xff}, 16))
	_, _, err := BuildChallengeResponse(identity, req, aka)
	if !errors.Is(err, ErrInvalidMAC) {
		t.Fatalf("BuildChallengeResponse() err=%v, want ErrInvalidMAC", err)
	}
}

func TestBuildSynchronizationFailureResponse(t *testing.T) {
	req := Packet{Code: CodeRequest, Identifier: 3, Type: TypeAKA, Subtype: SubtypeChallenge}
	wantAUTS := bytes.Repeat([]byte{0xaa}, 14)
	resp, err := BuildSynchronizationFailureResponse(req, wantAUTS)
	if err != nil {
		t.Fatalf("BuildSynchronizationFailureResponse() error = %v", err)
	}
	if resp.Code != CodeResponse || resp.Subtype != SubtypeSynchronizationFailure {
		t.Fatalf("response=%+v", resp)
	}
	attr, ok := FindAttribute(resp.Attributes, AttributeAUTS)
	if !ok {
		t.Fatal("missing AT_AUTS")
	}
	auts, err := attr.AUTSValue()
	if err != nil {
		t.Fatalf("AUTSValue() error = %v", err)
	}
	if !bytes.Equal(auts, wantAUTS) {
		t.Fatalf("AUTS=%x", auts)
	}
}

func signedChallengeRequest(t *testing.T, identity string, aka sim.AKAResult) Packet {
	t.Helper()
	keys, err := DeriveKeys(identity, aka)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	req := Packet{
		Code:       CodeRequest,
		Identifier: 7,
		Type:       TypeAKA,
		Subtype:    SubtypeChallenge,
		Attributes: []Attribute{
			RANDAttribute(bytes.Repeat([]byte{0xa1}, 16)),
			AUTNAttribute(bytes.Repeat([]byte{0xb2}, 16)),
			MACAttribute(nil),
		},
	}
	raw, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	mac, err := CalculateMAC(keys.KAut, raw, nil)
	if err != nil {
		t.Fatalf("CalculateMAC() error = %v", err)
	}
	req.Attributes[len(req.Attributes)-1] = MACAttribute(mac)
	return req
}
