package eapaka

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/kimoju/vowifi-go/engine/sim"
)

func TestAKAPrimeCheckcodeUsesSHA256(t *testing.T) {
	identity := "6310280233641503@nai.epc.mnc028.mcc310.3gppnetwork.org"
	aka := sim.AKAResult{
		RES: mustHex(t, "28d7b0f2a2ec3de5"),
		IK:  mustHex(t, "9744871ad32bf9bbd1dd5ce54e3e2e5a"),
		CK:  mustHex(t, "5349fbe098649f948f5d2e973a81c00f"),
	}
	idReq, err := (Packet{
		Code:       CodeRequest,
		Identifier: 1,
		Type:       TypeAKAPrime,
		Subtype:    SubtypeIdentity,
		Attributes: []Attribute{PermanentIDReqAttribute()},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(idReq) error = %v", err)
	}
	idResp, err := (Packet{
		Code:       CodeResponse,
		Identifier: 1,
		Type:       TypeAKAPrime,
		Subtype:    SubtypeIdentity,
		Attributes: []Attribute{IdentityAttribute(identity)},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(idResp) error = %v", err)
	}
	transcript := [][]byte{idReq, idResp}

	checkcodeAttr := CheckcodeAttributeForPacketsAndType(TypeAKAPrime, transcript)
	checkcodeVal, err := checkcodeAttr.CheckcodeValue()
	if err != nil {
		t.Fatalf("CheckcodeValue() error = %v", err)
	}
	if len(checkcodeVal) != sha256.Size {
		t.Fatalf("AKA' checkcode length = %d, want %d", len(checkcodeVal), sha256.Size)
	}
	if err := VerifyCheckcodeAttributeForType(TypeAKAPrime, checkcodeAttr, transcript); err != nil {
		t.Fatalf("VerifyCheckcodeAttributeForType(AKA') error = %v", err)
	}
	// 20-byte SHA-1 checkcode MUST be rejected on EAP-AKA'.
	sha1Attr := CheckcodeAttributeForPackets(transcript)
	if err := VerifyCheckcodeAttributeForType(TypeAKAPrime, sha1Attr, transcript); !errors.Is(err, ErrInvalidAttribute) {
		t.Fatalf("VerifyCheckcodeAttributeForType(AKA' with SHA-1) err=%v, want ErrInvalidAttribute", err)
	}

	autn := mustHex(t, "bb52e91c747ac3ab2a5c23d15ee351d5")
	keys, err := DeriveAKAPrimeKeys(identity, "WLAN", autn, aka)
	if err != nil {
		t.Fatalf("DeriveAKAPrimeKeys() error = %v", err)
	}
	req := Packet{
		Code:       CodeRequest,
		Identifier: 9,
		Type:       TypeAKAPrime,
		Subtype:    SubtypeChallenge,
		Attributes: []Attribute{
			RANDAttribute(mustHex(t, "81e92b6c0ee0e12ebceba8d92a99dfa5")),
			AUTNAttribute(autn),
			KDFInputAttribute("WLAN"),
			KDFAttribute(AKAPrimeKDFDefault),
			checkcodeAttr,
			MACAttribute(nil),
		},
	}
	rawReq, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(req) error = %v", err)
	}
	mac, err := CalculateAKAPrimeMAC(keys.KAut, rawReq, nil)
	if err != nil {
		t.Fatalf("CalculateAKAPrimeMAC() error = %v", err)
	}
	req.Attributes[len(req.Attributes)-1] = MACAttribute(mac)

	resp, _, err := BuildChallengeResponseWithCheckcode(identity, req, aka, transcript)
	if err != nil {
		t.Fatalf("BuildChallengeResponseWithCheckcode(AKA') error = %v", err)
	}
	respCheckcode, ok := FindAttribute(resp.Attributes, AttributeCheckcode)
	if !ok {
		t.Fatal("missing response AT_CHECKCODE")
	}
	respVal, err := respCheckcode.CheckcodeValue()
	if err != nil {
		t.Fatalf("response CheckcodeValue() error = %v", err)
	}
	if len(respVal) != sha256.Size {
		t.Fatalf("response AKA' checkcode length = %d, want %d", len(respVal), sha256.Size)
	}
}

func TestValidateNetworkNameAndCRIT04RejectsBeforeSIM(t *testing.T) {
	if !ValidateNetworkName("WLAN", "WLAN") {
		t.Fatal("ValidateNetworkName(WLAN, WLAN) = false")
	}
	if !ValidateNetworkName("WLAN:mnc028.mcc310.3gppnetwork.org", "WLAN") {
		t.Fatal("ValidateNetworkName(WLAN:operator, WLAN) = false")
	}
	for _, bad := range []string{"", "EHRPD", "UMTS", "WLAN2", "WLAN:", ":WLAN"} {
		if ValidateNetworkName(bad, "WLAN") {
			t.Fatalf("ValidateNetworkName(%q, WLAN) = true, want false", bad)
		}
	}

	identity := "6310280233641503@nai.epc.mnc028.mcc310.3gppnetwork.org"
	aka := sim.AKAResult{
		RES: mustHex(t, "28d7b0f2a2ec3de5"),
		IK:  mustHex(t, "9744871ad32bf9bbd1dd5ce54e3e2e5a"),
		CK:  mustHex(t, "5349fbe098649f948f5d2e973a81c00f"),
	}
	// Evil pass-through authenticator claiming non-WLAN network name.
	evilReq := signedAKAPrimeChallengeRequest(t, identity, "EHRPD", aka)
	simCalled := false
	res, err := BuildChallengeResponseFromProvider(identity, evilReq, challengeAKAProviderFunc(func(rand16, autn16 []byte) (sim.AKAResult, error) {
		simCalled = true
		return aka, nil
	}), nil)
	if err != nil {
		t.Fatalf("BuildChallengeResponseFromProvider(evil network name) error = %v", err)
	}
	if simCalled {
		t.Fatal("provider.CalculateAKA was called despite AT_KDF_INPUT network name mismatch")
	}
	if !res.AuthFailure || !res.NetworkNameMismatch || res.Response.Subtype != SubtypeAuthenticationReject {
		t.Fatalf("unexpected result for network name mismatch: %+v", res)
	}

	// Duplicate AT_KDF_INPUT must also be rejected in challengeKDFInput / BuildChallengeResponse.
	dupReq := signedAKAPrimeChallengeRequest(t, identity, "WLAN", aka)
	dupReq.Attributes = append(dupReq.Attributes[:len(dupReq.Attributes)-1], KDFInputAttribute("WLAN"), dupReq.Attributes[len(dupReq.Attributes)-1])
	if _, _, err := BuildChallengeResponse(identity, dupReq, aka); !errors.Is(err, ErrInvalidAttribute) {
		t.Fatalf("BuildChallengeResponse(duplicate AT_KDF_INPUT) err=%v, want ErrInvalidAttribute", err)
	}
}

func TestHIGH04PreSIMValidationAndClientErrorOnBadChallenge(t *testing.T) {
	identity := "0310280233641503@nai.epc.mnc028.mcc310.3gppnetwork.org"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	transcript := identityTranscriptPackets(t, identity)

	t.Run("missing AT_MAC does not touch SIM and emits ClientError", func(t *testing.T) {
		simCalled := false
		req := Packet{
			Code:       CodeRequest,
			Identifier: 7,
			Type:       TypeAKA,
			Subtype:    SubtypeChallenge,
			Attributes: []Attribute{
				RANDAttribute(bytes.Repeat([]byte{0xa1}, 16)),
				AUTNAttribute(bytes.Repeat([]byte{0xb2}, 16)),
			},
		}
		res, err := BuildChallengeResponseFromProvider(identity, req, challengeAKAProviderFunc(func(_, _ []byte) (sim.AKAResult, error) {
			simCalled = true
			return aka, nil
		}), nil)
		if err != nil {
			t.Fatalf("BuildChallengeResponseFromProvider() error = %v", err)
		}
		if simCalled {
			t.Fatal("SIM was invoked on challenge missing AT_MAC")
		}
		if !res.ClientError || res.Response.Subtype != SubtypeClientError {
			t.Fatalf("result=%+v, want ClientError response", res)
		}
	})

	t.Run("bidding down does not touch SIM and emits AuthenticationReject", func(t *testing.T) {
		simCalled := false
		req := signedChallengeRequestWithEncryptedAttrs(t, identity, aka, BiddingAttribute(true))
		res, err := BuildChallengeResponseFromProvider(identity, req, challengeAKAProviderFunc(func(_, _ []byte) (sim.AKAResult, error) {
			simCalled = true
			return aka, nil
		}), nil)
		if err != nil {
			t.Fatalf("BuildChallengeResponseFromProvider() error = %v", err)
		}
		if simCalled {
			t.Fatal("SIM was invoked on bidding-down challenge")
		}
		if !res.AuthFailure || !res.BiddingDown || res.Response.Subtype != SubtypeAuthenticationReject {
			t.Fatalf("result=%+v, want AuthenticationReject with BiddingDown=true", res)
		}
	})

	t.Run("tampered checkcode does not touch SIM and emits ClientError", func(t *testing.T) {
		simCalled := false
		req := signedChallengeRequestWithCheckcode(t, identity, aka, transcript)
		badTranscript := identityTranscriptPackets(t, identity+"tampered")
		res, err := BuildChallengeResponseFromProvider(identity, req, challengeAKAProviderFunc(func(_, _ []byte) (sim.AKAResult, error) {
			simCalled = true
			return aka, nil
		}), badTranscript)
		if err != nil {
			t.Fatalf("BuildChallengeResponseFromProvider() error = %v", err)
		}
		if simCalled {
			t.Fatal("SIM was invoked on tampered AT_CHECKCODE")
		}
		if !res.ClientError || res.Response.Subtype != SubtypeClientError {
			t.Fatalf("result=%+v, want ClientError response", res)
		}
	})

	t.Run("invalid AT_MAC emits ClientError response", func(t *testing.T) {
		req := signedChallengeRequest(t, identity, aka)
		req.Attributes[len(req.Attributes)-1] = MACAttribute(bytes.Repeat([]byte{0xee}, 16))
		res, err := BuildChallengeResponseFromProvider(identity, req, challengeAKAProviderFunc(func(_, _ []byte) (sim.AKAResult, error) {
			return aka, nil
		}), nil)
		if err != nil {
			t.Fatalf("BuildChallengeResponseFromProvider() error = %v", err)
		}
		if !res.ClientError || res.Response.Subtype != SubtypeClientError {
			t.Fatalf("result=%+v, want ClientError response on AT_MAC mismatch", res)
		}
	})
}

func TestMED05KDFAndNotificationEdgeCases(t *testing.T) {
	t.Run("duplicate AT_KDF value rejected", func(t *testing.T) {
		_, _, err := BuildAKAPrimeKDFNegotiationResponse(Packet{
			Code:       CodeRequest,
			Identifier: 1,
			Type:       TypeAKAPrime,
			Subtype:    SubtypeChallenge,
			Attributes: []Attribute{
				KDFAttribute(99),
				KDFAttribute(99),
				KDFAttribute(AKAPrimeKDFDefault),
			},
		})
		if !errors.Is(err, ErrInvalidAttribute) {
			t.Fatalf("duplicate AT_KDF err=%v, want ErrInvalidAttribute", err)
		}
	})

	t.Run("AKA' synchronization failure emits single selected AT_KDF", func(t *testing.T) {
		req := Packet{
			Code:       CodeRequest,
			Identifier: 2,
			Type:       TypeAKAPrime,
			Subtype:    SubtypeChallenge,
			Attributes: []Attribute{
				KDFInputAttribute("WLAN"),
				KDFAttribute(AKAPrimeKDFDefault),
				KDFAttribute(2),
			},
		}
		resp, err := BuildSynchronizationFailureResponse(req, bytes.Repeat([]byte{0xaa}, AUTSLength))
		if err != nil {
			t.Fatalf("BuildSynchronizationFailureResponse() error = %v", err)
		}
		kdfs, err := kdfValues(resp.Attributes)
		if err != nil {
			t.Fatalf("kdfValues(resp) error = %v", err)
		}
		if len(kdfs) != 1 || kdfs[0] != AKAPrimeKDFDefault {
			t.Fatalf("sync-failure KDFs=%v, want [%d]", kdfs, AKAPrimeKDFDefault)
		}
	})

	t.Run("notification P=1 forbids AT_MAC and duplicate AT_NOTIFICATION", func(t *testing.T) {
		reqWithMAC := Packet{
			Code:       CodeRequest,
			Identifier: 3,
			Type:       TypeAKA,
			Subtype:    SubtypeNotification,
			Attributes: []Attribute{
				NotificationAttribute(NotificationGeneralFailureBeforeAuthentication),
				MACAttribute(nil),
			},
		}
		if _, _, err := BuildNotificationResponse(reqWithMAC); !errors.Is(err, ErrInvalidAttribute) {
			t.Fatalf("BuildNotificationResponse(P=1 with AT_MAC) err=%v, want ErrInvalidAttribute", err)
		}
		clientResp, handled, isClientErr, err := BuildNotificationOrClientErrorResponse(reqWithMAC, NotificationOptions{})
		if err != nil || !handled || !isClientErr || clientResp.Subtype != SubtypeClientError {
			t.Fatalf("BuildNotificationOrClientErrorResponse() = (%+v, %t, %t, %v), want ClientError", clientResp, handled, isClientErr, err)
		}

		dupNotif := Packet{
			Code:       CodeRequest,
			Identifier: 4,
			Type:       TypeAKA,
			Subtype:    SubtypeNotification,
			Attributes: []Attribute{
				NotificationAttribute(NotificationGeneralFailureBeforeAuthentication),
				NotificationAttribute(NotificationGeneralFailureBeforeAuthentication),
			},
		}
		if _, _, err := BuildNotificationResponse(dupNotif); !errors.Is(err, ErrInvalidAttribute) {
			t.Fatalf("BuildNotificationResponse(duplicate AT_NOTIFICATION) err=%v, want ErrInvalidAttribute", err)
		}
	})

	t.Run("notification P=0 in fast re-auth verifies and echoes encrypted AT_COUNTER", func(t *testing.T) {
		identity := "reauth@example.com"
		aka := sim.AKAResult{
			RES: []byte{0x11, 0x22, 0x33, 0x44},
			CK:  bytes.Repeat([]byte{0xc1}, 16),
			IK:  bytes.Repeat([]byte{0xd2}, 16),
		}
		keys, err := DeriveKeys(identity, aka)
		if err != nil {
			t.Fatalf("DeriveKeys() error = %v", err)
		}
		reqIV := bytes.Repeat([]byte{0x44}, 16)
		encr, err := EncryptAttributes(keys.KEncr, reqIV, []Attribute{CounterAttribute(7)})
		if err != nil {
			t.Fatalf("EncryptAttributes() error = %v", err)
		}
		req := Packet{
			Code:       CodeRequest,
			Identifier: 5,
			Type:       TypeAKA,
			Subtype:    SubtypeNotification,
			Attributes: []Attribute{
				NotificationAttribute(NotificationGeneralFailureAfterAuthentication),
				IVAttribute(reqIV),
				encr,
				MACAttribute(nil),
			},
		}
		rawReq, err := req.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary(req) error = %v", err)
		}
		mac, err := CalculateMAC(keys.KAut, rawReq, nil)
		if err != nil {
			t.Fatalf("CalculateMAC(req) error = %v", err)
		}
		req.Attributes[len(req.Attributes)-1] = MACAttribute(mac)

		// Wrong counter must fail / trigger ClientError.
		if _, _, err := BuildNotificationResponseWithOptions(req, NotificationOptions{
			Authenticated:   true,
			Keys:            keys,
			FastReauth:      true,
			ExpectedCounter: 8,
		}); !errors.Is(err, ErrInvalidReauth) {
			t.Fatalf("wrong counter err=%v, want ErrInvalidReauth", err)
		}

		// Matching counter must succeed and return encrypted AT_COUNTER + valid AT_MAC.
		resp, handled, err := BuildNotificationResponseWithOptions(req, NotificationOptions{
			Authenticated:   true,
			Keys:            keys,
			FastReauth:      true,
			ExpectedCounter: 7,
			ResponseIV:      bytes.Repeat([]byte{0x99}, 16),
		})
		if err != nil || !handled {
			t.Fatalf("BuildNotificationResponseWithOptions() = (%+v, %t, %v)", resp, handled, err)
		}
		rawResp, err := resp.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary(resp) error = %v", err)
		}
		if err := VerifyMAC(keys.KAut, rawResp, nil); err != nil {
			t.Fatalf("VerifyMAC(resp) error = %v", err)
		}
		decrypted, hasPair, err := DecryptPacketEncryptedAttributes(resp, keys)
		if err != nil || !hasPair {
			t.Fatalf("DecryptPacketEncryptedAttributes(resp) = (%+v, %t, %v)", decrypted, hasPair, err)
		}
		counter, ok, err := CounterFromAttributes(decrypted)
		if err != nil || !ok || counter != 7 {
			t.Fatalf("response AT_COUNTER = (%d, %t, %v), want 7", counter, ok, err)
		}
	})
}
