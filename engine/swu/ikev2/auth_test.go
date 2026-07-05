package ikev2

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/engine/swu/eapaka"
)

type authFakeTransport struct {
	t          *testing.T
	init       InitResult
	keys       IKEKeys
	exchanges  int
	identity   string
	firstInner []Payload
}

func (f *authFakeTransport) ExchangeIKE(ctx context.Context, request []byte) ([]byte, error) {
	f.t.Helper()
	switch f.exchanges {
	case 0:
		msg, inner, err := UnprotectMessage(request, f.keys, true)
		if err != nil {
			return nil, err
		}
		if msg.Header.ExchangeType != ExchangeIKE_AUTH || msg.Header.MessageID != 1 || msg.Header.Flags&FlagInitiator == 0 {
			f.t.Fatalf("first auth header=%+v", msg.Header)
		}
		f.firstInner = clonePayloads(inner)
		if gotTypes(inner); !bytes.Equal(gotTypes(inner), []byte{PayloadIDi, PayloadCP, PayloadSA, PayloadTSi, PayloadTSr}) {
			f.t.Fatalf("first inner types=%v", gotTypes(inner))
		}
		req, err := (eapaka.Packet{
			Code:       eapaka.CodeRequest,
			Identifier: 9,
			Type:       eapaka.TypeAKA,
			Subtype:    eapaka.SubtypeIdentity,
			Attributes: []eapaka.Attribute{eapaka.FullAuthIDReqAttribute()},
		}).MarshalBinary()
		if err != nil {
			return nil, err
		}
		_, raw, err := ProtectMessage(authHeader(f.init, 1, false), f.keys, false, []Payload{EAPPayload(req)}, bytes.Repeat([]byte{0x31}, f.keys.Profile.EncryptionBlockSize))
		if err != nil {
			return nil, err
		}
		f.exchanges++
		return raw, nil
	case 1:
		msg, inner, err := UnprotectMessage(request, f.keys, true)
		if err != nil {
			return nil, err
		}
		if msg.Header.MessageID != 2 || len(inner) != 1 || inner[0].Type != PayloadEAP {
			f.t.Fatalf("second auth header=%+v inner=%+v", msg.Header, inner)
		}
		pkt, err := eapaka.ParsePacket(inner[0].Body)
		if err != nil {
			return nil, err
		}
		if pkt.Code != eapaka.CodeResponse || pkt.Subtype != eapaka.SubtypeIdentity {
			f.t.Fatalf("identity packet=%+v", pkt)
		}
		attr, ok := eapaka.FindAttribute(pkt.Attributes, eapaka.AttributeIdentity)
		if !ok {
			f.t.Fatal("missing AT_IDENTITY")
		}
		identity, err := attr.IdentityValue()
		if err != nil {
			return nil, err
		}
		f.identity = identity
		challenge, err := (eapaka.Packet{
			Code:       eapaka.CodeRequest,
			Identifier: 10,
			Type:       eapaka.TypeAKA,
			Subtype:    eapaka.SubtypeChallenge,
			Attributes: []eapaka.Attribute{
				eapaka.RANDAttribute(bytes.Repeat([]byte{0xa1}, 16)),
				eapaka.AUTNAttribute(bytes.Repeat([]byte{0xb2}, 16)),
			},
		}).MarshalBinary()
		if err != nil {
			return nil, err
		}
		_, raw, err := ProtectMessage(authHeader(f.init, 2, false), f.keys, false, []Payload{EAPPayload(challenge)}, bytes.Repeat([]byte{0x32}, f.keys.Profile.EncryptionBlockSize))
		if err != nil {
			return nil, err
		}
		f.exchanges++
		return raw, nil
	default:
		return nil, errors.New("unexpected extra exchange")
	}
}

func TestRunIKEAuthEAPIdentity(t *testing.T) {
	init := fakeInitResult(t)
	transport := &authFakeTransport{t: t, init: init, keys: init.Keys}
	res, err := RunIKE_AUTH_EAPIdentity(context.Background(), AuthConfig{
		Transport:     transport,
		Init:          init,
		InitiatorID:   Identity{Type: IDRFC822Addr, Data: []byte("310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org")},
		EAPIdentity:   "310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org",
		ChildSPI:      []byte{0xca, 0xfe, 0xba, 0xbe},
		InitialIV:     bytes.Repeat([]byte{0x21}, init.Keys.Profile.EncryptionBlockSize),
		EAPIdentityIV: bytes.Repeat([]byte{0x22}, init.Keys.Profile.EncryptionBlockSize),
	})
	if err != nil {
		t.Fatalf("RunIKE_AUTH_EAPIdentity() error = %v", err)
	}
	if transport.exchanges != 2 || transport.identity != "310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org" {
		t.Fatalf("exchanges=%d identity=%q", transport.exchanges, transport.identity)
	}
	childSA, err := ParseSecurityAssociation(transport.firstInner[2].Body)
	if err != nil {
		t.Fatalf("ParseSecurityAssociation() error = %v", err)
	}
	if len(childSA.Proposals) != 1 || !bytes.Equal(childSA.Proposals[0].SPI, []byte{0xca, 0xfe, 0xba, 0xbe}) {
		t.Fatalf("child SA=%+v", childSA)
	}
	if res.EAPRequest == nil || res.EAPRequest.Subtype != eapaka.SubtypeIdentity {
		t.Fatalf("EAPRequest=%+v", res.EAPRequest)
	}
	if res.EAPAfterIdentity == nil || res.EAPAfterIdentity.Subtype != eapaka.SubtypeChallenge || res.NextMessageID != 3 {
		t.Fatalf("after=%+v next=%d", res.EAPAfterIdentity, res.NextMessageID)
	}
	attr, ok := eapaka.FindAttribute(res.EAPAfterIdentity.Attributes, eapaka.AttributeRAND)
	if !ok {
		t.Fatal("missing AT_RAND")
	}
	rands, err := attr.RANDValues()
	if err != nil {
		t.Fatalf("RANDValues() error = %v", err)
	}
	if len(rands) != 1 || !bytes.Equal(rands[0], bytes.Repeat([]byte{0xa1}, 16)) {
		t.Fatalf("RAND=%x", rands)
	}
}

func TestRunIKEAuthAKAChallenge(t *testing.T) {
	init := fakeInitResult(t)
	identity := "310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org"
	aka := simAKAResult()
	challenge := signedAKAChallenge(t, identity, aka)
	transport := InitTransportFunc(func(ctx context.Context, request []byte) ([]byte, error) {
		msg, inner, err := UnprotectMessage(request, init.Keys, true)
		if err != nil {
			return nil, err
		}
		if msg.Header.MessageID != 3 || len(inner) != 1 || inner[0].Type != PayloadEAP {
			t.Fatalf("request header=%+v inner=%+v", msg.Header, inner)
		}
		pkt, err := eapaka.ParsePacket(inner[0].Body)
		if err != nil {
			return nil, err
		}
		if pkt.Code != eapaka.CodeResponse || pkt.Subtype != eapaka.SubtypeChallenge {
			t.Fatalf("packet=%+v", pkt)
		}
		keys, err := eapaka.DeriveKeys(identity, aka)
		if err != nil {
			return nil, err
		}
		raw, err := pkt.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if err := eapaka.VerifyMAC(keys.KAut, raw, nil); err != nil {
			return nil, err
		}
		resAttr, ok := eapaka.FindAttribute(pkt.Attributes, eapaka.AttributeRES)
		if !ok {
			t.Fatal("missing AT_RES")
		}
		res, _, err := resAttr.RESValue()
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(res, aka.RES) {
			t.Fatalf("RES=%x", res)
		}
		success, err := (eapaka.Packet{Code: eapaka.CodeSuccess, Identifier: pkt.Identifier}).MarshalBinary()
		if err != nil {
			return nil, err
		}
		saPayload, err := SecurityAssociationPayload(DefaultESPProposal([]byte{0xde, 0xad, 0xbe, 0xef}))
		if err != nil {
			return nil, err
		}
		tsiPayload, err := TrafficSelectorsPayload(PayloadTSi, IPv4AnyTrafficSelectors())
		if err != nil {
			return nil, err
		}
		tsrPayload, err := TrafficSelectorsPayload(PayloadTSr, IPv4AnyTrafficSelectors())
		if err != nil {
			return nil, err
		}
		cpPayload, err := ConfigurationPayload(Configuration{Type: CFGReply, Attributes: []ConfigurationAttribute{{Type: ConfigInternalIPv4Address, Value: []byte{10, 0, 0, 2}}}})
		if err != nil {
			return nil, err
		}
		_, rawResp, err := ProtectMessage(authHeader(init, 3, false), init.Keys, false, []Payload{EAPPayload(success), saPayload, tsiPayload, tsrPayload, cpPayload}, bytes.Repeat([]byte{0x42}, init.Keys.Profile.EncryptionBlockSize))
		return rawResp, err
	})
	localSPI := []byte{0xca, 0xfe, 0xba, 0xbe}
	res, err := RunIKE_AUTH_AKAChallenge(context.Background(), AKAChallengeConfig{
		Transport: transport,
		Init:      init,
		SIM:       akaProviderStub{result: aka},
		Identity:  identity,
		Request:   challenge,
		ChildSPI:  localSPI,
		MessageID: 3,
		IV:        bytes.Repeat([]byte{0x41}, init.Keys.Profile.EncryptionBlockSize),
	})
	if err != nil {
		t.Fatalf("RunIKE_AUTH_AKAChallenge() error = %v", err)
	}
	if res.SyncFailure || res.EAPNext == nil || res.EAPNext.Code != eapaka.CodeSuccess || res.NextMessageID != 4 {
		t.Fatalf("result=%+v", res)
	}
	if len(res.EAPKeys.KAut) != eapaka.KeyLengthKAut || len(res.EAPKeys.MSK) != eapaka.KeyLengthMSK {
		t.Fatalf("EAP keys=%+v", res.EAPKeys)
	}
	if res.ChildSA == nil || !bytes.Equal(res.ChildSA.LocalSPI, localSPI) || !bytes.Equal(res.ChildSA.RemoteSPI, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("child SA=%+v", res.ChildSA)
	}
	if len(res.ChildSA.Keys.Outbound.EncryptionKey) != 16 || len(res.ChildSA.Keys.Inbound.IntegrityKey) != 32 {
		t.Fatalf("child keys=%+v", res.ChildSA.Keys)
	}
}

func TestRunIKEAuthAKAPrimeChallenge(t *testing.T) {
	init := fakeInitResult(t)
	identity := "310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org"
	networkName := "WLAN"
	aka := simAKAResult()
	challenge := signedAKAPrimeChallenge(t, identity, networkName, aka)
	transport := InitTransportFunc(func(ctx context.Context, request []byte) ([]byte, error) {
		msg, inner, err := UnprotectMessage(request, init.Keys, true)
		if err != nil {
			return nil, err
		}
		if msg.Header.MessageID != 3 || len(inner) != 1 || inner[0].Type != PayloadEAP {
			t.Fatalf("request header=%+v inner=%+v", msg.Header, inner)
		}
		pkt, err := eapaka.ParsePacket(inner[0].Body)
		if err != nil {
			return nil, err
		}
		if pkt.Code != eapaka.CodeResponse || pkt.Type != eapaka.TypeAKAPrime || pkt.Subtype != eapaka.SubtypeChallenge {
			t.Fatalf("packet=%+v", pkt)
		}
		keys, err := eapaka.DeriveAKAPrimeKeys(identity, networkName, bytes.Repeat([]byte{0xb2}, 16), aka)
		if err != nil {
			return nil, err
		}
		raw, err := pkt.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if err := eapaka.VerifyAKAPrimeMAC(keys.KAut, raw, nil); err != nil {
			return nil, err
		}
		if _, ok := eapaka.FindAttribute(pkt.Attributes, eapaka.AttributeRES); !ok {
			t.Fatal("missing AT_RES")
		}
		kdfAttr, ok := eapaka.FindAttribute(pkt.Attributes, eapaka.AttributeKDF)
		if !ok {
			t.Fatal("missing AT_KDF")
		}
		kdf, err := kdfAttr.KDFValue()
		if err != nil {
			return nil, err
		}
		if kdf != eapaka.AKAPrimeKDFDefault {
			t.Fatalf("AT_KDF=%d", kdf)
		}
		success, err := (eapaka.Packet{Code: eapaka.CodeSuccess, Identifier: pkt.Identifier}).MarshalBinary()
		if err != nil {
			return nil, err
		}
		_, rawResp, err := ProtectMessage(authHeader(init, 3, false), init.Keys, false, []Payload{EAPPayload(success)}, bytes.Repeat([]byte{0x62}, init.Keys.Profile.EncryptionBlockSize))
		return rawResp, err
	})
	res, err := RunIKE_AUTH_AKAChallenge(context.Background(), AKAChallengeConfig{
		Transport: transport,
		Init:      init,
		SIM:       akaProviderStub{result: aka},
		Identity:  identity,
		Request:   challenge,
		MessageID: 3,
		IV:        bytes.Repeat([]byte{0x61}, init.Keys.Profile.EncryptionBlockSize),
	})
	if err != nil {
		t.Fatalf("RunIKE_AUTH_AKAChallenge(AKA') error = %v", err)
	}
	if res.SyncFailure || res.EAPNext == nil || res.EAPNext.Code != eapaka.CodeSuccess {
		t.Fatalf("result=%+v", res)
	}
	if res.EAPResponse.Type != eapaka.TypeAKAPrime || len(res.EAPKeys.KAut) != eapaka.KeyLengthAKAPrimeKAut || len(res.EAPKeys.KRe) != eapaka.KeyLengthKRe {
		t.Fatalf("AKA' response=%+v keys=%+v", res.EAPResponse, res.EAPKeys)
	}
}

func TestRunIKEAuthAKAPrimeKDFNegotiation(t *testing.T) {
	init := fakeInitResult(t)
	challenge := eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 12,
		Type:       eapaka.TypeAKAPrime,
		Subtype:    eapaka.SubtypeChallenge,
		Attributes: []eapaka.Attribute{
			eapaka.KDFAttribute(99),
			eapaka.KDFAttribute(eapaka.AKAPrimeKDFDefault),
			eapaka.KDFInputAttribute("WLAN"),
		},
	}
	transport := InitTransportFunc(func(ctx context.Context, request []byte) ([]byte, error) {
		msg, inner, err := UnprotectMessage(request, init.Keys, true)
		if err != nil {
			return nil, err
		}
		if msg.Header.MessageID != 3 || len(inner) != 1 || inner[0].Type != PayloadEAP {
			t.Fatalf("request header=%+v inner=%+v", msg.Header, inner)
		}
		pkt, err := eapaka.ParsePacket(inner[0].Body)
		if err != nil {
			return nil, err
		}
		if pkt.Code != eapaka.CodeResponse || pkt.Type != eapaka.TypeAKAPrime || pkt.Subtype != eapaka.SubtypeChallenge {
			t.Fatalf("packet=%+v", pkt)
		}
		if len(pkt.Attributes) != 1 || pkt.Attributes[0].Type != eapaka.AttributeKDF {
			t.Fatalf("attributes=%+v, want only AT_KDF", pkt.Attributes)
		}
		kdf, err := pkt.Attributes[0].KDFValue()
		if err != nil {
			return nil, err
		}
		if kdf != eapaka.AKAPrimeKDFDefault {
			t.Fatalf("AT_KDF=%d", kdf)
		}
		next, err := (eapaka.Packet{
			Code:       eapaka.CodeRequest,
			Identifier: 13,
			Type:       eapaka.TypeAKAPrime,
			Subtype:    eapaka.SubtypeChallenge,
			Attributes: []eapaka.Attribute{
				eapaka.KDFAttribute(eapaka.AKAPrimeKDFDefault),
				eapaka.KDFAttribute(99),
				eapaka.KDFInputAttribute("WLAN"),
			},
		}).MarshalBinary()
		if err != nil {
			return nil, err
		}
		_, rawResp, err := ProtectMessage(authHeader(init, 3, false), init.Keys, false, []Payload{EAPPayload(next)}, bytes.Repeat([]byte{0x72}, init.Keys.Profile.EncryptionBlockSize))
		return rawResp, err
	})
	res, err := RunIKE_AUTH_AKAChallenge(context.Background(), AKAChallengeConfig{
		Transport: transport,
		Init:      init,
		Request:   challenge,
		MessageID: 3,
		IV:        bytes.Repeat([]byte{0x71}, init.Keys.Profile.EncryptionBlockSize),
	})
	if err != nil {
		t.Fatalf("RunIKE_AUTH_AKAChallenge(KDF negotiation) error = %v", err)
	}
	if !res.KDFNegotiated || res.SyncFailure || res.EAPResponse.Type != eapaka.TypeAKAPrime {
		t.Fatalf("result=%+v", res)
	}
	if len(res.EAPResponse.Attributes) != 1 || res.EAPNext == nil || res.EAPNext.Identifier != 13 || res.NextMessageID != 4 {
		t.Fatalf("response=%+v next=%+v nextMessageID=%d", res.EAPResponse, res.EAPNext, res.NextMessageID)
	}
}

func TestRunIKEAuthAKAChallengeSyncFailure(t *testing.T) {
	init := fakeInitResult(t)
	identity := "310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org"
	aka := simAKAResult()
	challenge := signedAKAChallenge(t, identity, aka)
	wantAUTS := bytes.Repeat([]byte{0xee}, 14)
	transport := InitTransportFunc(func(ctx context.Context, request []byte) ([]byte, error) {
		msg, inner, err := UnprotectMessage(request, init.Keys, true)
		if err != nil {
			return nil, err
		}
		if msg.Header.MessageID != 3 || len(inner) != 1 || inner[0].Type != PayloadEAP {
			t.Fatalf("request header=%+v inner=%+v", msg.Header, inner)
		}
		pkt, err := eapaka.ParsePacket(inner[0].Body)
		if err != nil {
			return nil, err
		}
		if pkt.Subtype != eapaka.SubtypeSynchronizationFailure {
			t.Fatalf("packet=%+v", pkt)
		}
		attr, ok := eapaka.FindAttribute(pkt.Attributes, eapaka.AttributeAUTS)
		if !ok {
			t.Fatal("missing AT_AUTS")
		}
		auts, err := attr.AUTSValue()
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(auts, wantAUTS) {
			t.Fatalf("AUTS=%x", auts)
		}
		failure, err := (eapaka.Packet{Code: eapaka.CodeFailure, Identifier: pkt.Identifier}).MarshalBinary()
		if err != nil {
			return nil, err
		}
		_, rawResp, err := ProtectMessage(authHeader(init, 3, false), init.Keys, false, []Payload{EAPPayload(failure)}, bytes.Repeat([]byte{0x52}, init.Keys.Profile.EncryptionBlockSize))
		return rawResp, err
	})
	res, err := RunIKE_AUTH_AKAChallenge(context.Background(), AKAChallengeConfig{
		Transport: transport,
		Init:      init,
		SIM:       akaProviderStub{result: sim.AKAResult{AUTS: wantAUTS}, err: sim.ErrSyncFailure},
		Identity:  identity,
		Request:   challenge,
		MessageID: 3,
		IV:        bytes.Repeat([]byte{0x51}, init.Keys.Profile.EncryptionBlockSize),
	})
	if err != nil {
		t.Fatalf("RunIKE_AUTH_AKAChallenge() error = %v", err)
	}
	if !res.SyncFailure || res.EAPNext == nil || res.EAPNext.Code != eapaka.CodeFailure {
		t.Fatalf("result=%+v", res)
	}
}

func TestBuildIKEAuthInitialPayloadsRejectsMissingID(t *testing.T) {
	_, err := BuildIKEAuthInitialPayloads(AuthConfig{})
	if !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("BuildIKEAuthInitialPayloads() err=%v, want ErrInvalidIdentity", err)
	}
}

func fakeInitResult(t *testing.T) InitResult {
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
		NonceI:       bytes.Repeat([]byte{0xa1}, 32),
		NonceR:       bytes.Repeat([]byte{0xb2}, 32),
		SelectedSA:   DefaultIKEProposal(),
		Keys:         keys,
	}
}

type akaProviderStub struct {
	result sim.AKAResult
	err    error
}

func (p akaProviderStub) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	if !bytes.Equal(rand16, bytes.Repeat([]byte{0xa1}, 16)) || !bytes.Equal(autn16, bytes.Repeat([]byte{0xb2}, 16)) {
		return sim.AKAResult{}, errors.New("unexpected RAND/AUTN")
	}
	return p.result, p.err
}

func simAKAResult() sim.AKAResult {
	return sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
}

func signedAKAChallenge(t *testing.T, identity string, aka sim.AKAResult) eapaka.Packet {
	t.Helper()
	keys, err := eapaka.DeriveKeys(identity, aka)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	challenge := eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 10,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeChallenge,
		Attributes: []eapaka.Attribute{
			eapaka.RANDAttribute(bytes.Repeat([]byte{0xa1}, 16)),
			eapaka.AUTNAttribute(bytes.Repeat([]byte{0xb2}, 16)),
			eapaka.MACAttribute(nil),
		},
	}
	raw, err := challenge.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	mac, err := eapaka.CalculateMAC(keys.KAut, raw, nil)
	if err != nil {
		t.Fatalf("CalculateMAC() error = %v", err)
	}
	challenge.Attributes[len(challenge.Attributes)-1] = eapaka.MACAttribute(mac)
	return challenge
}

func signedAKAPrimeChallenge(t *testing.T, identity, networkName string, aka sim.AKAResult) eapaka.Packet {
	t.Helper()
	autn := bytes.Repeat([]byte{0xb2}, 16)
	keys, err := eapaka.DeriveAKAPrimeKeys(identity, networkName, autn, aka)
	if err != nil {
		t.Fatalf("DeriveAKAPrimeKeys() error = %v", err)
	}
	challenge := eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 11,
		Type:       eapaka.TypeAKAPrime,
		Subtype:    eapaka.SubtypeChallenge,
		Attributes: []eapaka.Attribute{
			eapaka.RANDAttribute(bytes.Repeat([]byte{0xa1}, 16)),
			eapaka.AUTNAttribute(autn),
			eapaka.KDFInputAttribute(networkName),
			eapaka.KDFAttribute(eapaka.AKAPrimeKDFDefault),
			eapaka.MACAttribute(nil),
		},
	}
	raw, err := challenge.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	mac, err := eapaka.CalculateAKAPrimeMAC(keys.KAut, raw, nil)
	if err != nil {
		t.Fatalf("CalculateAKAPrimeMAC() error = %v", err)
	}
	challenge.Attributes[len(challenge.Attributes)-1] = eapaka.MACAttribute(mac)
	return challenge
}

func gotTypes(payloads []Payload) []byte {
	out := make([]byte, len(payloads))
	for i, p := range payloads {
		out[i] = p.Type
	}
	return out
}
