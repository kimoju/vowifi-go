package ikev2

import (
	"bytes"
	"context"
	"errors"
	"testing"

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
		SelectedSA:   DefaultIKEProposal(),
		Keys:         keys,
	}
}

func gotTypes(payloads []Payload) []byte {
	out := make([]byte, len(payloads))
	for i, p := range payloads {
		out[i] = p.Type
	}
	return out
}
