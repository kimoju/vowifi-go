package ikev2

import (
	"bytes"
	"context"
	"testing"
)

func TestMODP2048KeyExchangeDerivesSameSecret(t *testing.T) {
	a, err := newDHKeyExchange(DHGroup2048BitMODP, []byte{0x11}, bytes.NewReader(make([]byte, 64)))
	if err != nil {
		t.Fatalf("newDHKeyExchange(a) error = %v", err)
	}
	b, err := newDHKeyExchange(DHGroup2048BitMODP, []byte{0x22}, bytes.NewReader(make([]byte, 64)))
	if err != nil {
		t.Fatalf("newDHKeyExchange(b) error = %v", err)
	}
	if len(a.public) != 256 || len(b.public) != 256 {
		t.Fatalf("public key lengths=%d/%d, want 256/256", len(a.public), len(b.public))
	}
	sharedA, err := a.shared(b.public)
	if err != nil {
		t.Fatalf("a.shared() error = %v", err)
	}
	sharedB, err := b.shared(a.public)
	if err != nil {
		t.Fatalf("b.shared() error = %v", err)
	}
	if len(sharedA) != 256 || !bytes.Equal(sharedA, sharedB) {
		t.Fatalf("shared secrets differ or have wrong size: %d/%d", len(sharedA), len(sharedB))
	}
}

func TestRunIKESAInitSupports3GPPMODP2048Proposal(t *testing.T) {
	responder, err := newDHKeyExchange(DHGroup2048BitMODP, []byte{0x22}, bytes.NewReader(make([]byte, 64)))
	if err != nil {
		t.Fatalf("newDHKeyExchange(responder) error = %v", err)
	}
	var responderShared []byte
	transport := InitTransportFunc(func(_ context.Context, request []byte) ([]byte, error) {
		req, err := ParseMessage(request)
		if err != nil {
			return nil, err
		}
		ke, err := ParseKeyExchange(req.Payloads[1].Body)
		if err != nil {
			return nil, err
		}
		if ke.DHGroup != DHGroup2048BitMODP || len(ke.KeyData) != 256 {
			t.Fatalf("initiator KE group=%d len=%d", ke.DHGroup, len(ke.KeyData))
		}
		responderShared, err = responder.shared(ke.KeyData)
		if err != nil {
			return nil, err
		}
		selected := selected3GPPIKEProposal()
		saPayload, err := SecurityAssociationPayload(selected)
		if err != nil {
			return nil, err
		}
		resp := Message{
			Header: Header{
				InitiatorSPI: req.Header.InitiatorSPI,
				ResponderSPI: 0x1112131415161718,
				ExchangeType: ExchangeIKE_SA_INIT,
				Flags:        FlagResponse,
			},
			Payloads: []Payload{
				saPayload,
				KeyExchangePayload(DHGroup2048BitMODP, responder.public),
				NoncePayload(bytes.Repeat([]byte{0xb2}, 32)),
			},
		}
		return resp.MarshalBinary()
	})

	result, err := RunIKE_SA_INIT(context.Background(), InitConfig{
		Transport:    transport,
		SA:           Default3GPPIKEProposal(),
		InitiatorSPI: 0x0102030405060708,
		NonceI:       bytes.Repeat([]byte{0xa1}, 32),
		DHPrivateKey: []byte{0x11},
		RemotePort:   500,
		LocalPort:    500,
	})
	if err != nil {
		t.Fatalf("RunIKE_SA_INIT() error = %v", err)
	}
	if !bytes.Equal(result.SharedSecret, responderShared) || len(result.SharedSecret) != 256 {
		t.Fatalf("shared secret mismatch or wrong size: %d", len(result.SharedSecret))
	}
	if result.SelectedSA.Proposals[0].Transforms[3].ID != DHGroup2048BitMODP {
		t.Fatalf("selected SA=%+v", result.SelectedSA)
	}
}

func selected3GPPIKEProposal() SecurityAssociation {
	return SecurityAssociation{Proposals: []Proposal{{
		Number:     1,
		ProtocolID: ProtocolIKE,
		Transforms: []Transform{
			{Type: TransformENCR, ID: ENCR_AES_CBC, Attributes: []TransformAttribute{KeyLengthAttribute(128)}},
			{Type: TransformPRF, ID: PRF_HMAC_SHA2_256},
			{Type: TransformINTEG, ID: INTEG_HMAC_SHA2_256_128},
			{Type: TransformDHRGroup, ID: DHGroup2048BitMODP},
		},
	}}}
}
