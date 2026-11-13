package ikev2

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestDHGroup19And20ECDHSharedSecret(t *testing.T) {
	for _, tc := range []struct {
		name    string
		group   uint16
		pubSize int
	}{
		{name: "P-256 Group 19", group: DHGroup256BitECP, pubSize: 64},
		{name: "P-384 Group 20", group: DHGroup384BitECP, pubSize: 96},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alice, err := newDHKeyExchange(tc.group, nil, rand.Reader)
			if err != nil {
				t.Fatalf("newDHKeyExchange(alice) error = %v", err)
			}
			bob, err := newDHKeyExchange(tc.group, nil, rand.Reader)
			if err != nil {
				t.Fatalf("newDHKeyExchange(bob) error = %v", err)
			}
			if len(alice.public) != tc.pubSize || len(bob.public) != tc.pubSize {
				t.Fatalf("public key lengths = %d/%d, want %d", len(alice.public), len(bob.public), tc.pubSize)
			}
			s1, err := alice.shared(bob.public)
			if err != nil {
				t.Fatalf("alice.shared error = %v", err)
			}
			s2, err := bob.shared(alice.public)
			if err != nil {
				t.Fatalf("bob.shared error = %v", err)
			}
			if !bytes.Equal(s1, s2) || len(s1) != tc.pubSize/2 {
				t.Fatalf("shared secret mismatch or wrong length %d", len(s1))
			}
			if _, err := alice.shared(bytes.Repeat([]byte{0xff}, tc.pubSize)); !errors.Is(err, ErrInvalidInitResponse) {
				t.Fatalf("invalid curve point err = %v, want ErrInvalidInitResponse", err)
			}
		})
	}

	prop := Default3GPPIKEProposal()
	if len(prop.Proposals) != 1 {
		t.Fatalf("Default3GPPIKEProposal proposals = %d", len(prop.Proposals))
	}
	for _, wantGroup := range []uint16{DHGroup2048BitMODP, DHGroup256BitECP, DHGroup384BitECP, DHGroupCurve25519} {
		if !saOffersDHGroup(prop, wantGroup) {
			t.Fatalf("Default3GPPIKEProposal missing DH group %d", wantGroup)
		}
	}
}

func TestRunIKESAInitRetriesOnInvalidKEPayload(t *testing.T) {
	var calls int
	responderDH, err := newDHKeyExchange(DHGroup256BitECP, nil, rand.Reader)
	if err != nil {
		t.Fatalf("newDHKeyExchange(P-256) error = %v", err)
	}
	responderNonce := bytes.Repeat([]byte{0x5a}, 32)
	const responderSPI = uint64(0xfeedfacecafebeef)

	transport := InitTransportFunc(func(ctx context.Context, reqBytes []byte) ([]byte, error) {
		calls++
		req, err := ParseMessage(reqBytes)
		if err != nil {
			t.Fatalf("ParseMessage(req %d) error = %v", calls, err)
		}
		var gotKE KeyExchange
		for _, p := range req.Payloads {
			if p.Type == PayloadKE {
				gotKE, err = ParseKeyExchange(p.Body)
				if err != nil {
					t.Fatalf("ParseKeyExchange error = %v", err)
				}
			}
		}
		if calls == 1 {
			if gotKE.DHGroup != DHGroup2048BitMODP {
				t.Fatalf("initial DHGroup = %d, want %d", gotKE.DHGroup, DHGroup2048BitMODP)
			}
			var groupBytes [2]byte
			binary.BigEndian.PutUint16(groupBytes[:], DHGroup256BitECP)
			resp := Message{
				Header: Header{
					InitiatorSPI: req.Header.InitiatorSPI,
					ResponderSPI: 0,
					ExchangeType: ExchangeIKE_SA_INIT,
					Flags:        FlagResponse,
					MessageID:    0,
				},
				Payloads: []Payload{
					NotifyWithZeroSPI(NotifyInvalidKEPayload, groupBytes[:]),
				},
			}
			return resp.MarshalBinary()
		}
		if gotKE.DHGroup != DHGroup256BitECP {
			t.Fatalf("retry DHGroup = %d, want %d", gotKE.DHGroup, DHGroup256BitECP)
		}
		selected := SecurityAssociation{
			Proposals: []Proposal{{
				Number:     1,
				ProtocolID: ProtocolIKE,
				Transforms: []Transform{
					{Type: TransformENCR, ID: ENCR_AES_CBC, Attributes: []TransformAttribute{KeyLengthAttribute(128)}},
					{Type: TransformPRF, ID: PRF_HMAC_SHA2_256},
					{Type: TransformINTEG, ID: INTEG_HMAC_SHA2_256_128},
					{Type: TransformDHRGroup, ID: DHGroup256BitECP},
				},
			}},
		}
		saPayload, err := SecurityAssociationPayload(selected)
		if err != nil {
			t.Fatalf("SecurityAssociationPayload error = %v", err)
		}
		resp := Message{
			Header: Header{
				InitiatorSPI: req.Header.InitiatorSPI,
				ResponderSPI: responderSPI,
				ExchangeType: ExchangeIKE_SA_INIT,
				Flags:        FlagResponse,
				MessageID:    0,
			},
			Payloads: []Payload{
				saPayload,
				KeyExchangePayload(DHGroup256BitECP, responderDH.public),
				NoncePayload(responderNonce),
			},
		}
		return resp.MarshalBinary()
	})

	res, err := RunIKE_SA_INIT(context.Background(), InitConfig{
		Transport: transport,
		Random:    rand.Reader,
		SA:        Default3GPPIKEProposal(),
	})
	if err != nil {
		t.Fatalf("RunIKE_SA_INIT() error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	gotGroup, err := dhGroupFromSA(res.SelectedSA)
	if err != nil || gotGroup != DHGroup256BitECP || res.ResponderSPI != responderSPI || len(res.Keys.SKEi) == 0 {
		t.Fatalf("unexpected result: group=%d (err=%v) spi=%x keyLen=%d", gotGroup, err, res.ResponderSPI, len(res.Keys.SKEi))
	}
}

func TestUDPTransportRetransmitsOnTimeout(t *testing.T) {
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket error = %v", err)
	}
	defer serverConn.Close()

	var attempts atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, peer, readErr := serverConn.ReadFrom(buf)
			if readErr != nil {
				return
			}
			count := attempts.Add(1)
			if count == 1 {
				continue
			}
			_, _ = serverConn.WriteTo(buf[:n], peer)
			return
		}
	}()

	tr := &UDPTransport{
		RemoteAddr:        serverConn.LocalAddr().String(),
		Timeout:           150 * time.Millisecond,
		RetransmitTimeout: 40 * time.Millisecond,
		MaxRetransmits:    3,
	}
	req := bytes.Repeat([]byte{0x42}, 32)
	resp, err := tr.ExchangeIKE(context.Background(), req)
	if err != nil {
		t.Fatalf("ExchangeIKE() error = %v", err)
	}
	<-done
	if !bytes.Equal(resp, req) || attempts.Load() < 2 {
		t.Fatalf("attempts=%d resp=%x", attempts.Load(), resp)
	}
}

func TestEncryptedFragmentBoundsAndAssembler(t *testing.T) {
	tooMany := make([]byte, 5)
	binary.BigEndian.PutUint16(tooMany[0:2], 1)
	binary.BigEndian.PutUint16(tooMany[2:4], MaxEncryptedFragments+1)
	tooMany[4] = 0xaa
	if _, err := ParseEncryptedFragment(tooMany); !errors.Is(err, ErrInvalidEncryptedFragment) {
		t.Fatalf("ParseEncryptedFragment(>MaxEncryptedFragments) err = %v, want ErrInvalidEncryptedFragment", err)
	}

	assembler := &EncryptedFragmentAssembler{MaxSize: 16}
	_, _, err := assembler.Add(EncryptedFragment{
		FragmentNumber: 1,
		TotalFragments: 2,
		EncryptedData:  bytes.Repeat([]byte{0xaa}, 12),
	})
	if err != nil {
		t.Fatalf("assembler.Add(1) error = %v", err)
	}
	if _, _, err := assembler.Add(EncryptedFragment{
		FragmentNumber: 2,
		TotalFragments: 2,
		EncryptedData:  bytes.Repeat([]byte{0xbb}, 12),
	}); !errors.Is(err, ErrInvalidEncryptedFragment) {
		t.Fatalf("assembler.Add(exceeding max bytes) err = %v, want ErrInvalidEncryptedFragment", err)
	}

	got, err := ReassembleEncryptedFragments([]EncryptedFragment{
		{FragmentNumber: 2, TotalFragments: 2, EncryptedData: []byte{0x03, 0x04}},
		{FragmentNumber: 1, TotalFragments: 2, EncryptedData: []byte{0x01, 0x02}},
	})
	if err != nil {
		t.Fatalf("ReassembleEncryptedFragments error = %v", err)
	}
	if !bytes.Equal(got, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Fatalf("ReassembleEncryptedFragments = %x, want 01020304", got)
	}
}
