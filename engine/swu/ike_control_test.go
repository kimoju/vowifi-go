package swu

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/iniwex5/vowifi-go/engine/swu/ikev2"
)

func TestPacketSessionCloseSendsIKEDeletes(t *testing.T) {
	init := ikeControlInit(t)
	child := packetChildSA(true)
	control := &ikeCloseTransport{
		t:         t,
		init:      init,
		keys:      init.Keys,
		child:     child,
		messageID: 8,
	}
	handler, err := NewIKECloseHandler(IKECloseConfig{
		Transport:     control,
		Init:          init,
		ChildSA:       child,
		NextMessageID: 8,
	})
	if err != nil {
		t.Fatalf("NewIKECloseHandler() error = %v", err)
	}
	espTransport := &captureESPPacketTransport{}
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:      child,
		Transport:    espTransport,
		CloseHandler: handler,
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if control.requests != 1 || !control.sawChildDelete || !control.sawIKEDelete {
		t.Fatalf("control requests=%d child=%t ike=%t", control.requests, control.sawChildDelete, control.sawIKEDelete)
	}
	if !espTransport.closed {
		t.Fatalf("ESP transport was not closed")
	}
}

func TestNewIKECloseHandlerRejectsInvalidConfig(t *testing.T) {
	init := ikeControlInit(t)
	if _, err := NewIKECloseHandler(IKECloseConfig{Init: init, NextMessageID: 1}); !errors.Is(err, ErrInvalidIKEControl) {
		t.Fatalf("NewIKECloseHandler(missing transport) err=%v, want ErrInvalidIKEControl", err)
	}
	if _, err := NewIKECloseHandler(IKECloseConfig{Transport: &ikeCloseTransport{t: t}, Init: init}); !errors.Is(err, ErrInvalidIKEControl) {
		t.Fatalf("NewIKECloseHandler(missing msgid) err=%v, want ErrInvalidIKEControl", err)
	}
}

type ikeCloseTransport struct {
	t              *testing.T
	init           ikev2.InitResult
	keys           ikev2.IKEKeys
	child          ikev2.ChildSAResult
	messageID      uint32
	requests       int
	sawChildDelete bool
	sawIKEDelete   bool
}

func (tr *ikeCloseTransport) ExchangeIKE(ctx context.Context, request []byte) ([]byte, error) {
	tr.t.Helper()
	_, inner, err := ikev2.ParseInformationalRequest(request, tr.init, tr.keys, tr.messageID)
	if err != nil {
		tr.t.Fatalf("ParseInformationalRequest() error = %v", err)
	}
	tr.requests++
	for _, payload := range inner {
		if payload.Type != ikev2.PayloadDelete {
			continue
		}
		deletePayload, err := ikev2.ParseDelete(payload.Body)
		if err != nil {
			tr.t.Fatalf("ParseDelete() error = %v", err)
		}
		switch deletePayload.ProtocolID {
		case ikev2.ProtocolESP:
			if len(deletePayload.SPIs) != 1 || !bytes.Equal(deletePayload.SPIs[0], tr.child.LocalSPI) {
				tr.t.Fatalf("ESP delete=%+v, want local SPI %x", deletePayload, tr.child.LocalSPI)
			}
			tr.sawChildDelete = true
		case ikev2.ProtocolIKE:
			if len(deletePayload.SPIs) != 0 {
				tr.t.Fatalf("IKE delete=%+v, want no SPIs", deletePayload)
			}
			tr.sawIKEDelete = true
		}
	}
	_, raw, err := ikev2.BuildInformationalResponse(
		tr.init,
		tr.keys,
		tr.messageID,
		nil,
		bytes.Repeat([]byte{0x88}, tr.keys.Profile.EncryptionBlockSize),
	)
	if err != nil {
		tr.t.Fatalf("BuildInformationalResponse() error = %v", err)
	}
	return raw, nil
}

func ikeControlInit(t *testing.T) ikev2.InitResult {
	t.Helper()
	profile, err := ikev2.KeyMaterialProfileFromSA(ikev2.DefaultIKEProposal())
	if err != nil {
		t.Fatalf("KeyMaterialProfileFromSA() error = %v", err)
	}
	keys, err := ikev2.SplitIKEKeys(profile, ikeControlBytes(profile.RequiredLength()))
	if err != nil {
		t.Fatalf("SplitIKEKeys() error = %v", err)
	}
	return ikev2.InitResult{
		InitiatorSPI: 0x0102030405060708,
		ResponderSPI: 0x1112131415161718,
		NonceI:       bytes.Repeat([]byte{0xa1}, 32),
		NonceR:       bytes.Repeat([]byte{0xb2}, 32),
		SelectedSA:   ikev2.DefaultIKEProposal(),
		Keys:         keys,
	}
}

func ikeControlBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}
