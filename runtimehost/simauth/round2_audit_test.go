package simauth

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	swusim "github.com/kimoju/vowifi-go/engine/sim"
)

func TestRound2Audit8B01MACFailure9862AndNoSecurityRetry(t *testing.T) {
	info, classifyErr := ClassifyUSIMAuthResponse(nil, 0x98, 0x62)
	if classifyErr == nil || info.Class != AKAAuthResponseClassMACFailure {
		t.Fatalf("ClassifyUSIMAuthResponse(9862) = (%+v, %v), want %q", info, classifyErr, AKAAuthResponseClassMACFailure)
	}

	_, err := ParseUSIMAuthResponse(nil, 0x98, 0x62)
	if !errors.Is(err, swusim.ErrAuthFailure) {
		t.Fatalf("ParseUSIMAuthResponse(9862) error = %v, want errors.Is(swusim.ErrAuthFailure)", err)
	}
	var statusErr *StatusError
	if !errors.As(err, &statusErr) || statusErr.Status() != 0x9862 {
		t.Fatalf("ParseUSIMAuthResponse(9862) statusErr = %+v (err=%v), want 0x9862", statusErr, err)
	}

	// calculateAKAOnApp must NOT send a second AUTHENTICATE APDU with Le=0x00 on SW=9862, 6982, 6983, or transport error.
	rand16 := bytes.Repeat([]byte{0x11}, 16)
	autn16 := bytes.Repeat([]byte{0x22}, 16)
	for _, sw := range []string{"9862", "6982", "6983"} {
		ft := &fakeTransport{responses: []string{sw}}
		provider := NewAKAProvider(ft)
		_, akaErr := provider.CalculateAKA(rand16, autn16)
		if akaErr == nil {
			t.Fatalf("CalculateAKA(%s) = nil, want error", sw)
		}
		if len(ft.calls) != 1 {
			t.Fatalf("CalculateAKA(%s) APDU calls = %d (%v), want 1 (must not re-send with Le=0x00)", sw, len(ft.calls), ft.calls)
		}
		if sw == "9862" && !errors.Is(akaErr, swusim.ErrAuthFailure) {
			t.Fatalf("CalculateAKA(9862) error = %v, want swusim.ErrAuthFailure", akaErr)
		}
	}

	ioTransport := &fakeTransport{err: errors.New("serial port disconnected")}
	provider := NewAKAProvider(ioTransport)
	if _, ioErr := provider.CalculateAKA(rand16, autn16); ioErr == nil {
		t.Fatal("CalculateAKA(io error) = nil, want error")
	}
	if len(ioTransport.calls) != 1 {
		t.Fatalf("CalculateAKA(io error) APDU calls = %d, want 1", len(ioTransport.calls))
	}
}

func TestRound2Audit8B03DecodeISIMIdentityStringEdgeCases(t *testing.T) {
	// 1. Cleared ISIM EF record: 80 00 FF FF FF FF or 80 00 00 00 must decode to "", never "\x80".
	for _, raw := range [][]byte{
		{0x80, 0x00, 0xFF, 0xFF, 0xFF, 0xFF},
		{0x80, 0x00, 0x00, 0x00},
		{0x80, 0x10, 'a', 'b'}, // truncated TLV
	} {
		if got := DecodeISIMIdentityString(raw); got != "" {
			t.Fatalf("DecodeISIMIdentityString(% X) = %q, want empty string", raw, got)
		}
	}

	// 2. Multi-byte BER length (80 81 82 <130 bytes> FF FF).
	longURI := "sip:" + strings.Repeat("a", 110) + "@ims.example.org"
	tlv := append([]byte{0x80, 0x81, byte(len(longURI))}, []byte(longURI)...)
	tlv = append(tlv, 0xFF, 0xFF)
	if got := DecodeISIMIdentityString(tlv); got != longURI {
		t.Fatalf("DecodeISIMIdentityString(long BER TLV) = %q, want %q", got, longURI)
	}

	// 3. Untagged 56-byte NAI starting with ASCII '1' (0x31 = 49 < 56) must NOT be truncated as a length-prefixed string.
	untaggedNAI := "1310260123456789@nai.epc.mnc260.mcc310.3gppnetwork.org"
	untaggedRecord := append([]byte(untaggedNAI), 0xFF, 0xFF, 0xFF, 0xFF)
	if got := DecodeISIMIdentityString(untaggedRecord); got != untaggedNAI {
		t.Fatalf("DecodeISIMIdentityString(untagged NAI) = %q, want %q", got, untaggedNAI)
	}
}

func TestRound2Audit8B11BinaryOffsetGuardAndMultiChunkTransparentEF(t *testing.T) {
	if _, err := UpdateBinaryAPDU(0x8000, []byte{0x01}); err == nil {
		t.Fatal("UpdateBinaryAPDU(0x8000) = nil, want SFI offset error")
	}
	if _, err := UpdateBinaryAPDU(-1, []byte{0x01}); err == nil {
		t.Fatal("UpdateBinaryAPDU(-1) = nil, want negative offset error")
	}
	if _, err := ReadBinaryAPDUChecked(0x8000, 16); err == nil {
		t.Fatal("ReadBinaryAPDUChecked(0x8000) = nil, want SFI offset error")
	}
	if _, err := ReadBinaryAPDUChecked(-1, 16); err == nil {
		t.Fatal("ReadBinaryAPDUChecked(-1) = nil, want negative offset error")
	}
	clamped := ReadBinaryAPDU(0x8001, 16)
	if !bytes.Equal(clamped, []byte{0x00, 0xB0, 0x7F, 0xFF, 0x10}) {
		t.Fatalf("ReadBinaryAPDU(0x8001, 16) = % X, want 00 B0 7F FF 10 (never SFI bit 8 set)", clamped)
	}

	// ReadTransparentEF without FCP size reads >256 bytes across multiple 256-byte chunks.
	chunk1 := bytes.Repeat([]byte{0xAB}, 256)
	chunk2 := bytes.Repeat([]byte{0xCD}, 44)
	ft := &fakeTransport{responses: []string{
		"9000", // SELECT without FCP body
		strings.ToUpper(hex.EncodeToString(chunk1)) + "9000",
		strings.ToUpper(hex.EncodeToString(chunk2)) + "9000",
	}}
	data, _, err := ReadTransparentEF(ft, 1, 0x6F02)
	if err != nil {
		t.Fatalf("ReadTransparentEF(300B without FCP) error = %v", err)
	}
	want := append(append([]byte(nil), chunk1...), chunk2...)
	if !bytes.Equal(data, want) {
		t.Fatalf("ReadTransparentEF len=%d, want %d", len(data), len(want))
	}

	// chaseGetResponse clears proprietary bit 8 on CLA=0x80 (with logical channel 2 -> 0x02).
	ftCLA := &fakeTransport{responses: []string{
		"6102",
		"BEEF9000",
	}}
	resp, err := Transmit(ftCLA, 2, []byte{0x80, 0xF2, 0x00, 0x00, 0x00})
	if err != nil || !bytes.Equal(resp.Body, []byte{0xBE, 0xEF}) {
		t.Fatalf("Transmit(80F2->6102) = (%+v, %v)", resp, err)
	}
	if len(ftCLA.calls) != 2 || ftCLA.calls[1] != "00C0000002" {
		t.Fatalf("chaseGetResponse calls = %#v, want second call 00C0000002", ftCLA.calls)
	}
}

type unhashableInner struct {
	fn    func()
	slice []byte
}

type structWithInterfaceTransport struct {
	meta any
}

func (structWithInterfaceTransport) OpenLogicalChannel(string) (int, error)   { return 1, nil }
func (structWithInterfaceTransport) CloseLogicalChannel(int) error            { return nil }
func (structWithInterfaceTransport) TransmitAPDU(int, string) (string, error) { return "9000", nil }

func TestRound2Audit8B12LockLogicalChannelNoUnhashablePanicAndReleasesRef(t *testing.T) {
	// 1. Value struct holding an interface with an unhashable dynamic value must not panic.
	unhashable := structWithInterfaceTransport{meta: unhashableInner{slice: []byte{1, 2, 3}}}
	unlock := LockLogicalChannel(unhashable)
	unlock()

	// 2. Pointer transport serializes concurrent callers and cleans up map entry when unlocked.
	ft := &fakeTransport{}
	var active int32
	var maxConcurrent int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel := LockLogicalChannel(ft)
			defer rel()
			cur := atomic.AddInt32(&active, 1)
			for {
				prev := atomic.LoadInt32(&maxConcurrent)
				if cur <= prev || atomic.CompareAndSwapInt32(&maxConcurrent, prev, cur) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			atomic.AddInt32(&active, -1)
		}()
	}
	wg.Wait()
	if maxConcurrent != 1 {
		t.Fatalf("maxConcurrent = %d, want 1", maxConcurrent)
	}

	logicalChannelLocksMu.Lock()
	_, leaked := logicalChannelSessionLocks[ft]
	logicalChannelLocksMu.Unlock()
	if leaked {
		t.Fatal("logicalChannelSessionLocks retained entry after all unlocks")
	}
}
