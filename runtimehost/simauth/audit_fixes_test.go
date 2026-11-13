package simauth

import (
	"bytes"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	swusim "github.com/kimoju/vowifi-go/engine/sim"
)

func TestReadTransparentEFAcceptsSW6282WithDataAndRejectsEmpty(t *testing.T) {
	// SELECT returns 9000 without FCP size -> ReadTransparentEF requests 256 bytes,
	// card returns 4-byte EF_AD payload + SW=6282 (EOF reached before Le).
	ft := &fakeTransport{responses: []string{
		"9000",
		"000000026282",
	}}
	raw, _, err := ReadTransparentEF(ft, 1, 0x6FAD)
	if err != nil {
		t.Fatalf("ReadTransparentEF(SW=6282 with data) error = %v", err)
	}
	if !bytes.Equal(raw, []byte{0x00, 0x00, 0x00, 0x02}) {
		t.Fatalf("ReadTransparentEF(SW=6282) = %X, want 00000002", raw)
	}
	if mncLen, ok := MNCLengthFromAD(raw); !ok || mncLen != 2 {
		t.Fatalf("MNCLengthFromAD = %d/%v, want 2/true", mncLen, ok)
	}

	// Empty body with SW=6282 at offset 0 must still fail.
	emptyFT := &fakeTransport{responses: []string{
		"9000",
		"6282",
	}}
	if _, _, err := ReadTransparentEF(emptyFT, 1, 0x6FAD); err == nil {
		t.Fatal("ReadTransparentEF(empty SW=6282) = nil, want error")
	}
}

func TestAKAProviderPreservesISIMSyncFailureAUTSWithoutUSIMFallback(t *testing.T) {
	rand16 := bytesFrom(0x11, 16)
	autn16 := bytesFrom(0x22, 16)
	wantAUTS := bytesFrom(0xA5, 14)
	syncPayload := append([]byte{0xDC, byte(len(wantAUTS))}, wantAUTS...)
	syncHex := hex.EncodeToString(syncPayload) + "9000"

	for _, pref := range []string{AKAAppPreferenceISIMStrict, AKAAppPreferenceISIM, AKAAppPreferenceAuto} {
		t.Run(pref, func(t *testing.T) {
			ft := &fakeTransport{responses: []string{syncHex}}
			p := NewAKAProvider(ft)
			res, err := p.CalculateAKAWithPreference(rand16, autn16, pref)
			if !errors.Is(err, swusim.ErrSyncFailure) {
				t.Fatalf("CalculateAKAWithPreference(%s) err = %v, want ErrSyncFailure", pref, err)
			}
			if !bytes.Equal(res.AUTS, wantAUTS) {
				t.Fatalf("CalculateAKAWithPreference(%s) AUTS = %X, want %X", pref, res.AUTS, wantAUTS)
			}
			if len(ft.openedAIDs) != 1 || ft.openedAIDs[0] != ISIMAIDPrefix {
				t.Fatalf("openedAIDs = %v, want only ISIM without USIM fallback on sync failure", ft.openedAIDs)
			}
		})
	}
}

func TestFormatEAPAKAPermanentIdentityDerivesTwoDigitMNCAndEFAD(t *testing.T) {
	got, err := FormatEAPAKAPermanentIdentity("234150123456789", "", "")
	if err != nil {
		t.Fatalf("FormatEAPAKAPermanentIdentity(234-15) error = %v", err)
	}
	if got != "0234150123456789@wlan.mnc015.mcc234.3gppnetwork.org" {
		t.Fatalf("got %q, want mnc015.mcc234", got)
	}

	gotAD, err := FormatEAPAKAPermanentIdentityWithAD("310260123456789", "", "", []byte{0x00, 0x00, 0x00, 0x02})
	if err != nil {
		t.Fatalf("FormatEAPAKAPermanentIdentityWithAD(EF_AD=2) error = %v", err)
	}
	if gotAD != "0310260123456789@wlan.mnc026.mcc310.3gppnetwork.org" {
		t.Fatalf("got %q, want mnc026.mcc310", gotAD)
	}
}

type interleavingCheckTransport struct {
	mu      sync.Mutex
	inUse   bool
	overlap bool
	respHex string
}

func (t *interleavingCheckTransport) OpenLogicalChannel(_ string) (int, error) {
	t.mu.Lock()
	if t.inUse {
		t.overlap = true
	}
	t.inUse = true
	t.mu.Unlock()
	time.Sleep(2 * time.Millisecond)
	return 1, nil
}

func (t *interleavingCheckTransport) TransmitAPDU(_ int, _ string) (string, error) {
	time.Sleep(2 * time.Millisecond)
	return t.respHex, nil
}

func (t *interleavingCheckTransport) CloseLogicalChannel(_ int) error {
	time.Sleep(1 * time.Millisecond)
	t.mu.Lock()
	t.inUse = false
	t.mu.Unlock()
	return nil
}

func TestLogicalChannelSerializationPreventsConcurrentInterleaving(t *testing.T) {
	tr := &interleavingCheckTransport{respHex: successfulAKAResponseHex()}
	p := NewAKAProvider(tr)
	rand16 := bytesFrom(0x10, 16)
	autn16 := bytesFrom(0x20, 16)

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.CalculateAKA(rand16, autn16); err != nil {
				t.Errorf("CalculateAKA error = %v", err)
			}
		}()
	}
	wg.Wait()
	if tr.overlap {
		t.Fatal("detected overlapping OpenLogicalChannel/TransmitAPDU/CloseLogicalChannel sequences")
	}
}
