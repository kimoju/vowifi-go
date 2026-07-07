package sim

import (
	"bytes"
	"errors"
	"testing"
)

func TestSyncFailureErrorCarriesAUTS(t *testing.T) {
	auts := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D}
	err := NewSyncFailureError(auts)
	auts[0] = 0xFF

	if !errors.Is(err, ErrSyncFailure) {
		t.Fatalf("errors.Is(SyncFailureError, ErrSyncFailure) = false")
	}
	if got := err.Error(); got != ErrSyncFailure.Error() {
		t.Fatalf("SyncFailureError.Error() = %q, want %q", got, ErrSyncFailure.Error())
	}
	if got := err.AUTS(); !bytes.Equal(got, []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D}) {
		t.Fatalf("SyncFailureError.AUTS() = % X", got)
	}

	got := err.AUTS()
	got[0] = 0xEE
	if bytes.Equal(err.AUTS(), got) {
		t.Fatalf("SyncFailureError.AUTS() returned mutable backing storage")
	}
}
