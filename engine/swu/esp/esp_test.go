package esp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/boa-z/vowifi-go/engine/swu/ikev2"
)

func TestSealOpenRoundTrip(t *testing.T) {
	sa, err := NewSA(SA{
		SPI:           0xdeadbeef,
		EncryptionKey: bytes.Repeat([]byte{0x11}, 16),
		IntegrityKey:  bytes.Repeat([]byte{0x22}, 32),
		Integrity:     IntegrityHMACSHA2_256_128,
	})
	if err != nil {
		t.Fatalf("NewSA() error = %v", err)
	}
	payload := []byte{0x45, 0x00, 0x00, 0x14, 0xaa, 0xbb, 0xcc}
	packet, err := sa.Seal(NextHeaderIPv4, payload, SealOptions{
		Sequence: 7,
		IV:       bytes.Repeat([]byte{0xa5}, 16),
	})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if binary.BigEndian.Uint32(packet[0:4]) != 0xdeadbeef || binary.BigEndian.Uint32(packet[4:8]) != 7 {
		t.Fatalf("packet header=%x", packet[:8])
	}
	if len(packet) != 8+16+16+16 {
		t.Fatalf("packet len=%d", len(packet))
	}
	openSA, err := NewSA(SA{
		SPI:           0xdeadbeef,
		EncryptionKey: bytes.Repeat([]byte{0x11}, 16),
		IntegrityKey:  bytes.Repeat([]byte{0x22}, 32),
		Integrity:     IntegrityHMACSHA2_256_128,
	})
	if err != nil {
		t.Fatalf("NewSA(open) error = %v", err)
	}
	out, err := openSA.Open(packet)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if out.SPI != 0xdeadbeef || out.Sequence != 7 || out.NextHeader != NextHeaderIPv4 || !bytes.Equal(out.Payload, payload) {
		t.Fatalf("open=%+v payload=%x", out, out.Payload)
	}
}

func TestOpenRejectsTamperedICV(t *testing.T) {
	sa, err := NewSA(SA{
		SPI:           0x01020304,
		EncryptionKey: bytes.Repeat([]byte{0x33}, 16),
		IntegrityKey:  bytes.Repeat([]byte{0x44}, 32),
		Integrity:     IntegrityHMACSHA2_256_128,
	})
	if err != nil {
		t.Fatalf("NewSA() error = %v", err)
	}
	packet, err := sa.Seal(NextHeaderIPv6, []byte{0x60, 0x00, 0x00}, SealOptions{Sequence: 1, IV: bytes.Repeat([]byte{0x55}, 16)})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	packet[len(packet)-1] ^= 0xff
	_, err = sa.Open(packet)
	if !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("Open() err=%v, want ErrInvalidPacket", err)
	}
}

func TestReplayDetection(t *testing.T) {
	sealer, err := NewSA(SA{
		SPI:              0x11111111,
		EncryptionKey:    bytes.Repeat([]byte{0x77}, 16),
		IntegrityKey:     bytes.Repeat([]byte{0x88}, 32),
		Integrity:        IntegrityHMACSHA2_256_128,
		ReplayWindowSize: 64,
	})
	if err != nil {
		t.Fatalf("NewSA() error = %v", err)
	}
	packet10, err := sealer.Seal(NextHeaderIPv4, []byte{1, 2, 3}, SealOptions{Sequence: 10, IV: bytes.Repeat([]byte{0x99}, 16)})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	packet9, err := sealer.Seal(NextHeaderIPv4, []byte{4, 5, 6}, SealOptions{Sequence: 9, IV: bytes.Repeat([]byte{0xaa}, 16)})
	if err != nil {
		t.Fatalf("Seal(9) error = %v", err)
	}
	opener, err := NewSA(SA{
		SPI:              0x11111111,
		EncryptionKey:    bytes.Repeat([]byte{0x77}, 16),
		IntegrityKey:     bytes.Repeat([]byte{0x88}, 32),
		Integrity:        IntegrityHMACSHA2_256_128,
		ReplayWindowSize: 64,
	})
	if err != nil {
		t.Fatalf("NewSA(open) error = %v", err)
	}
	if _, err := opener.Open(packet10); err != nil {
		t.Fatalf("Open(10) error = %v", err)
	}
	if _, err := opener.Open(packet9); err != nil {
		t.Fatalf("Open(9 out-of-order) error = %v", err)
	}
	if _, err := opener.Open(packet9); !errors.Is(err, ErrReplay) {
		t.Fatalf("Open(replay) err=%v, want ErrReplay", err)
	}
}

func TestOpenRejectsWrongSPIAndSequenceZeroWithoutAdvancingReplay(t *testing.T) {
	sealer := newTestSA(t, 0xabcdef01, 0)
	packet, err := sealer.Seal(NextHeaderIPv4, []byte{1, 2, 3}, SealOptions{
		Sequence: 5,
		IV:       bytes.Repeat([]byte{0x51}, 16),
	})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	opener := newTestSA(t, 0xabcdef01, 64)
	wrongSPI := append([]byte(nil), packet...)
	binary.BigEndian.PutUint32(wrongSPI[0:4], 0xabcdef02)
	if _, err := opener.Open(wrongSPI); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("Open(wrong SPI) err=%v, want ErrInvalidPacket", err)
	}
	zeroSequence := append([]byte(nil), packet...)
	binary.BigEndian.PutUint32(zeroSequence[4:8], 0)
	if _, err := opener.Open(zeroSequence); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("Open(sequence zero) err=%v, want ErrInvalidPacket", err)
	}
	out, err := opener.Open(packet)
	if err != nil {
		t.Fatalf("Open(valid after rejects) error = %v", err)
	}
	if out.Sequence != 5 || opener.HighestSequence != 5 {
		t.Fatalf("sequence=%d highest=%d, want 5", out.Sequence, opener.HighestSequence)
	}
}

func TestReplayWindowRejectsPacketsOutsideWindow(t *testing.T) {
	sealer := newTestSA(t, 0x22222222, 0)
	packet66, err := sealer.Seal(NextHeaderIPv4, []byte{0x66}, SealOptions{Sequence: 66, IV: bytes.Repeat([]byte{0x66}, 16)})
	if err != nil {
		t.Fatalf("Seal(66) error = %v", err)
	}
	packet3, err := sealer.Seal(NextHeaderIPv4, []byte{0x03}, SealOptions{Sequence: 3, IV: bytes.Repeat([]byte{0x03}, 16)})
	if err != nil {
		t.Fatalf("Seal(3) error = %v", err)
	}
	packet2, err := sealer.Seal(NextHeaderIPv4, []byte{0x02}, SealOptions{Sequence: 2, IV: bytes.Repeat([]byte{0x02}, 16)})
	if err != nil {
		t.Fatalf("Seal(2) error = %v", err)
	}
	opener := newTestSA(t, 0x22222222, 64)
	if _, err := opener.Open(packet66); err != nil {
		t.Fatalf("Open(66) error = %v", err)
	}
	if _, err := opener.Open(packet3); err != nil {
		t.Fatalf("Open(3 boundary) error = %v", err)
	}
	if _, err := opener.Open(packet2); !errors.Is(err, ErrReplay) {
		t.Fatalf("Open(2 outside window) err=%v, want ErrReplay", err)
	}
}

func TestReplayWindowSizeCapsAt64Packets(t *testing.T) {
	sealer := newTestSA(t, 0x33333333, 0)
	packet100, err := sealer.Seal(NextHeaderIPv4, []byte{0x10, 0x00}, SealOptions{Sequence: 100, IV: bytes.Repeat([]byte{0x10}, 16)})
	if err != nil {
		t.Fatalf("Seal(100) error = %v", err)
	}
	packet37, err := sealer.Seal(NextHeaderIPv4, []byte{0x37}, SealOptions{Sequence: 37, IV: bytes.Repeat([]byte{0x37}, 16)})
	if err != nil {
		t.Fatalf("Seal(37) error = %v", err)
	}
	packet36, err := sealer.Seal(NextHeaderIPv4, []byte{0x36}, SealOptions{Sequence: 36, IV: bytes.Repeat([]byte{0x36}, 16)})
	if err != nil {
		t.Fatalf("Seal(36) error = %v", err)
	}
	opener := newTestSA(t, 0x33333333, 128)
	if _, err := opener.Open(packet100); err != nil {
		t.Fatalf("Open(100) error = %v", err)
	}
	if _, err := opener.Open(packet37); err != nil {
		t.Fatalf("Open(37 capped boundary) error = %v", err)
	}
	if _, err := opener.Open(packet36); !errors.Is(err, ErrReplay) {
		t.Fatalf("Open(36 outside capped window) err=%v, want ErrReplay", err)
	}
}

func TestSealRejectsSequenceOverflow(t *testing.T) {
	sa := newTestSA(t, 0x44444444, 0)
	sa.Sequence = ^uint32(0)
	_, err := sa.Seal(NextHeaderIPv4, []byte{0x45, 0x00}, SealOptions{IV: bytes.Repeat([]byte{0x44}, 16)})
	if !errors.Is(err, ErrInvalidSA) {
		t.Fatalf("Seal(sequence overflow) err=%v, want ErrInvalidSA", err)
	}
}

func TestNewSAFromChildDirections(t *testing.T) {
	child := ikev2.ChildSAResult{
		LocalSPI:  []byte{0xca, 0xfe, 0xba, 0xbe},
		RemoteSPI: []byte{0xde, 0xad, 0xbe, 0xef},
		Keys: ikev2.ChildSAKeys{
			Profile: ikev2.ESPKeyProfile{IntegrityID: ikev2.INTEG_HMAC_SHA2_256_128},
			Outbound: ikev2.ESPKeys{
				EncryptionKey: bytes.Repeat([]byte{0x10}, 16),
				IntegrityKey:  bytes.Repeat([]byte{0x20}, 32),
			},
			Inbound: ikev2.ESPKeys{
				EncryptionKey: bytes.Repeat([]byte{0x30}, 16),
				IntegrityKey:  bytes.Repeat([]byte{0x40}, 32),
			},
		},
	}
	outbound, err := NewOutboundSAFromChild(child)
	if err != nil {
		t.Fatalf("NewOutboundSAFromChild() error = %v", err)
	}
	inbound, err := NewInboundSAFromChild(child)
	if err != nil {
		t.Fatalf("NewInboundSAFromChild() error = %v", err)
	}
	if outbound.SPI != 0xdeadbeef || inbound.SPI != 0xcafebabe {
		t.Fatalf("SPIs outbound=%08x inbound=%08x", outbound.SPI, inbound.SPI)
	}
	if !bytes.Equal(outbound.EncryptionKey, bytes.Repeat([]byte{0x10}, 16)) ||
		!bytes.Equal(inbound.EncryptionKey, bytes.Repeat([]byte{0x30}, 16)) {
		t.Fatalf("keys outbound=%x inbound=%x", outbound.EncryptionKey, inbound.EncryptionKey)
	}
}

func newTestSA(t *testing.T, spi uint32, replayWindow uint32) *SA {
	t.Helper()
	sa, err := NewSA(SA{
		SPI:              spi,
		EncryptionKey:    bytes.Repeat([]byte{0x91}, 16),
		IntegrityKey:     bytes.Repeat([]byte{0xa2}, 32),
		Integrity:        IntegrityHMACSHA2_256_128,
		ReplayWindowSize: replayWindow,
	})
	if err != nil {
		t.Fatalf("NewSA() error = %v", err)
	}
	return sa
}
