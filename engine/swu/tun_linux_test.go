//go:build linux

package swu

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestValidateTUNName(t *testing.T) {
	if err := validateTUNName(""); err != nil {
		t.Fatalf("validateTUNName(empty) error = %v", err)
	}
	if err := validateTUNName("vohive0"); err != nil {
		t.Fatalf("validateTUNName(valid) error = %v", err)
	}
	if err := validateTUNName("bad/name"); !errors.Is(err, ErrInvalidPacketTunnel) {
		t.Fatalf("validateTUNName(slash) err=%v, want ErrInvalidPacketTunnel", err)
	}
	if err := validateTUNName(strings.Repeat("a", 16)); !errors.Is(err, ErrInvalidPacketTunnel) {
		t.Fatalf("validateTUNName(long) err=%v, want ErrInvalidPacketTunnel", err)
	}
}

func TestOpenTUNDeviceRejectsInvalidNameBeforeOpeningDevice(t *testing.T) {
	_, err := OpenTUNDevice(TUNDeviceConfig{Name: "bad/name", Path: "/definitely/not/a/tun"})
	if !errors.Is(err, ErrInvalidPacketTunnel) {
		t.Fatalf("OpenTUNDevice() err=%v, want ErrInvalidPacketTunnel", err)
	}
	if err == nil || strings.Contains(err.Error(), "/definitely/not/a/tun") {
		t.Fatalf("OpenTUNDevice() should reject the name before opening path, err=%v", err)
	}
}

func TestOpenTUNDeviceFileUsesNonblockingDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tun-file")
	created, err := os.Create(path)
	if err != nil {
		t.Fatalf("create test file: %v", err)
	}
	if err := created.Close(); err != nil {
		t.Fatalf("close test file: %v", err)
	}

	file, err := openTUNDeviceFile(path)
	if err != nil {
		t.Fatalf("openTUNDeviceFile() error = %v", err)
	}
	defer file.Close()
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatalf("F_GETFL: %v", err)
	}
	if flags&unix.O_NONBLOCK == 0 {
		t.Fatalf("descriptor flags=%#x, want O_NONBLOCK", flags)
	}
}

func TestTUNDeviceCloseUnblocksRead(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create a TUN device")
	}
	dev, err := OpenTUNDevice(TUNDeviceConfig{Name: fmt.Sprintf("vwtest%d", os.Getpid()%100000)})
	if err != nil {
		t.Skipf("TUN device unavailable: %v", err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, readErr := dev.ReadInnerPacket(context.Background())
		readDone <- readErr
	}()
	time.Sleep(50 * time.Millisecond)
	if err := dev.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("ReadInnerPacket() error = nil after close")
		}
	case <-time.After(time.Second):
		t.Fatal("Close() did not unblock the pending TUN read")
	}
}

func TestNilTUNDeviceMethods(t *testing.T) {
	var dev *TUNDevice
	if dev.Name() != "" {
		t.Fatalf("nil Name()=%q, want empty", dev.Name())
	}
	if _, err := dev.ReadInnerPacket(context.Background()); !errors.Is(err, ErrInvalidPacketTunnel) {
		t.Fatalf("nil ReadInnerPacket() err=%v, want ErrInvalidPacketTunnel", err)
	}
	if err := dev.WriteInnerPacket(context.Background(), []byte{0x45}); !errors.Is(err, ErrInvalidPacketTunnel) {
		t.Fatalf("nil WriteInnerPacket() err=%v, want ErrInvalidPacketTunnel", err)
	}
	if err := dev.Close(context.Background()); err != nil {
		t.Fatalf("nil Close() error = %v", err)
	}
}
