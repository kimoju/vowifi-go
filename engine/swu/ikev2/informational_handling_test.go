package ikev2

import (
	"bytes"
	"errors"
	"net"
	"testing"
)

func TestHandleInformationalContentSummarizesDeletesAndNotifies(t *testing.T) {
	espDelete, err := ESPDeletePayload([]byte{0x01, 0x02, 0x03, 0x04})
	if err != nil {
		t.Fatalf("ESPDeletePayload() error = %v", err)
	}
	cookie, err := Cookie2Notify([]byte("cookie-1"))
	if err != nil {
		t.Fatalf("Cookie2Notify() error = %v", err)
	}
	ipv4, err := AdditionalIPAddressNotify(net.ParseIP("192.0.2.44"))
	if err != nil {
		t.Fatalf("AdditionalIPAddressNotify(v4) error = %v", err)
	}
	ipv6, err := AdditionalIPAddressNotify(net.ParseIP("2001:db8::44"))
	if err != nil {
		t.Fatalf("AdditionalIPAddressNotify(v6) error = %v", err)
	}
	handling, err := HandleInformationalPayloads([]Payload{
		espDelete,
		IKEDeletePayload(),
		UpdateSAAddressesNotify(),
		NoAdditionalAddressesNotify(),
		ipv4,
		ipv6,
		cookie,
	})
	if err != nil {
		t.Fatalf("HandleInformationalPayloads() error = %v", err)
	}
	if handling.Empty || handling.LivenessCheck || !handling.DeleteIKE || len(handling.DeleteESP) != 1 ||
		!bytes.Equal(handling.DeleteESP[0], []byte{0x01, 0x02, 0x03, 0x04}) ||
		!handling.UpdateSAAddresses || !handling.NoAdditionalAddresses ||
		len(handling.AdditionalAddresses) != 2 || !bytes.Equal(handling.Cookie2, []byte("cookie-1")) {
		t.Fatalf("handling=%+v", handling)
	}
	if got := handling.AdditionalAddresses[0].String(); got != "192.0.2.44" {
		t.Fatalf("ipv4 additional=%s", got)
	}
	if got := handling.AdditionalAddresses[1].String(); got != "2001:db8::44" {
		t.Fatalf("ipv6 additional=%s", got)
	}
}

func TestHandleInformationalContentTreatsEmptyAsLiveness(t *testing.T) {
	handling, err := HandleInformationalPayloads(nil)
	if err != nil {
		t.Fatalf("HandleInformationalPayloads(nil) error = %v", err)
	}
	if !handling.Empty || !handling.LivenessCheck || len(handling.Notifies) != 0 || len(handling.Deletes) != 0 {
		t.Fatalf("handling=%+v", handling)
	}
}

func TestHandleInformationalContentPreservesNotifyError(t *testing.T) {
	payload, err := NotifyPayload(Notify{NotifyType: NotifyUnexpectedNATDetected})
	if err != nil {
		t.Fatalf("NotifyPayload() error = %v", err)
	}
	handling, err := HandleInformationalPayloads([]Payload{payload})
	if err != nil {
		t.Fatalf("HandleInformationalPayloads() error = %v", err)
	}
	if !errors.Is(handling.NotifyError, ErrIKEv2NotifyError) ||
		!errors.Is(handling.NotifyError, ErrNotifyUnexpectedNATDetected) {
		t.Fatalf("NotifyError=%v", handling.NotifyError)
	}
}

func TestHandleInformationalContentReportsInvalidSelectors(t *testing.T) {
	payload, err := NotifyPayload(Notify{
		ProtocolID:       ProtocolESP,
		NotifyType:       NotifyInvalidSelectors,
		SPI:              []byte{0xca, 0xfe, 0xba, 0xbe},
		NotificationData: []byte{0x45, 0x00, 0x00, 0x54, 0xaa, 0xbb, 0xcc, 0xdd},
	})
	if err != nil {
		t.Fatalf("NotifyPayload() error = %v", err)
	}
	handling, err := HandleInformationalPayloads([]Payload{payload})
	if err != nil {
		t.Fatalf("HandleInformationalPayloads() error = %v", err)
	}
	if !errors.Is(handling.NotifyError, ErrNotifyInvalidSelectors) {
		t.Fatalf("NotifyError=%v, want ErrNotifyInvalidSelectors", handling.NotifyError)
	}
	if len(handling.InvalidSelectors) != 1 {
		t.Fatalf("InvalidSelectors=%+v, want one report", handling.InvalidSelectors)
	}
	report := handling.InvalidSelectors[0]
	if report.ProtocolID != ProtocolESP ||
		!bytes.Equal(report.SPI, []byte{0xca, 0xfe, 0xba, 0xbe}) ||
		!bytes.Equal(report.PacketPrefix, []byte{0x45, 0x00, 0x00, 0x54, 0xaa, 0xbb, 0xcc, 0xdd}) {
		t.Fatalf("report=%+v", report)
	}
}

func TestHandleInformationalContentRejectsMalformedInvalidSelectors(t *testing.T) {
	payload, err := NotifyPayload(Notify{
		ProtocolID:       ProtocolIKE,
		NotifyType:       NotifyInvalidSelectors,
		SPI:              []byte{0x01, 0x02, 0x03, 0x04},
		NotificationData: []byte{0x45},
	})
	if err != nil {
		t.Fatalf("NotifyPayload() error = %v", err)
	}
	_, err = HandleInformationalPayloads([]Payload{payload})
	if !errors.Is(err, ErrInvalidInformational) || !errors.Is(err, ErrInvalidNotify) {
		t.Fatalf("HandleInformationalPayloads(malformed invalid selectors) err=%v, want ErrInvalidInformational and ErrInvalidNotify", err)
	}
}

func TestHandleInformationalContentRejectsMalformedMOBIKENotify(t *testing.T) {
	payload := NotifyWithZeroSPI(NotifyAdditionalIPv4Address, []byte{1, 2, 3})
	_, err := HandleInformationalPayloads([]Payload{payload})
	if !errors.Is(err, ErrInvalidInformational) || !errors.Is(err, ErrInvalidNotify) {
		t.Fatalf("HandleInformationalPayloads(malformed ip) err=%v, want ErrInvalidInformational and ErrInvalidNotify", err)
	}
}
