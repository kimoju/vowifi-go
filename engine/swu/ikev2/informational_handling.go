package ikev2

import (
	"fmt"
	"net"
)

type InformationalHandling struct {
	Empty                 bool
	LivenessCheck         bool
	DeleteIKE             bool
	DeleteESP             [][]byte
	DeleteAH              [][]byte
	UpdateSAAddresses     bool
	NoAdditionalAddresses bool
	AdditionalAddresses   []net.IP
	Cookie2               []byte
	InvalidSelectors      []InvalidSelectorReport
	NotifyError           error
	Notifies              []Notify
	Deletes               []Delete
}

func HandleInformationalPayloads(payloads []Payload) (InformationalHandling, error) {
	content, err := ParseInformationalContent(payloads)
	if err != nil {
		return InformationalHandling{}, err
	}
	return HandleInformationalContent(content)
}

func HandleInformationalContent(content InformationalContent) (InformationalHandling, error) {
	handling := InformationalHandling{
		Empty:         len(content.Payloads) == 0,
		LivenessCheck: len(content.Payloads) == 0,
		NotifyError:   cloneNotifyError(content.NotifyError),
		Notifies:      cloneNotifies(content.Notifies),
		Deletes:       cloneDeletes(content.Deletes),
	}
	for _, deletePayload := range content.Deletes {
		switch deletePayload.ProtocolID {
		case ProtocolIKE:
			handling.DeleteIKE = true
		case ProtocolESP:
			handling.DeleteESP = append(handling.DeleteESP, cloneByteSlices(deletePayload.SPIs)...)
		case ProtocolAH:
			handling.DeleteAH = append(handling.DeleteAH, cloneByteSlices(deletePayload.SPIs)...)
		}
	}
	for _, notify := range content.Notifies {
		if err := handleInformationalNotify(&handling, notify); err != nil {
			return InformationalHandling{}, err
		}
	}
	return handling, nil
}

func handleInformationalNotify(handling *InformationalHandling, notify Notify) error {
	switch notify.NotifyType {
	case NotifyUpdateSAAddresses:
		handling.UpdateSAAddresses = true
	case NotifyNoAdditionalAddresses:
		handling.NoAdditionalAddresses = true
	case NotifyAdditionalIPv4Address:
		if len(notify.NotificationData) != net.IPv4len {
			return fmt.Errorf("%w: %w: ADDITIONAL_IP4_ADDRESS length %d", ErrInvalidInformational, ErrInvalidNotify, len(notify.NotificationData))
		}
		handling.AdditionalAddresses = append(handling.AdditionalAddresses, append(net.IP(nil), notify.NotificationData...))
	case NotifyAdditionalIPv6Address:
		if len(notify.NotificationData) != net.IPv6len {
			return fmt.Errorf("%w: %w: ADDITIONAL_IP6_ADDRESS length %d", ErrInvalidInformational, ErrInvalidNotify, len(notify.NotificationData))
		}
		handling.AdditionalAddresses = append(handling.AdditionalAddresses, append(net.IP(nil), notify.NotificationData...))
	case NotifyCookie2:
		if len(notify.NotificationData) < 8 || len(notify.NotificationData) > 64 {
			return fmt.Errorf("%w: %w: COOKIE2 length %d", ErrInvalidInformational, ErrInvalidNotify, len(notify.NotificationData))
		}
		handling.Cookie2 = append([]byte(nil), notify.NotificationData...)
	case NotifyInvalidSelectors:
		report, _, err := notify.InvalidSelectorReport()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidInformational, err)
		}
		handling.InvalidSelectors = append(handling.InvalidSelectors, report)
	}
	return nil
}
