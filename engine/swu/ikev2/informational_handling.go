package ikev2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

type NotifyActionKind uint8

const (
	NotifyActionNone NotifyActionKind = iota
	NotifyActionMOBIKESupported
	NotifyActionMOBIKEUpdateAddresses
	NotifyActionMOBIKEAdditionalAddress
	NotifyActionMOBIKENoAdditionalAddresses
	NotifyActionMOBIKEEchoCookie2
	NotifyActionRekeyChildSA
	NotifyActionRetryWithSuggestedDH
	NotifyActionRetryWithDifferentProposal
	NotifyActionNarrowTrafficSelectors
	NotifyActionRecreateChildSA
	NotifyActionRecreateIKESA
	NotifyActionMOBIKEAddressRecovery
	NotifyActionWaitAndRetry
	NotifyActionReauthenticate
	NotifyActionAbort
)

type NotifyAction struct {
	Notify           Notify
	Kind             NotifyActionKind
	Retry            bool
	RetryLater       bool
	RecreateIKE      bool
	RecreateChild    bool
	SuggestedDHGroup uint16
}

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
	NotifyActions         []NotifyAction
	Deletes               []Delete
}

type InformationalResponsePlan struct {
	Payloads    []Payload
	EchoCookie2 bool
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
		if action := ClassifyNotifyAction(notify); action.Kind != NotifyActionNone {
			handling.NotifyActions = append(handling.NotifyActions, action)
		}
	}
	return handling, nil
}

func PlanInformationalResponse(handling InformationalHandling) (InformationalResponsePlan, error) {
	var payloads []Payload
	echoCookie2 := len(handling.Cookie2) > 0
	if echoCookie2 {
		payload, err := Cookie2Notify(handling.Cookie2)
		if err != nil {
			return InformationalResponsePlan{}, fmt.Errorf("%w: %w", ErrInvalidInformational, err)
		}
		payloads = append(payloads, payload)
	}
	return InformationalResponsePlan{
		Payloads:    clonePayloads(payloads),
		EchoCookie2: echoCookie2,
	}, nil
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

func ClassifyNotifyAction(notify Notify) NotifyAction {
	action := NotifyAction{Notify: cloneNotify(notify)}
	switch notify.NotifyType {
	case NotifyMOBIKESupported:
		action.Kind = NotifyActionMOBIKESupported
	case NotifyUpdateSAAddresses:
		action.Kind = NotifyActionMOBIKEUpdateAddresses
	case NotifyAdditionalIPv4Address, NotifyAdditionalIPv6Address:
		action.Kind = NotifyActionMOBIKEAdditionalAddress
	case NotifyNoAdditionalAddresses:
		action.Kind = NotifyActionMOBIKENoAdditionalAddresses
	case NotifyCookie2:
		action.Kind = NotifyActionMOBIKEEchoCookie2
	case NotifyRekeySA:
		action.Kind = NotifyActionRekeyChildSA
	case NotifyInvalidKEPayload:
		if len(notify.NotificationData) == 2 {
			action.Kind = NotifyActionRetryWithSuggestedDH
			action.Retry = true
			action.SuggestedDHGroup = binary.BigEndian.Uint16(notify.NotificationData)
		} else {
			action.Kind = NotifyActionAbort
		}
	case NotifyNoProposalChosen:
		action.Kind = NotifyActionRetryWithDifferentProposal
		action.Retry = true
	case NotifySinglePairRequired, NotifyTSUnacceptable, NotifyInvalidSelectors:
		action.Kind = NotifyActionNarrowTrafficSelectors
		action.Retry = true
		action.RecreateChild = true
	case NotifyInvalidSPI:
		action.Kind = NotifyActionRecreateChildSA
		action.Retry = true
		action.RecreateChild = true
	case NotifyNoAdditionalSAs:
		action.Kind = NotifyActionWaitAndRetry
		action.Retry = true
		action.RetryLater = true
	case NotifyInvalidIKESPI, NotifyInternalAddressFailure, NotifyFailedCPRequired:
		action.Kind = NotifyActionRecreateIKESA
		action.Retry = true
		action.RecreateIKE = true
	case NotifyUnacceptableAddresses, NotifyUnexpectedNATDetected, NotifyNoNATsAllowed:
		action.Kind = NotifyActionMOBIKEAddressRecovery
		action.Retry = true
	case NotifyAuthenticationFailed:
		action.Kind = NotifyActionReauthenticate
		action.RecreateIKE = true
	case NotifyUnsupportedCriticalPayload, NotifyInvalidMajorVersion, NotifyInvalidSyntax, NotifyInvalidMessageID:
		action.Kind = NotifyActionAbort
	default:
		if notify.NotifyType < 16384 {
			action.Kind = NotifyActionAbort
		}
	}
	return action
}

func NotifyActionFromError(err error) (NotifyAction, bool) {
	if err == nil {
		return NotifyAction{}, false
	}
	var notifyErr *NotifyError
	if !errors.As(err, &notifyErr) {
		return NotifyAction{}, false
	}
	action := ClassifyNotifyAction(notifyErr.Notify)
	return action, action.Kind != NotifyActionNone
}
