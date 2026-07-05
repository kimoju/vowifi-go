package ikev2

import (
	"errors"
	"fmt"
)

var ErrInvalidInformational = errors.New("invalid ikev2 informational exchange")

func BuildInformationalRequest(init InitResult, keys IKEKeys, messageID uint32, inner []Payload, iv []byte) (Message, []byte, error) {
	return BuildInformationalRequestFrom(init, keys, messageID, true, inner, iv)
}

func BuildInformationalResponse(init InitResult, keys IKEKeys, messageID uint32, inner []Payload, iv []byte) (Message, []byte, error) {
	return BuildInformationalResponseFrom(init, keys, messageID, false, inner, iv)
}

func BuildInformationalRequestFrom(init InitResult, keys IKEKeys, messageID uint32, fromInitiator bool, inner []Payload, iv []byte) (Message, []byte, error) {
	return ProtectMessage(informationalHeader(init, messageID, fromInitiator, false), keys, fromInitiator, inner, iv)
}

func BuildInformationalResponseFrom(init InitResult, keys IKEKeys, messageID uint32, fromInitiator bool, inner []Payload, iv []byte) (Message, []byte, error) {
	return ProtectMessage(informationalHeader(init, messageID, fromInitiator, true), keys, fromInitiator, inner, iv)
}

func ParseInformationalRequest(raw []byte, init InitResult, keys IKEKeys, messageID uint32) (Message, []Payload, error) {
	return ParseInformationalRequestFrom(raw, init, keys, messageID, true)
}

func ParseInformationalResponse(raw []byte, init InitResult, keys IKEKeys, messageID uint32) (Message, []Payload, error) {
	return ParseInformationalResponseFrom(raw, init, keys, messageID, false)
}

func ParseInformationalRequestFrom(raw []byte, init InitResult, keys IKEKeys, messageID uint32, fromInitiator bool) (Message, []Payload, error) {
	msg, inner, err := UnprotectMessage(raw, keys, fromInitiator)
	if err != nil {
		return Message{}, nil, err
	}
	if err := validateInformationalHeader(msg.Header, init, messageID, fromInitiator, false); err != nil {
		return Message{}, nil, err
	}
	return msg, inner, nil
}

func ParseInformationalResponseFrom(raw []byte, init InitResult, keys IKEKeys, messageID uint32, fromInitiator bool) (Message, []Payload, error) {
	msg, inner, err := UnprotectMessage(raw, keys, fromInitiator)
	if err != nil {
		return Message{}, nil, err
	}
	if err := validateInformationalHeader(msg.Header, init, messageID, fromInitiator, true); err != nil {
		return Message{}, nil, err
	}
	return msg, inner, nil
}

func informationalHeader(init InitResult, messageID uint32, fromInitiator bool, response bool) Header {
	flags := uint8(0)
	if fromInitiator {
		flags |= FlagInitiator
	}
	if response {
		flags |= FlagResponse
	}
	return Header{
		InitiatorSPI: init.InitiatorSPI,
		ResponderSPI: init.ResponderSPI,
		ExchangeType: ExchangeINFORMATIONAL,
		Flags:        flags,
		MessageID:    messageID,
	}
}

func validateInformationalHeader(h Header, init InitResult, messageID uint32, fromInitiator bool, response bool) error {
	if h.InitiatorSPI != init.InitiatorSPI || h.ResponderSPI != init.ResponderSPI ||
		h.ExchangeType != ExchangeINFORMATIONAL || h.MessageID != messageID {
		return fmt.Errorf("%w: unexpected header", ErrInvalidInformational)
	}
	expectedFlags := uint8(0)
	if fromInitiator {
		expectedFlags |= FlagInitiator
	}
	if response {
		expectedFlags |= FlagResponse
	}
	if h.Flags&(FlagInitiator|FlagResponse) != expectedFlags {
		return fmt.Errorf("%w: unexpected flags", ErrInvalidInformational)
	}
	return nil
}
